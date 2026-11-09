"""Link anonymous resources to cases through the deletion-worker activity stream.

Evidence for a deleted account usually carries no identifier (a 404 lookup), so the account of a case
is recovered from ``system_activity.csv``: the deletion worker submits the primary profile shortly before the
workflow reports its result, and for most cases the reported result of that activity mirrors the claim
(COMPLETE->SUCCESS, PARTIALLY_COMPLETE->PARTIAL, NOT_STARTED->FAILED).  Candidates that are visibly keyed to
another person, or already taken by another case, are eliminated; remaining ambiguity is resolved by proximity
to the activities of the case's identity-linked records.
"""
from __future__ import annotations

from collections import defaultdict

from .common import parse_ts, read_csv, DATASET
from .model import Obs

RESULT_FOR_STATUS = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}


class ActivityIndex:
    def __init__(self) -> None:
        self.rows = read_csv(DATASET / "system_activity.csv")
        for r in self.rows:
            r["_t"] = parse_ts(r["event_time"])
        self.by_rid: dict[str, list[dict]] = defaultdict(list)
        for r in self.rows:
            self.by_rid[r["resource_id"]].append(r)
        self.account_deletes = [r for r in self.rows if r["event_type"] == "DELETE_RECORD"
                                and r["target_system"] == "account_service"]


def _keyed_to_other(rid: str, by_rid: dict[str, list[Obs]], tokens: set[str]) -> bool:
    for o in by_rid.get(rid, ()):
        if o.keys and not (o.keys & tokens):
            strong = {k for k in o.keys if k[0] in "ehpu"}
            if strong and not (strong & tokens):
                return True
    return False


SPECS = {
    "account": dict(prefix="account_", event="DELETE_RECORD", target="account_service", penalty=None, anchor_off=40),
    "analytics": dict(prefix="analytics_", event="ANONYMIZE_RECORD", target="analytics_platform", penalty=3000.0, anchor_off=20),
}


def candidate_accounts(case: dict, idx: ActivityIndex, by_rid) -> list[dict]:
    R = parse_ts(case["reported_at"])
    A = parse_ts(case["audit_at"])
    want = RESULT_FOR_STATUS.get(case["reported_status"])
    out = []
    for a in idx.account_deletes:
        if a["_t"] > A:
            continue
        dt = (a["_t"] - R).total_seconds() / 60.0
        near = abs(dt) <= 10 and len(a["resource_id"].split("_")[1]) <= 3
        window = -80 <= dt <= 10 and a["reported_result"] == want
        if near or window:
            if not _keyed_to_other(a["resource_id"], by_rid, case["tokens"]):
                out.append(a)
    return out


def assign_accounts(cases: list[dict], idx: ActivityIndex, by_rid, spec_name: str = "account") -> dict[str, dict]:
    """cases: dicts with case_id, reported_at, reported_status, audit_at, tokens, linked (set of rids),
    anchor_times (list[datetime]).  Returns case_id -> chosen activity row."""
    spec = SPECS[spec_name]
    taken: set[str] = set()
    for c in cases:
        for rid in c["linked"]:
            if rid.startswith(spec["prefix"]):
                taken.add(rid)
    pool = {}
    for c in cases:
        if any(r.startswith(spec["prefix"]) for r in c["linked"]):
            continue
        cand = candidate_accounts(c, idx, by_rid) if spec_name == "account" else candidate_by_window(c, idx, by_rid, spec)
        pool[c["case_id"]] = [a for a in cand if a["resource_id"] not in taken]
    chosen: dict[str, dict] = {}
    by_case = {c["case_id"]: c for c in cases}
    changed = True
    while changed:
        changed = False
        for cid, cand in sorted(pool.items(), key=lambda kv: (len(kv[1]), kv[0])):
            if cid in chosen:
                continue
            cand = [a for a in cand if a["resource_id"] not in taken]
            if len(cand) == 1 and spec["penalty"] is None:
                chosen[cid] = cand[0]
                taken.add(cand[0]["resource_id"])
                changed = True
    # remaining ambiguity: min-cost matching on time distance to the case's own anchor activities
    open_cases = [cid for cid in sorted(pool) if cid not in chosen]
    for comp in _components(open_cases, pool, taken):
        sol = _best_matching(comp, pool, taken, by_case, spec["penalty"], spec["anchor_off"])
        for cid, a in sol.items():
            chosen[cid] = a
            taken.add(a["resource_id"])
    return chosen


def candidate_by_window(case, idx, by_rid, spec) -> list[dict]:
    R = parse_ts(case["reported_at"])
    A = parse_ts(case["audit_at"])
    out = []
    for a in idx.rows:
        if a["event_type"] != spec["event"] or a["target_system"] != spec["target"] or a["_t"] > A:
            continue
        dt = (a["_t"] - R).total_seconds() / 60.0
        if -100 <= dt <= 190 and a["resource_id"] in by_rid and not _keyed_to_other(a["resource_id"], by_rid, case["tokens"]):
            out.append(a)
    return out


def _anchor(c, off=40) -> float:
    ts = sorted(t.timestamp() for t in c["anchor_times"])
    if ts:
        return ts[len(ts) // 2]
    return parse_ts(c["reported_at"]).timestamp() - off * 60


def _components(open_cases, pool, taken):
    seen, comps = set(), []
    for cid in open_cases:
        if cid in seen:
            continue
        comp, stack = [], [cid]
        while stack:
            x = stack.pop()
            if x in seen:
                continue
            seen.add(x)
            comp.append(x)
            rx = {a["resource_id"] for a in pool[x] if a["resource_id"] not in taken}
            for y in open_cases:
                if y not in seen and rx & {a["resource_id"] for a in pool[y] if a["resource_id"] not in taken}:
                    stack.append(y)
        comps.append(sorted(comp))
    return comps


def _best_matching(comp, pool, taken, by_case, penalty, off=40):
    anchors = {cid: _anchor(by_case[cid], off) for cid in comp}
    cands = {cid: [a for a in pool[cid] if a["resource_id"] not in taken] for cid in comp}
    order = sorted(comp, key=lambda c: (anchors[c], c))
    # exact search with a sane cap, falling back to greedy order-preserving assignment for big components
    if len(comp) <= 8:
        best_key = [None]
        sol_holder = {}

        def search(i, used, cost, cur):
            if i == len(order):
                key = (-len(cur), cost) if penalty is None else (0, cost + penalty * (len(order) - len(cur)))
                if best_key[0] is None or key < best_key[0]:
                    best_key[0] = key
                    sol_holder.clear()
                    sol_holder.update(cur)
                return
            cid = order[i]
            opts = [a for a in cands[cid] if a["resource_id"] not in used]
            for a in opts:
                cur[cid] = a
                search(i + 1, used | {a["resource_id"]}, cost + abs(a["_t"].timestamp() - anchors[cid]), cur)
                del cur[cid]
            search(i + 1, used, cost, cur)

        search(0, frozenset(), 0.0, {})
        return dict(sol_holder)
    out, used = {}, set()
    for cid in order:
        opts = sorted((a for a in cands[cid] if a["resource_id"] not in used),
                      key=lambda a: abs(a["_t"].timestamp() - anchors[cid]))
        if opts:
            out[cid] = opts[0]
            used.add(opts[0]["resource_id"])
    return out
