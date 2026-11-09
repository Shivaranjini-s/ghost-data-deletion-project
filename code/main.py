"""Ghost Data audit agent. Usage: python3 code/main.py [--requests PATH] [--out PATH]"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghost_audit.common import DATASET, REPO_ROOT, read_csv  # noqa: E402
from ghost_audit.assign import ActivityIndex, assign_accounts  # noqa: E402
from ghost_audit.model import Obs  # noqa: E402
from ghost_audit.engine import audit_case, authorizes_deletion, collect_states  # noqa: E402
from ghost_audit.evidence import load_all_observations  # noqa: E402
from ghost_audit.identity import IdentityBook  # noqa: E402


def run(requests: list[dict], context: list[dict] | None = None) -> list[dict]:
    """`context` are extra requests (e.g. the public samples) that compete for the same activity records."""
    wanted = {q['case_id'] for q in requests}
    ids = {q['case_id'] for q in requests}
    requests = list(requests) + [q for q in (context or []) if q['case_id'] not in ids]
    obs, _ = load_all_observations()
    book = IdentityBook()
    idx = ActivityIndex()
    by_rid: dict[str, list] = defaultdict(list)
    for o in obs:
        by_rid[o.rid].append(o)
    account_files = sorted({(o.file_id, o.t) for o in obs if o.system == "account_service"},
                           key=lambda x: (x[1], x[0]))
    # pass 1: intent, identity, identity-linked resources
    cases = []
    for q in requests:
        c = dict(q)
        c["deletion"] = authorizes_deletion(q["request_text"])
        c["uid"], _ = book.resolve(q["email"]) if c["deletion"] else (None, {})
        c["tokens"] = book.tokens_for(c["uid"]) if c["uid"] else set()
        T, A = c["tokens"], q["audit_at"]
        c["linked"] = {rid for rid, lst in by_rid.items() if T and any((o.keys & T) and q["requested_at"] <= o.t <= A for o in lst)}
        anchors = []
        for rid in c["linked"]:
            if rid.startswith("account_"):
                continue
            for a in idx.by_rid.get(rid, ()):
                anchors.append(a["_t"])
        c["anchor_times"] = anchors
        cases.append(c)
    # pass 2: resources only reachable through the activity stream
    chosen = assign_accounts([c for c in cases if c["deletion"] and c["uid"]], idx, by_rid)
    chosen_an = assign_accounts([c for c in cases if c["deletion"] and c["uid"]], idx, by_rid, "analytics")
    out = []
    for c in cases:
        if not c["deletion"]:
            out.append({"case_id": c["case_id"], "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"})
            continue
        status, steps = "COMPLETE", []
        if c["uid"]:
            linked = set(c["linked"])
            extra: list[Obs] = []
            act = chosen.get(c["case_id"])
            if act:
                linked.add(act["resource_id"])
                if act["resource_id"] not in by_rid:
                    cover = [f for f, cap in account_files if act["event_time"] <= cap <= c["audit_at"]]
                    ev = cover[-1] if cover else act["activity_id"]
                    extra.append(Obs(file_id=ev, file_captured=act["event_time"], t=act["event_time"],
                                     system="account_service", rid=act["resource_id"], kind="ACCOUNT", present=False,
                                     src="activity"))
            an = chosen_an.get(c["case_id"])
            if an:
                linked.add(an["resource_id"])
            local = {rid: list(by_rid[rid]) for rid in linked if rid in by_rid}
            for o in extra:
                local[o.rid] = [o]
            states = collect_states(linked, local, c["audit_at"], c["requested_at"])
            status, steps = audit_case(states, c["audit_at"])
        out.append({"case_id": c["case_id"], "deletion_status": status,
                    "steps_json": json.dumps(steps, sort_keys=True, ensure_ascii=False, separators=(",", ":"))})
    out = [r for r in out if r["case_id"] in wanted]
    out.sort(key=lambda r: r["case_id"])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", default=str(DATASET / "deletion_requests.csv"))
    ap.add_argument("--out", default=str(REPO_ROOT / "output.csv"))
    a = ap.parse_args()
    ctx = [r for r in read_csv(DATASET / "sample_deletion_requests.csv")]
    rows = run(read_csv(Path(a.requests)), ctx)
    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["case_id", "deletion_status", "steps_json"])
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {a.out}")


if __name__ == "__main__":
    main()
