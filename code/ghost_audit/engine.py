"""Deterministic audit engine: Obs + identity + policy -> (status, steps)."""
from __future__ import annotations

import re
from collections import defaultdict

from .common import parse_ts
from .model import Obs

# ---------------------------------------------------------------------------
# intent
# ---------------------------------------------------------------------------
NEGATIVE = re.compile(
    r"not asking for (a )?deletion|not a request (to|for)|(do not|don'?t|please do not) (close|delete|remove|erase)|"
    r"without removing|(leave|keep) (the |my )?(account|profile)|leave .{0,40}in place|account active|"
    r"continue (to )?us(e|ing)|still (need|want|use)|(marketing|mailing) lists only|stop the promotional|"
    r"information request|replace it with|change the email|is misspelled|download my|(need|send me|get) a copy of|copy of (the information|last year)", re.I)


def authorizes_deletion(text: str) -> bool:
    """Requests are deletion requests unless they carry an explicit non-deletion intent
    (access, correction, export, marketing opt-out, login help)."""
    return not NEGATIVE.search(text or "")


# ---------------------------------------------------------------------------
# step ordering
# ---------------------------------------------------------------------------
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT", "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE", "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}


def mk_step(phase, system, rid, op, evidence=""):
    return {"phase": phase, "system_id": system, "resource_id": rid, "operation": op, "state": STATE[op],
            "evidence_id": evidence}


def order_steps(steps: list[dict]) -> list[dict]:
    steps = sorted(steps, key=lambda s: (PHASE_ORDER[s["phase"]], OP_ORDER[s["operation"]], s["system_id"],
                                         s["resource_id"]))
    for i, s in enumerate(steps, 1):
        s["step_no"] = i
    return steps


# ---------------------------------------------------------------------------
# resource state
# ---------------------------------------------------------------------------
class ResState:
    """Latest known state of one resource at audit_at."""

    def __init__(self, rid: str, system: str, kind: str, obs: list[Obs], audit_at: str):
        self.rid, self.system, self.kind = rid, system, kind
        self.obs = obs
        last = obs[-1]
        grp = [o for o in obs if o.file_id == last.file_id and o.t == last.t]
        self.last = last
        self.group = grp
        self.present = any(o.present for o in grp if o.present is not None) if any(
            o.present is not None for o in grp) else None
        self.flags = {}
        for o in grp:
            for k, v in o.flags.items():
                if isinstance(v, bool):
                    self.flags[k] = self.flags.get(k, False) or v
                else:
                    self.flags[k] = v
        cit = [o for o in obs if o.file_captured <= audit_at]
        self.evidence = (cit[-1].file_id if cit else last.file_id)

    def flag(self, k):
        return bool(self.flags.get(k))


def collect_states(linked: set[str], by_rid: dict[str, list[Obs]], audit_at: str, since: str = "") -> list[ResState]:
    out = []
    for rid in sorted(linked):
        obs = [o for o in by_rid[rid] if since <= o.t <= audit_at]
        if not obs:
            continue
        obs.sort(key=lambda o: (o.t, o.file_captured, o.file_id))
        o0 = obs[0]
        out.append(ResState(rid, o0.system, o0.kind, obs, audit_at))
    return out


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------
def audit_case(states: list[ResState], audit_at: str) -> tuple[str, list[dict]]:
    findings, remed, verif = [], [], []
    bad = False
    for s in states:
        k, f, ev = s.kind, s.flags, s.evidence
        P, S, R = s.rid, s.system, s.rid
        if k == "ACCOUNT":
            if s.present:
                bad = True
                findings.append(mk_step("FINDING", S, R, "REPORT_REMAINING_RECORD", ev))
                remed.append(mk_step("REMEDIATION", S, R, "DELETE_RECORD"))
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_RECORD_ABSENT"))
            else:
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_RECORD_ABSENT", ev))
        elif k in ("SEARCH", "EXPORT", "MARKETING", "CACHE", "OBJECT") or (k == "SUPPORT" and f.get("sub") != "message") \
                or (k == "ANALYTICS" and f.get("contact")):
            if s.present:
                bad = True
                findings.append(mk_step("FINDING", S, R, "REPORT_REMAINING_RECORD", ev))
                remed.append(mk_step("REMEDIATION", S, R, "DELETE_RECORD"))
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_RECORD_ABSENT"))
            else:
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_RECORD_ABSENT", ev))
        elif k == "SUPPORT":
            if f.get("identifiable") and not f.get("redacted"):
                bad = True
                findings.append(mk_step("FINDING", S, R, "REPORT_EXPOSED_PII", ev))
                remed.append(mk_step("REMEDIATION", S, R, "REDACT_RECORD"))
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_RECORD_REDACTED"))
            else:
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_RECORD_REDACTED", ev))
        elif k == "ANALYTICS":
            if f.get("identifiable"):
                bad = True
                findings.append(mk_step("FINDING", S, R, "REPORT_EXPOSED_PII", ev))
                remed.append(mk_step("REMEDIATION", S, R, "ANONYMIZE_RECORD"))
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_RECORD_ANONYMIZED"))
            else:
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_RECORD_ANONYMIZED", ev))
        elif k in ("TOMBSTONE", "EMAIL_LOG"):
            if f.get("identifiable"):
                bad = True
                findings.append(mk_step("FINDING", S, R, "REPORT_EXPOSED_PII", ev))
                remed.append(mk_step("REMEDIATION", S, R, "REDACT_RECORD"))
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_RECORD_REDACTED"))
            else:
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_RECORD_REDACTED", ev))
        elif k == "DATA_FLOW":
            if f.get("enabled"):
                bad = True
                findings.append(mk_step("FINDING", S, R, "REPORT_ACTIVE_DATA_FLOW", ev))
                remed.append(mk_step("REMEDIATION", S, R, "DISABLE_DATA_FLOW"))
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_DATA_FLOW_DISABLED"))
            else:
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_DATA_FLOW_DISABLED", ev))
        elif k == "BACKUP":
            if f.get("restorable"):
                bad = True
                findings.append(mk_step("FINDING", S, R, "REPORT_RESTORE_RISK", ev))
                remed.append(mk_step("REMEDIATION", S, R, "BLOCK_RESTORE"))
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_RESTORE_BLOCKED"))
            else:
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_RESTORE_BLOCKED", ev))
        elif k in ("AUDIT", "LEGAL_HOLD"):
            if s.present is not False:
                verif.append(mk_step("VERIFICATION", S, R, "VERIFY_RECORD_PRESENT", ev))
    if not bad:
        steps = verif
    else:
        for v in verif:
            v["evidence_id"] = ""
        steps = findings + remed + verif
    return ("INCOMPLETE" if bad else "COMPLETE"), order_steps(steps)
