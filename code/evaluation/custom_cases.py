"""Team-authored evaluation cases (independent of the supplied samples).

Each case builds synthetic resource states / request texts and states the expected audit result explicitly.
Run: python3 code/evaluation/custom_cases.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_audit.engine import ResState, audit_case, authorizes_deletion  # noqa: E402
from ghost_audit.model import Obs  # noqa: E402

AUDIT_AT = "2026-10-01T12:00:00Z"


def st(rid, system, kind, present=True, flags=None, file="evidence_x", t="2026-09-30T10:00:00Z"):
    o = Obs(file_id=file, file_captured=t, t=t, system=system, rid=rid, kind=kind, present=present,
            flags=dict(flags or {}))
    return ResState(rid, system, kind, [o], AUDIT_AT)


def ops(steps):
    return [(s["phase"][:4], s["operation"], s["resource_id"], s["evidence_id"]) for s in steps]


def case_a_mixed_incomplete():
    """CC-1: live connector + unredacted support message + identifiable analytics + restorable backup."""
    states = [
        st("account_1", "account_service", "ACCOUNT", present=False, file="evidence_a"),
        st("data_flow_1", "integration_service", "DATA_FLOW", flags={"enabled": True}, file="evidence_a"),
        st("support_1", "support_platform", "SUPPORT", flags={"sub": "message", "identifiable": True}, file="evidence_a"),
        st("analytics_1", "analytics_platform", "ANALYTICS", flags={"identifiable": True}, file="evidence_a"),
        st("backup_1", "backup_service", "BACKUP", flags={"restorable": True}, file="evidence_a"),
        st("audit_record_1", "security_service", "AUDIT", file="evidence_a"),
    ]
    status, steps = audit_case(states, AUDIT_AT)
    expected = [
        ("FIND", "REPORT_EXPOSED_PII", "analytics_1", "evidence_a"),
        ("FIND", "REPORT_EXPOSED_PII", "support_1", "evidence_a"),
        ("FIND", "REPORT_ACTIVE_DATA_FLOW", "data_flow_1", "evidence_a"),
        ("FIND", "REPORT_RESTORE_RISK", "backup_1", "evidence_a"),
        ("REME", "DISABLE_DATA_FLOW", "data_flow_1", ""),
        ("REME", "BLOCK_RESTORE", "backup_1", ""),
        ("REME", "REDACT_RECORD", "support_1", ""),
        ("REME", "ANONYMIZE_RECORD", "analytics_1", ""),
        ("VERI", "VERIFY_RECORD_ABSENT", "account_1", ""),
        ("VERI", "VERIFY_RECORD_PRESENT", "audit_record_1", ""),
        ("VERI", "VERIFY_RECORD_REDACTED", "support_1", ""),
        ("VERI", "VERIFY_RECORD_ANONYMIZED", "analytics_1", ""),
        ("VERI", "VERIFY_DATA_FLOW_DISABLED", "data_flow_1", ""),
        ("VERI", "VERIFY_RESTORE_BLOCKED", "backup_1", ""),
    ]
    return status == "INCOMPLETE" and ops(steps) == expected, status, ops(steps)


def case_b_fully_compliant():
    """CC-2: every record already has its required treatment -> COMPLETE with evidence-backed verifications only."""
    states = [
        st("account_2", "account_service", "ACCOUNT", present=False, file="evidence_b"),
        st("search_2", "search_service", "SEARCH", present=False, file="evidence_b"),
        st("tombstone_2", "identity_service", "TOMBSTONE", flags={"identifiable": False}, file="evidence_b"),
        st("audit_record_2", "security_service", "AUDIT", file="evidence_b"),
        st("data_flow_2", "integration_service", "DATA_FLOW", flags={"enabled": False}, file="evidence_b"),
    ]
    status, steps = audit_case(states, AUDIT_AT)
    ok = status == "COMPLETE" and all(s["phase"] == "VERIFICATION" and s["evidence_id"] == "evidence_b" for s in steps)
    return ok and len(steps) == 5, status, ops(steps)


def case_c_tombstone_exposed():
    """CC-3: tombstone still carries direct identifiers -> redact (never delete) and verify the account is gone."""
    states = [
        st("account_3", "account_service", "ACCOUNT", present=False),
        st("tombstone_3", "identity_service", "TOMBSTONE", flags={"identifiable": True}),
        st("audit_record_3", "security_service", "AUDIT"),
    ]
    status, steps = audit_case(states, AUDIT_AT)
    names = [s["operation"] for s in steps]
    return (status == "INCOMPLETE" and "REDACT_RECORD" in names and "DELETE_RECORD" not in names
            and names[0] == "REPORT_EXPOSED_PII"), status, ops(steps)


def case_d_resurrected_by_sync():
    """CC-4: the account was deleted but an active sync re-created a search document later in time."""
    t_old, t_new = "2026-09-20T10:00:00Z", "2026-09-28T10:00:00Z"
    obs = [
        Obs(file_id="evidence_old", file_captured=t_old, t=t_old, system="search_service", rid="search_4",
            kind="SEARCH", present=False),
        Obs(file_id="evidence_new", file_captured=t_new, t=t_new, system="search_service", rid="search_4",
            kind="SEARCH", present=True),
    ]
    s = ResState("search_4", "search_service", "SEARCH", obs, AUDIT_AT)
    status, steps = audit_case([s], AUDIT_AT)
    return status == "INCOMPLETE" and steps[0]["evidence_id"] == "evidence_new", status, ops(steps)


def case_e_non_deletion_requests():
    """CC-5: access / correction / export / marketing-only requests (several languages) are NOT_APPLICABLE."""
    non_deletion = [
        "Please send me a copy of the information you hold on my account. Do not delete anything.",
        "I only want to unsubscribe: remove me from marketing lists only, keep the account.",
        "Please change the email address used for this account. I want to continue using the service.",
    ]
    deletion = [
        "Je demande la suppression définitive du compte associé à cette adresse e-mail.",
        "このメールアドレスに関連するアカウントの完全な削除を依頼します。",
        "Please erase the account linked to this email address.",
    ]
    ok = (not any(authorizes_deletion(t) for t in non_deletion)) and all(authorizes_deletion(t) for t in deletion)
    return ok, "NOT_APPLICABLE/DELETION", []


CASES = [case_a_mixed_incomplete, case_b_fully_compliant, case_c_tombstone_exposed, case_d_resurrected_by_sync,
         case_e_non_deletion_requests]

if __name__ == "__main__":
    failed = 0
    for fn in CASES:
        ok, status, detail = fn()
        print(f"{'PASS' if ok else 'FAIL'}  {fn.__name__}: {status}")
        if not ok:
            failed += 1
            for d in detail:
                print("     ", d)
    print(f"{len(CASES) - failed}/{len(CASES)} custom cases passed")
    sys.exit(1 if failed else 0)
