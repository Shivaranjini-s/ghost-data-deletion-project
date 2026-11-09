"""Identity resolution: request e-mail -> user_id -> every identifier the user has ever had."""
from __future__ import annotations

from .common import (DATASET, read_csv, tok_email, tok_hash, tok_name, tok_phone, tok_user)

# Fields whose historical values count as identifiers (audit log field_name -> tokeniser)
FIELD_TOK = {"email": tok_email, "email_hash": tok_hash, "phone": tok_phone, "name": tok_name}


class IdentityBook:
    def __init__(self) -> None:
        self.users = {r["user_id"]: r for r in read_csv(DATASET / "user_identities.csv")}
        self.audit = read_csv(DATASET / "user_audit_log.csv")
        self.by_email: dict[str, set[str]] = {}
        self.tokens: dict[str, set[str]] = {}
        self.audit_by_user: dict[str, list[dict]] = {}
        for uid, r in self.users.items():
            self.by_email.setdefault(r["email"].strip().lower(), set()).add(uid)
            self.tokens[uid] = {t for t in (tok_email(r["email"]), tok_hash(r["email_hash"]), tok_phone(r["phone"]),
                                            tok_user(uid)) if t}
        for a in self.audit:
            uid = a["user_id"]
            self.audit_by_user.setdefault(uid, []).append(a)
            fn = FIELD_TOK.get(a["field_name"])
            if not fn:
                continue
            for v in (a["old_value"], a["new_value"]):
                t = fn(v)
                if t and uid in self.tokens:
                    self.tokens[uid].add(t)
                if a["field_name"] == "email" and v:
                    self.by_email.setdefault(v.strip().lower(), set()).add(uid)

    def resolve(self, email: str) -> tuple[str | None, dict]:
        """Return (user_id, info). Current e-mail wins; otherwise the user whose history contains it."""
        e = (email or "").strip().lower()
        cands = sorted(self.by_email.get(e, ()))
        if not cands:
            return None, {"match": "none"}
        current = [u for u in cands if self.users[u]["email"].strip().lower() == e]
        if current:
            return current[0], {"match": "current", "candidates": cands}
        return cands[0], {"match": "historical", "candidates": cands}

    def tokens_for(self, uid: str) -> set[str]:
        return set(self.tokens.get(uid, ()))
