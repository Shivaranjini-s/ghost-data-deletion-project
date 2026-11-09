"""Shared helpers: paths, time parsing, identifier normalisation, resource-id vocabulary."""
from __future__ import annotations

import csv
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET = REPO_ROOT / "dataset"

ISO = "%Y-%m-%dT%H:%M:%SZ"


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    value = value.strip()
    for fmt in (ISO, "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(value, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(ISO)


def minutes_between(later: datetime, earlier: datetime) -> float:
    return (later - earlier).total_seconds() / 60.0


def read_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# ---------------------------------------------------------------------------
# Resource vocabulary
# ---------------------------------------------------------------------------
# resource-id prefix -> (kind, system_id)
PREFIX_KIND = {
    "account": ("ACCOUNT", "account_service"),
    "search": ("SEARCH", "search_service"),
    "support": ("SUPPORT", "support_platform"),
    "analytics": ("ANALYTICS", "analytics_platform"),
    "export": ("EXPORT", "export_service"),
    "data_flow": ("DATA_FLOW", "integration_service"),
    "backup": ("BACKUP", "backup_service"),
    "audit_record": ("AUDIT", "security_service"),
    "legal_hold": ("LEGAL_HOLD", "legal_service"),
    "tombstone": ("TOMBSTONE", "identity_service"),
    "marketing": ("MARKETING", "marketing_platform"),
    "object": ("OBJECT", "object_storage"),
    "cache": ("CACHE", "cache_service"),
    "email_delivery": ("EMAIL_LOG", "email_delivery_service"),
}

RID_RE = re.compile(r"^(account|search|support|analytics|export|data_flow|backup|audit_record|legal_hold|tombstone|marketing|object|cache|email_delivery)_[A-Za-z0-9]+$")


def rid_kind(rid: str) -> tuple[str, str] | None:
    m = RID_RE.match(rid or "")
    if not m:
        return None
    return PREFIX_KIND[m.group(1)]


# ---------------------------------------------------------------------------
# Identifier tokens
# ---------------------------------------------------------------------------
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
USER_RE = re.compile(r"\buser_\d+\b")
NULLISH = {"", "null", "none", "nan", "n/a", "-"}


def is_null(v) -> bool:
    return v is None or (isinstance(v, str) and v.strip().lower() in NULLISH)


def tok_email(v) -> str | None:
    if is_null(v):
        return None
    v = str(v).strip().lower()
    return f"e:{v}" if "@" in v else None


def tok_hash(v) -> str | None:
    if is_null(v):
        return None
    v = str(v).strip().lower()
    return f"h:{v}" if re.fullmatch(r"[0-9a-f]{64}", v) else None


def tok_phone(v) -> str | None:
    if is_null(v):
        return None
    digits = re.sub(r"\D", "", str(v))
    return f"p:{digits}" if len(digits) >= 7 else None


def tok_user(v) -> str | None:
    if is_null(v):
        return None
    v = str(v).strip().lower()
    return f"u:{v}" if re.fullmatch(r"user_\d+", v) else None


def tok_name(v) -> str | None:
    if is_null(v):
        return None
    v = re.sub(r"\s+", " ", str(v).strip().lower())
    return f"n:{v}" if len(v) >= 4 else None


def tokens_from_text(text: str) -> set[str]:
    """All identifier tokens appearing inside free text (emails, hashes, user refs)."""
    out: set[str] = set()
    if not text:
        return out
    for m in EMAIL_RE.findall(text):
        out.add(f"e:{m.lower()}")
    for m in HASH_RE.findall(text.lower()):
        out.add(f"h:{m}")
    for m in USER_RE.findall(text.lower()):
        out.add(f"u:{m}")
    return out


def tokens_from_values(*values) -> set[str]:
    """Best-effort token extraction from loosely typed values (email/hash/phone/user/name)."""
    out: set[str] = set()
    for v in values:
        if is_null(v):
            continue
        for fn in (tok_email, tok_hash, tok_user):
            t = fn(v)
            if t:
                out.add(t)
    return out


def hours(h: float) -> timedelta:
    return timedelta(hours=h)
