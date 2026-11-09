"""PDF / screenshot evidence -> Obs.

PDFs are read with ``pdftotext``; PNG screenshots with ``tesseract``. Screenshots are admin consoles that
show a table of records plus a detail panel for the *selected* record; the selected record id is the one that
follows the "<n> records" caption of the detail panel. OCR noise in e-mail domains is repaired against the
set of domains that occur in the identity table.
"""
from __future__ import annotations

import difflib
import re
import shutil
import subprocess
from functools import lru_cache

from .common import DATASET, PREFIX_KIND, read_csv, tok_email, tok_phone, tok_user
from .model import Obs

RID = re.compile(r"\b(account|search|support|analytics|export|data[_ ]flow|backup|audit[_ ]record|legal[_ ]hold|"
                 r"tombstone|marketing|object|cache|email[_ ]delivery)[_ ]?(\d{1,5})\b", re.I)
SELECTED = re.compile(r"records?\s+((?:account|search|support|analytics|export|data[_ ]flow|backup|audit[_ ]record|"
                      r"legal[_ ]hold|tombstone|marketing|object|cache)[_ ]\d{1,5})", re.I)
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER = re.compile(r"\buser[_ ]?(\d{1,4})\b", re.I)
PHONE = re.compile(r"\+\d[\d ()\-]{7,}\d")


@lru_cache(maxsize=1)
def _domains() -> list[str]:
    return sorted({r["email"].split("@")[-1].lower() for r in read_csv(DATASET / "user_identities.csv")})


def _fix_email(e: str) -> str:
    local, _, dom = e.lower().partition("@")
    doms = _domains()
    if dom not in doms:
        m = difflib.get_close_matches(dom, doms, n=1, cutoff=0.75)
        if m:
            dom = m[0]
    return f"{local}@{dom}"


def _norm_rid(s: str) -> str:
    return re.sub(r"[ ]", "_", s.strip().lower()).replace("data_flow", "data_flow")


def read_text(path) -> str:
    suffix = path.suffix.lower()
    try:
        if suffix == ".pdf":
            if shutil.which("pdftotext"):
                return subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True,
                                      timeout=60).stdout
        elif suffix == ".png" and shutil.which("tesseract"):
            return subprocess.run(["tesseract", str(path), "-", "--psm", "6"], capture_output=True, text=True,
                                  timeout=120).stdout
    except Exception:
        pass
    return ""


def _kind(rid: str):
    m = re.match(r"([a-z_]+?)_\d+$", rid)
    return PREFIX_KIND.get(m.group(1)) if m else None


def parse_artifact(f, path) -> list[Obs]:
    text = read_text(path)
    if not text.strip():
        return []
    emails = {_fix_email(e) for e in EMAIL.findall(text)}
    users = {f"user_{int(m)}" for m in USER.findall(text)}
    phones = {tok_phone(p) for p in PHONE.findall(text)}
    keys = {t for t in (tok_email(e) for e in emails) if t} | {tok_user(u) for u in users if tok_user(u)} | \
           {p for p in phones if p}
    t = f["captured_at"]
    low = text.lower()
    out: list[Obs] = []
    rids: list[str] = []
    if path.suffix.lower() == ".png":
        m = SELECTED.search(text)
        if m:
            rids = [_norm_rid(m.group(1))]
    else:
        seen = []
        for m in RID.finditer(text):
            r = _norm_rid(f"{m.group(1)}_{m.group(2)}")
            if r not in seen:
                seen.append(r)
        rids = seen
    for rid in rids:
        rk = _kind(rid)
        if not rk:
            continue
        kind, system = rk
        flags: dict = {}
        meta: dict = {}
        if kind == "ANALYTICS":
            flags["identifiable"] = bool(emails)
        elif kind == "SUPPORT":
            if "attachment" in low or "upload" in low:
                flags["sub"] = "attachment"
            else:
                flags.update(sub="message", identifiable=bool(emails), redacted=False)
        elif kind == "DATA_FLOW":
            flags["enabled"] = not re.search(r"disabled|paused|stopped", low)
        elif kind == "BACKUP":
            flags["restorable"] = not re.search(r"blocked|restore denied", low)
        elif kind == "AUDIT":
            mm = re.search(r"retain until\s+(\d{1,2} \w{3} \d{4})", text)
            if mm:
                meta["retain_until_text"] = mm.group(1)
        out.append(Obs(file_id=f["file_id"], file_captured=f["captured_at"], t=t, system=system, rid=rid, kind=kind,
                       present=True, flags=flags, keys=frozenset(keys), src="ocr", meta=meta))
    return out
