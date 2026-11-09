"""Evidence normalisation: every evidence file -> list[Obs].

The supplied evidence arrives as logs (six layouts), JSON exports and snapshot bundles,
SQLite snapshot dumps (primary + replicas), text hand-over ledgers and PDF / PNG artefacts.
Each parser below emits :class:`Obs` records in one shared vocabulary so that the audit engine
never has to know which modality a fact came from.
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

from .common import (DATASET, EMAIL_RE, is_null, read_csv, rid_kind, tok_email, tok_hash, tok_name,
                     tok_phone, tok_user, tokens_from_text, tokens_from_values)
from .logparse import parse_log
from .model import Obs


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _keys(*vals, names=()) -> frozenset:
    out = set()
    for v in vals:
        if is_null(v):
            continue
        for fn in (tok_email, tok_hash, tok_user, tok_phone):
            t = fn(v)
            if t:
                out.add(t)
                break
    for n in names:
        t = tok_name(n)
        if t:
            out.add(t)
    return frozenset(out)


def _mk(f, t, rid, *, present=None, flags=None, keys=(), topo="", src="", meta=None) -> Obs | None:
    rk = rid_kind(rid)
    if rk is None:
        return None
    kind, system = rk
    return Obs(file_id=f["file_id"], file_captured=f["captured_at"], t=t, system=system, rid=rid, kind=kind,
               present=present, flags=dict(flags or {}), keys=frozenset(keys), topo=topo, src=src,
               meta=dict(meta or {}))


def _cover(f, t, system) -> Obs:
    """Coverage marker: this file inspected `system` at time t (so absence of a record is a fact)."""
    return Obs(file_id=f["file_id"], file_captured=f["captured_at"], t=t, system=system or "", rid="__cover__",
               kind="COVER", present=None, src="cover")


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes", "y")


# ---------------------------------------------------------------------------
# generic ledger rows (record_type / result / subject)
# ---------------------------------------------------------------------------
def ledger_obs(f, t, rid, rtype, result, subject, src) -> Obs | None:
    keys = tokens_from_values(subject)
    if not keys and not is_null(subject):
        keys = frozenset(tokens_from_text(str(subject)))
    rtype = (rtype or "").upper()
    result = (result or "").upper()
    flags: dict = {}
    present: bool | None = True
    if rtype in ("USER_PROFILE", "SEARCH_INDEX_ENTRY", "USER_EXPORT", "SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
        present = result == "FOUND"
    elif rtype == "SUPPORT_MESSAGE":
        flags = {"sub": "message", "identifiable": result == "IDENTIFIABLE", "redacted": result == "REDACTED"}
    elif rtype == "SUPPORT_ATTACHMENT":
        flags = {"sub": "attachment"}
        present = result == "FOUND"
    elif rtype == "ANALYTICS_PROFILE":
        flags = {"identifiable": result == "IDENTIFIABLE"}
    elif rtype == "BACKUP_ARCHIVE":
        flags = {"restorable": result == "ACTIVE"}
    elif rtype == "DATA_FLOW":
        flags = {"enabled": result == "ACTIVE"}
    elif rtype in ("EMAIL_DELIVERY_LOG", "MARKETING_PROFILE", "SECONDARY_IDENTIFIER", "CACHE_ENTRY", "PRODUCT_TELEMETRY"):
        flags = {"ledger_type": rtype}
        present = result in ("FOUND", "IDENTIFIABLE", "ACTIVE")
        if rtype in ("EMAIL_DELIVERY_LOG", "PRODUCT_TELEMETRY"):
            flags["identifiable"] = result == "IDENTIFIABLE"
    else:
        flags = {"ledger_type": rtype}
    return _mk(f, t, rid, present=present, flags=flags, keys=keys, src=src,
               meta={"record_type": rtype, "result": result})


# ---------------------------------------------------------------------------
# logs
# ---------------------------------------------------------------------------
KEY_FIELDS = ("lookup_key", "match_key", "subject_key", "scan_key", "owner_key", "subject_ref", "correlation_key",
              "matched_value", "email", "customer_email", "owner_email", "requester_email", "subject_reference",
              "customer_reference", "requester_phone", "owner_phone", "phone", "email_hash", "lookup_value")


def parse_log_file(f, text: str) -> list[Obs]:
    lines = parse_log(text)
    trace_keys: dict[str, set] = defaultdict(set)
    trace_rids: dict[str, set] = defaultdict(set)
    for d in lines:
        tr = d.get("trace_id")
        if not tr:
            continue
        for k in KEY_FIELDS:
            if k in d and not is_null(d[k]):
                trace_keys[tr] |= set(_keys(d[k]))
        if d.get("resource_id"):
            trace_rids[tr].add(d["resource_id"])
    out: list[Obs] = []
    src = "log"

    def keys_of(d, *fields):
        ks = set(trace_keys.get(d.get("trace_id"), ()))
        for fld in fields:
            if fld in d:
                ks |= set(_keys(d[fld]))
        return ks

    for d in lines:
        ev = d.get("event")
        rid = d.get("resource_id", "")
        t = d["ts"]
        o: Obs | None = None
        if ev == "profile_lookup_completed":
            present = d.get("http_status") == "200" or (d.get("rows", "0") not in ("0", ""))
            o = _mk(f, t, rid, present=present, keys=keys_of(d, "correlation_key"), src=src,
                    meta={"http_status": d.get("http_status")})
        elif ev == "index_query_completed":
            present = d.get("result") == "hit" and d.get("total_hits", "1") != "0"
            o = _mk(f, t, rid, present=present, keys=keys_of(d, "email", "correlation_key"), src=src)
        elif ev == "message_pii_scan":
            o = _mk(f, t, rid, present=True, flags={"sub": "message", "identifiable": True},
                    keys=keys_of(d, "matched_value"), src=src)
        elif ev == "attachment_pii_scan":
            o = _mk(f, t, rid, present=True, flags={"sub": "attachment", "identifiable": True},
                    keys=keys_of(d, "matched_value"), src=src, meta={"file": d.get("file")})
        elif ev == "support_ticket_read_completed":
            ident = any(not is_null(d.get(x)) for x in ("requester_email", "requester_name", "requester_phone"))
            o = _mk(f, t, rid, present=True, flags={"identifiable": ident, "sub": "message"},
                    keys=keys_of(d, "requester_email", "customer_reference", "requester_phone")
                    | set(_keys(names=[d.get("requester_name")])), src=src)
        elif ev == "message_read":
            red = d.get("message_text", "").strip() == "[REDACTED]"
            o = _mk(f, t, rid, present=True,
                    flags={"sub": "message", "redacted": red, "identifiable": not red},
                    keys=keys_of(d, "subject_ref"), src=src)
        elif ev == "contact_query_completed":
            o = _mk(f, t, rid, present=d.get("rows", "0") != "0", flags={"identifiable": True}, keys=keys_of(d), src=src)
        elif ev == "deletion_marker_check":
            o = _mk(f, t, rid, present=not _truthy(d.get("marker_found")), keys=keys_of(d), src=src,
                    meta={"marker": d.get("marker_found")})
        elif ev == "analytics_identity_scan":
            o = _mk(f, t, rid, present=True, flags={"identifiable": d.get("direct_identifiers", "0") not in ("0", "")},
                    keys=keys_of(d, "matched_value"), src=src)
        elif ev == "analytics_profile_read":
            ident = d.get("direct_identifiers", "0") not in ("0", "")
            o = _mk(f, t, rid, present=True, flags={"identifiable": ident}, keys=keys_of(d, "email", "phone"), src=src)
        elif ev == "analytics_profile_read_completed":
            ident = any(not is_null(d.get(x)) for x in ("email", "phone", "email_hash", "customer_reference"))
            o = _mk(f, t, rid, present=True, flags={"identifiable": ident},
                    keys=keys_of(d, "email", "phone", "email_hash", "customer_reference"), src=src)
        elif ev == "contact_lookup_completed":
            o = _mk(f, t, rid, present=d.get("rows", "0") != "0", flags={"identifiable": True, "contact": True},
                    keys=keys_of(d, "correlation_key"), src=src, meta={"email_opt_in": d.get("email_opt_in")})
        elif ev == "connector_config_read_completed":
            o = _mk(f, t, rid, present=True, flags={"enabled": _truthy(d.get("enabled"))},
                    keys=keys_of(d, "customer_email", "customer_reference"), src=src,
                    meta={"connector": d.get("connector_name"), "status": d.get("last_delivery_status")})
        elif ev == "connector_config_loaded":
            o = _mk(f, t, rid, present=True, flags={"enabled": _truthy(d.get("enabled"))},
                    keys=keys_of(d, "correlation_key"), src=src, meta={"scheduler": d.get("scheduler_registered")})
        elif ev == "connector_heartbeat":
            o = _mk(f, t, rid, present=True, flags={"enabled": _truthy(d.get("enabled"))}, keys=keys_of(d), src=src,
                    meta={"scheduler": d.get("scheduler_registered")})
        elif ev == "restore_policy_read_completed":
            o = _mk(f, t, rid, present=_truthy(d.get("archive_present", "true")),
                    flags={"restorable": _truthy(d.get("restore_allowed"))},
                    keys=keys_of(d, "customer_email", "customer_reference"), src=src)
        elif ev == "restore_candidate_evaluated":
            restorable = _truthy(d.get("eligible")) and not _truthy(d.get("deletion_block"))
            o = _mk(f, t, rid, present=True, flags={"restorable": restorable}, keys=keys_of(d), src=src)
        elif ev == "restore_authorization_completed":
            o = _mk(f, t, rid, present=True, flags={"restorable": d.get("decision", "").lower() == "allow"},
                    keys=keys_of(d), src=src)
        elif ev == "export_download_check_completed":
            o = _mk(f, t, rid, present=_truthy(d.get("available")), keys=keys_of(d), src=src)
        elif ev == "export_metadata_read_completed":
            o = _mk(f, t, rid, present=_truthy(d.get("available")), keys=keys_of(d, "owner_email"), src=src)
        elif ev == "audit_record_read_completed":
            o = _mk(f, t, rid, present=True, keys=keys_of(d, "subject_reference"), src=src,
                    meta={"retention_until": d.get("retention_until"), "event_code": d.get("event_code")})
        elif ev == "retained_order_loaded":
            o = _mk(f, t, rid, present=d.get("access", "allowed") != "denied", keys=keys_of(d), src=src,
                    meta={"reason": d.get("reason")})
        elif ev == "record_lookup":
            o = ledger_obs(f, t, rid, d.get("record_type"), d.get("result"), d.get("subject_reference"), src="ledger_log")
        if o is not None:
            out.append(o)
    return out


# ---------------------------------------------------------------------------
# text hand-over ledger
# ---------------------------------------------------------------------------
def parse_ledger_text(f, text: str) -> list[Obs]:
    out = []
    for line in text.split("\n"):
        line = line.strip().lstrip("-").strip()
        parts = [p.strip() for p in line.split("|")]
        if len(parts) == 6 and re.match(r"\d{4}-\d\d-\d\dT", parts[0]):
            t, system, rid, rtype, result, subject = parts
            o = ledger_obs(f, t, rid, rtype, result, subject, src="ledger_txt")
            if o:
                out.append(o)
    return out


# ---------------------------------------------------------------------------
# JSON documents
# ---------------------------------------------------------------------------
def _collection_obs(f, t, collection, rec, topo, src) -> list[Obs]:
    """Map one record of a (data_store, collection) pair to observations."""
    rid = rec.get("resource_id", "")
    o: Obs | None = None
    if collection == "customer_profiles":
        o = _mk(f, t, rid, present=True, flags={"status": rec.get("account_status")},
                keys=_keys(rec.get("customer_reference"), rec.get("user_id"), rec.get("email"), rec.get("phone"),
                           rec.get("email_hash"), names=[rec.get("full_name")]), topo=topo, src=src)
    elif collection == "customer_search_documents":
        doc = rec.get("document") or {}
        o = _mk(f, t, rid, present=True, keys=_keys(doc.get("customer_reference"), doc.get("email"), doc.get("phone"),
                                                    doc.get("email_hash"), names=[doc.get("display_name")]),
                topo=topo, src=src, meta={"index": rec.get("index_name")})
    elif collection == "customer_analytics_reports":
        ident = any(not is_null(rec.get(x)) for x in ("user_id", "email", "phone", "email_hash"))
        o = _mk(f, t, rid, present=True, flags={"identifiable": ident},
                keys=_keys(rec.get("user_id"), rec.get("email"), rec.get("phone"), rec.get("email_hash")),
                topo=topo, src=src)
    elif collection == "backup_catalog":
        o = _mk(f, t, rid, present=True, flags={"restorable": bool(rec.get("restore_allowed"))},
                keys=_keys(rec.get("subject_reference")), topo=topo, src=src)
    elif collection == "customer_export_jobs":
        avail = rec.get("download_available")
        o = _mk(f, t, rid, present=True if avail is None else bool(avail),
                keys=_keys(rec.get("owner_email")), topo=topo, src=src)
    elif collection == "deleted_customer_references":
        ident = any(not is_null(rec.get(x)) for x in ("name", "email", "phone", "email_hash"))
        o = _mk(f, t, rid, present=True, flags={"identifiable": ident},
                keys=_keys(rec.get("subject_reference"), rec.get("email"), rec.get("phone"), rec.get("email_hash"),
                           names=[rec.get("name")]), topo=topo, src=src)
    elif collection == "connector_configurations":
        o = _mk(f, t, rid, present=True, flags={"enabled": bool(rec.get("enabled"))},
                keys=_keys(rec.get("subject_selector")), topo=topo, src=src,
                meta={"connector": rec.get("connector_name")})
    elif collection == "retained_order_records":
        o = _mk(f, t, rid, present=True, keys=_keys(rec.get("subject_reference")), topo=topo, src=src,
                meta={"retained_until": rec.get("retained_until")})
    elif collection == "security_audit_events":
        o = _mk(f, t, rid, present=True, keys=_keys(rec.get("subject_reference")), topo=topo, src=src,
                meta={"event": rec.get("event_name")})
    elif collection == "support_conversations":
        text = rec.get("message_text", "") or ""
        red = text.strip() == "[REDACTED]"
        ks = set(_keys(rec.get("subject_reference"))) | tokens_from_text(text)
        o = _mk(f, t, rid, present=True, flags={"sub": "message", "redacted": red, "identifiable": not red},
                keys=ks, topo=topo, src=src, meta={"ticket": rec.get("ticket_id"), "text": text})
    elif collection == "ticket_attachments":
        o = _mk(f, t, rid, present=True, flags={"sub": "attachment"}, keys=_keys(rec.get("uploaded_by")),
                topo=topo, src=src, meta={"ticket": rec.get("ticket_id"), "file": rec.get("file_name")})
    elif collection == "operational_record_history":
        o = ledger_obs(f, rec.get("recorded_at") or t, rid, rec.get("record_type"), rec.get("result"),
                       rec.get("lookup_value"), src="ledger_json")
    return [o] if o else []


def parse_snapshot_bundle(f, doc) -> list[Obs]:
    out: list[Obs] = []
    for snap in doc.get("snapshots", []):
        t = snap.get("captured_at") or doc.get("exported_at") or f["captured_at"]
        ds = snap.get("data_store")
        out.append(_cover(f, t, ds))
        for rec in snap.get("records", []):
            out += _collection_obs(f, t, snap.get("collection"), rec, topo="", src="bundle")
        # an empty collection is itself a fact: nothing in scope
    return out


def parse_ledger_json(f, doc) -> list[Obs]:
    out = []
    for r in doc.get("records", []):
        o = ledger_obs(f, r.get("recorded_at") or f["captured_at"], r.get("resource_id", ""), r.get("record_type"),
                       r.get("result"), r.get("subject_reference"), src="ledger_json")
        if o:
            out.append(o)
    return out


def parse_service_export(f, doc) -> list[Obs]:
    out: list[Obs] = []
    svc = doc.get("service_exports", {})
    src = "service_export"
    if "account_service" in svc:
        out.append(_cover(f, doc.get("exported_at") or f["captured_at"], "account_service"))

    def t_of(r):
        return r.get("observed_at") or doc.get("exported_at") or f["captured_at"]

    for r in svc.get("account_service", {}).get("profile_lookups", []):
        p = r.get("profile") or {}
        out.append(_mk(f, t_of(r), r["resource_id"], present=r.get("status_code") == 200 and bool(p) or r.get("status_code") == 200,
                       keys=_keys(p.get("customer_reference"), p.get("email"), p.get("phone"), p.get("email_hash"),
                                  names=[p.get("full_name")]), src=src, meta={"status": r.get("status_code")}))
    for r in svc.get("analytics_platform", {}).get("profiles", []):
        ident = any(not is_null(r.get(x)) for x in ("customer_reference", "email", "phone", "email_hash"))
        out.append(_mk(f, t_of(r), r["resource_id"], present=True, flags={"identifiable": ident},
                       keys=_keys(r.get("customer_reference"), r.get("email"), r.get("phone"), r.get("email_hash")),
                       src=src))
    for r in svc.get("backup_service", {}).get("restore_entries", []):
        out.append(_mk(f, t_of(r), r["resource_id"], present=True, flags={"restorable": bool(r.get("restore_allowed"))},
                       keys=_keys(r.get("customer_reference"), r.get("customer_email")), src=src))
    for r in svc.get("export_service", {}).get("exports", []):
        out.append(_mk(f, t_of(r), r["resource_id"], present=True,
                       keys=_keys(r.get("customer_reference"), r.get("owner_email"), r.get("owner_phone")), src=src))
    for r in svc.get("integration_service", {}).get("connectors", []):
        out.append(_mk(f, t_of(r), r["resource_id"], present=True, flags={"enabled": bool(r.get("enabled"))},
                       keys=_keys(r.get("customer_reference"), r.get("customer_email")), src=src,
                       meta={"connector": r.get("connector_name"), "status": r.get("last_delivery_status")}))
    for r in svc.get("search_service", {}).get("index_queries", []):
        hits = (r.get("hits") or {}).get("documents", [])
        total = (r.get("hits") or {}).get("total", len(hits))
        qk = _keys(r.get("query"))
        if hits:
            for h in hits:
                out.append(_mk(f, t_of(r), h.get("resource_id") or r.get("resource_id"), present=True,
                               keys=_keys(h.get("customer_reference"), h.get("email"), h.get("phone"), h.get("email_hash"),
                                          names=[h.get("display_name")]) | qk, src=src))
        elif r.get("resource_id"):
            out.append(_mk(f, t_of(r), r["resource_id"], present=bool(total), keys=qk, src=src))
    for r in svc.get("security_service", {}).get("audit_records", []):
        out.append(_mk(f, t_of(r), r["resource_id"], present=True, keys=_keys(r.get("subject_reference")), src=src,
                       meta={"retention_until": r.get("retention_until"), "event_code": r.get("event_code")}))
    for r in svc.get("support_platform", {}).get("tickets", []):
        ident = any(not is_null(r.get(x)) for x in ("requester_email", "requester_name", "requester_phone"))
        out.append(_mk(f, t_of(r), r["resource_id"], present=True, flags={"identifiable": ident, "sub": "message"},
                       keys=_keys(r.get("customer_reference"), r.get("requester_email"), r.get("requester_phone"),
                                  names=[r.get("requester_name")]), src=src, meta={"excerpt": r.get("message_excerpt")}))
    return [o for o in out if o]


def parse_simple_records(f, doc) -> list[Obs]:
    """customer_analytics_report / customer_export_jobs style documents."""
    out = []
    t = doc.get("captured_at") or f["captured_at"]
    coll = doc.get("collection")
    for r in doc.get("records", []):
        if coll == "customer_analytics_reports":
            out += _collection_obs(f, t, coll, r, "", "simple_json")
        elif coll == "customer_export_jobs":
            out += _collection_obs(f, t, coll, r, "", "simple_json")
    return out


def parse_json_file(f, path: Path) -> list[Obs]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if "service_exports" in doc:
        return parse_service_export(f, doc)
    if "snapshots" in doc:
        return parse_snapshot_bundle(f, doc)
    if doc.get("collection") in ("customer_analytics_reports", "customer_export_jobs"):
        return parse_simple_records(f, doc)
    if "records" in doc and doc["records"] and "record_type" in doc["records"][0]:
        return parse_ledger_json(f, doc)
    return []


# ---------------------------------------------------------------------------
# SQL snapshots
# ---------------------------------------------------------------------------
def _sql_conn(text: str) -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(text)
    return con


def parse_sql_file(f, path: Path) -> list[Obs]:
    text = path.read_text(encoding="utf-8")
    con = _sql_conn(text)
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    m = re.search(r"Captured at:\s*(\S+)", text) or re.search(r"snapshot_completed_at=(\S+)", text)
    snap_t = m.group(1) if m else f["captured_at"]
    out: list[Obs] = []
    src = "sql"
    if any(re.search(r"profile|account|customer_data_", tb) for tb in tables):
        out.append(_cover(f, snap_t, "account_service"))
    for tb in tables:
        cols = [r[1] for r in con.execute(f'pragma table_info("{tb}")')]
        rows = [dict(r) for r in con.execute(f'select * from "{tb}"')]
        if "record_json" in cols:  # primary / replica documents
            topo = "primary" if tb.endswith("_primary") else "replica:" + tb.replace("customer_data_", "")
            for r in rows:
                rec = json.loads(r["record_json"])
                out += _collection_obs(f, snap_t, r["collection_name"], rec, topo, src)
            continue
        if tb in ("customer_profiles_primary", "customer_profiles_failover_replica"):
            topo = "primary" if tb.endswith("_primary") else "replica:failover"
            for r in rows:
                out.append(_mk(f, snap_t, r["resource_id"], present=True, flags={"status": r.get("account_status")},
                               keys=_keys(r.get("user_id"), r.get("email"), r.get("phone"), names=[r.get("full_name")]),
                               topo=topo, src=src))
            continue
        if tb == "search_documents_primary":
            for r in rows:
                out.append(_mk(f, snap_t, r["resource_id"], present=True,
                               keys=_keys(r.get("email"), names=[r.get("display_name")]), topo="primary", src=src,
                               meta={"source": r.get("source_resource_id")}))
            continue
        for r in rows:  # inventory family
            o = None
            if tb == "customer_profiles":
                o = _mk(f, snap_t, r["resource_id"], present=True, flags={"status": r.get("account_status")},
                        keys=_keys(r.get("customer_reference"), r.get("email"), r.get("phone"), r.get("email_hash"),
                                   names=[r.get("full_name")]), src=src)
            elif tb == "customer_search_documents":
                o = _mk(f, snap_t, r["resource_id"], present=True,
                        keys=_keys(r.get("customer_reference"), r.get("email"), r.get("phone"), r.get("email_hash"),
                                   names=[r.get("display_name")]), src=src)
            elif tb == "customer_analytics_profiles":
                ident = any(not is_null(r.get(x)) for x in ("customer_reference", "email", "phone", "email_hash"))
                o = _mk(f, snap_t, r["resource_id"], present=True, flags={"identifiable": ident},
                        keys=_keys(r.get("customer_reference"), r.get("email"), r.get("phone"), r.get("email_hash")), src=src)
            elif tb == "support_records":
                ident = any(not is_null(r.get(x)) for x in ("requester_email", "requester_name", "requester_phone"))
                o = _mk(f, snap_t, r["resource_id"], present=True, flags={"identifiable": ident, "sub": "message"},
                        keys=_keys(r.get("customer_reference"), r.get("requester_email"), r.get("requester_phone"),
                                   names=[r.get("requester_name")]), src=src, meta={"excerpt": r.get("message_excerpt")})
            elif tb == "customer_exports":
                o = _mk(f, snap_t, r["resource_id"], present=True,
                        keys=_keys(r.get("customer_reference"), r.get("owner_email"), r.get("owner_phone")), src=src)
            elif tb == "connector_subscriptions":
                o = _mk(f, snap_t, r["resource_id"], present=True, flags={"enabled": _truthy(r.get("enabled"))},
                        keys=_keys(r.get("customer_reference"), r.get("customer_email")), src=src,
                        meta={"connector": r.get("connector_name"), "status": r.get("last_delivery_status")})
            elif tb == "backup_restore_entries":
                o = _mk(f, snap_t, r["resource_id"], present=True, flags={"restorable": _truthy(r.get("restore_allowed"))},
                        keys=_keys(r.get("customer_reference"), r.get("customer_email")), src=src)
            elif tb == "security_audit_records":
                o = _mk(f, snap_t, r["resource_id"], present=True, keys=_keys(r.get("subject_reference")), src=src,
                        meta={"retention_until": r.get("retention_until"), "event_code": r.get("event_code")})
            if o:
                out.append(o)
    return out


# ---------------------------------------------------------------------------
# top-level loader
# ---------------------------------------------------------------------------
def load_manifest() -> list[dict]:
    return read_csv(DATASET / "evidence_files.csv")


def load_all_observations(include_ocr: bool = True) -> tuple[list[Obs], list[dict]]:
    manifest = load_manifest()
    obs: list[Obs] = []
    art_files: list[dict] = []
    for f in manifest:
        p = DATASET / f["file_path"]
        suffix = p.suffix.lower()
        try:
            if suffix == ".log":
                obs += parse_log_file(f, p.read_text(encoding="utf-8", errors="replace"))
            elif suffix == ".json":
                obs += parse_json_file(f, p)
            elif suffix == ".sql":
                obs += parse_sql_file(f, p)
            elif suffix == ".txt":
                obs += parse_ledger_text(f, p.read_text(encoding="utf-8", errors="replace"))
            elif suffix in (".pdf", ".png") and include_ocr:
                from .ocr import parse_artifact
                obs += parse_artifact(f, p)
                art_files.append(f)
        except Exception as exc:  # keep going; one bad file must not sink the audit
            print(f"[warn] failed to parse {f['file_id']} ({p.name}): {exc}")
    obs = apply_identity_links(obs, art_files)
    return obs, manifest


# ---------------------------------------------------------------------------
# data-catalog identity links (system_activity LINK_RESOURCE_IDENTITY)
# ---------------------------------------------------------------------------
LINK_RE = re.compile(r"(?:linked|belongs only to)\b.*?(?:to\s+)?([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}) and (user_\d+)")


def apply_identity_links(obs: list[Obs], art_files: list[dict]) -> list[Obs]:
    """Screenshots / PDFs are noisy; the data catalog states exactly which identity a resource shown there
    belongs to.  The link replaces the OCR-derived keys and (for artefacts without a readable record id)
    supplies the observation itself."""
    from .common import parse_ts, tok_email, tok_user
    from datetime import timedelta
    links = []
    for r in read_csv(DATASET / "system_activity.csv"):
        if r["event_type"] != "LINK_RESOURCE_IDENTITY":
            continue
        m = LINK_RE.search(r["details"])
        if not m:
            continue
        links.append((r["resource_id"], parse_ts(r["event_time"]), frozenset({tok_email(m.group(1)), tok_user(m.group(2))})))
    by_file = {f["file_id"]: f for f in art_files}
    out = list(obs)
    for rid, t, keys in links:
        # the artefact captured a few minutes before the catalog link was written
        cands = [f for f in art_files if timedelta(0) <= t - parse_ts(f["captured_at"]) <= timedelta(minutes=30)]
        cands.sort(key=lambda f: t - parse_ts(f["captured_at"]))
        hit = False
        for o in out:
            if o.rid == rid and o.src == "ocr":
                o.keys = keys
                hit = True
        if not hit and cands:
            f = cands[0]
            rk = rid_kind(rid)
            if rk:
                kind, system = rk
                flags = {"identifiable": True} if kind == "ANALYTICS" else {}
                out.append(Obs(file_id=f["file_id"], file_captured=f["captured_at"], t=f["captured_at"], system=system,
                               rid=rid, kind=kind, present=True, flags=flags, keys=keys, src="ocr"))
    return out
