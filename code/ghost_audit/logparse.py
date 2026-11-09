"""Tokeniser for the six platform log layouts found in dataset/evidence/logs.

Layouts handled: key=value, JSON-per-line, RFC5424-style syslog, pipe separated,
bracketed, and the cloud-runtime wrapper whose payload sits in a quoted ``message`` field.
Every line is turned into a flat dict with at least ``ts``; ``service``/``event``/``trace_id``
are filled when the layout provides them.
"""
from __future__ import annotations

import json
import re

KV = re.compile(r'([A-Za-z_][\w.]*)=("(?:[^"\\]|\\.)*"|\S+)')
TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s+(.*)$")
SYSLOG = re.compile(r"<(\d+)>1 (\S+) (\S+) (\S+) - - (.*)$")
BRACKET = re.compile(r"\[(\w+)\] \[(\w+)\] \[([^\]]+)\] (\w+): (.*)$")


def _unq(v: str) -> str:
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return v


def kv(text: str) -> dict:
    return {k: _unq(v) for k, v in KV.findall(text)}


def parse_line(line: str) -> dict | None:
    m = TS.match(line)
    if not m:
        return None
    ts, rest = m.groups()
    d: dict = {"ts": ts}
    if rest.startswith("{"):
        try:
            payload = json.loads(rest)
        except ValueError:
            return None
        for k, v in payload.items():
            d[k] = v if isinstance(v, str) else json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        d["level"] = d.pop("severity", d.get("level"))
        d["_fmt"] = "json"
        return d
    if rest.startswith("<"):
        mm = SYSLOG.match(rest)
        if not mm:
            return None
        _, _node, svc, trace, tail = mm.groups()
        d.update(kv(tail))
        d.update(service=svc, trace_id=trace, _fmt="syslog")
        return d
    parts = rest.split(" | ", 4)
    if len(parts) == 5 and parts[0] in ("DEBUG", "INFO", "WARN", "ERROR"):
        level, svc, trace, event, tail = parts
        d.update(kv(tail))
        d.update(level=level, service=svc, trace_id=trace, event=event, _fmt="pipe")
        return d
    mb = BRACKET.match(rest)
    if mb:
        level, svc, trace, event, tail = mb.groups()
        d.update(kv(tail))
        d.update(level=level, service=svc, trace_id=trace, event=event, _fmt="bracket")
        return d
    if rest.startswith("requestId="):
        head, _, msg = rest.partition(" message=")
        d.update(kv(head))
        if msg:
            d.update(kv(_unq(msg)))
        d["service"] = d.get("function") or d.get("service")
        d["trace_id"] = d.get("requestId")
        d["_fmt"] = "cloud"
        return d
    d.update(kv(rest))
    d["_fmt"] = "kv"
    return d


def parse_log(text: str) -> list[dict]:
    out = []
    for line in text.split("\n"):
        if not line.strip():
            continue
        d = parse_line(line)
        if d is not None:
            out.append(d)
    return out
