"""Normalised observation model shared by every evidence parser."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Obs:
    """One timestamped fact about one resource, extracted from one evidence file.

    kind     ACCOUNT | SEARCH | SUPPORT | ANALYTICS | EXPORT | DATA_FLOW | BACKUP | AUDIT |
             LEGAL_HOLD | TOMBSTONE | MARKETING | OBJECT
    present  whether the resource exists / is visible (None when the source says nothing)
    flags    normalised state flags, interpreted per kind:
               identifiable  record still exposes (or is attributable to) a person
               redacted      record explicitly redacted
               enabled       data flow active
               restorable    backup can restore the subject
               sub           SUPPORT sub type: "message" | "attachment" | ""
    keys     identity tokens ("e:<email>", "h:<hash>", "p:<phone>", "u:<user_id>", "n:<name>")
             that link the record to a person; empty for anonymous records.
    topo     database topology the row came from ("primary", "replica:<name>", "").
    """

    file_id: str
    file_captured: str
    t: str
    system: str
    rid: str
    kind: str
    present: bool | None = None
    flags: dict = field(default_factory=dict)
    keys: frozenset = frozenset()
    topo: str = ""
    src: str = ""
    meta: dict = field(default_factory=dict)

    def key_str(self) -> str:
        return ",".join(sorted(self.keys))
