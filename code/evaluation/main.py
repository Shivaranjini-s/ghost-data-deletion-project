"""Compare a prediction CSV with a reference CSV. Usage: python3 code/evaluation/main.py PRED REF [-v]"""
from __future__ import annotations

import csv
import json
import sys

FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def load(p):
    return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(open(p, encoding="utf-8"))}


def key(s):
    return tuple(s[f] for f in FIELDS)


def evaluate(pred, ref, verbose=False):
    n = len(ref)
    st = seq = 0
    tp = fp = fn = 0
    fld_ok = fld_tot = 0
    for cid, (rs, rsteps) in sorted(ref.items()):
        ps, psteps = pred.get(cid, ("", []))
        st += ps == rs
        seq += [key(s) for s in psteps] == [key(s) for s in rsteps]
        pk, rk = {key(s) for s in psteps}, {key(s) for s in rsteps}
        tp += len(pk & rk); fp += len(pk - rk); fn += len(rk - pk)
        for a, b in zip(psteps, rsteps):
            for f in FIELDS:
                fld_tot += 1
                fld_ok += a[f] == b[f]
        fld_tot += abs(len(psteps) - len(rsteps)) * len(FIELDS)
        if verbose and (ps != rs or [key(s) for s in psteps] != [key(s) for s in rsteps]):
            print(f"MISMATCH {cid} pred={ps} ref={rs}")
            for k in sorted(rk - pk): print("   missing", k)
            for k in sorted(pk - rk): print("   extra  ", k)
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return {"cases": n, "status_accuracy": st / n, "sequence_accuracy": seq / n, "step_precision": p, "step_recall": r,
            "step_f1": 2 * p * r / (p + r) if p + r else 0.0, "field_accuracy": fld_ok / fld_tot if fld_tot else 1.0}


if __name__ == "__main__":
    res = evaluate(load(sys.argv[1]), load(sys.argv[2]), "-v" in sys.argv)
    for k, v in res.items():
        print(f"{k}: {v:.4f}" if isinstance(v, float) else f"{k}: {v}")
