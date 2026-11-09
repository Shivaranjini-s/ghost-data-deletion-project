# Ghost Data audit agent

Deterministic deletion-audit pipeline for the HackerRank Orchestrate "Ghost Data Still Exists" challenge.
It makes **no LLM calls**; every decision is derived from `dataset/` with rules, so runs are reproducible,
free, and token-cost is zero (see `evaluation/usage_report.md`).

## Setup
* Python 3.10+ (standard library only, no `pip install` needed).
* Optional but recommended for screenshots / PDFs: `tesseract` (PNG OCR) and `pdftotext` (poppler-utils).
  Without them the image/PDF evidence is skipped and only logs, JSON, SQL and text evidence are used.

## Run
From the repository root:

```bash
python3 code/main.py                       # writes ./output.csv for dataset/deletion_requests.csv
python3 code/main.py --requests dataset/sample_deletion_requests.csv --out /tmp/sample_pred.csv
python3 code/evaluation/main.py /tmp/sample_pred.csv dataset/sample_output.csv -v   # metrics + diffs
python3 code/evaluation/custom_cases.py    # team-authored evaluation cases
```

No secrets or environment variables are used.

## Pipeline (code/ghost_audit)
1. `engine.authorizes_deletion` – request text -> deletion or not (access / correction / export /
   marketing-only / login-help requests become `NOT_APPLICABLE`, `[]`).
2. `identity.IdentityBook` – request e-mail -> `user_id` via the current snapshot *or* the audit log
   (historical e-mail), then every identifier the user ever had (e-mails, hashes, phones, user id).
3. `evidence.py`, `logparse.py`, `ocr.py` – every evidence file (6 log layouts, JSON exports and snapshot
   bundles, SQLite SQL dumps with primary/replica/failover tables, text ledgers, PDFs, screenshots) is
   normalised into timestamped observations (`model.Obs`). The data-catalog `LINK_RESOURCE_IDENTITY`
   activities repair OCR identity links.
4. Linking: a resource belongs to a case if an observation dated between `requested_at` and `audit_at`
   carries one of the user's identifiers. Anonymous resources (404 account lookups, anonymised analytics rows)
   are recovered from `system_activity.csv` (`assign.py`): deletion-worker activity near `reported_at`,
   eliminating resources keyed to other people and solving residual ambiguity by min-cost matching.
5. State at `audit_at`: latest observation per resource (only data dated <= `audit_at`; only files captured
   <= `audit_at` are cited). Workflow statuses and activity results are treated as claims.
6. `engine.audit_case` applies `deletion_rules.csv` (delete / redact / anonymise / retain / tombstone),
   emits findings, ordered remediation (disable flows & block restores first) and verification steps, in the
   canonical order, and decides `COMPLETE` vs `INCOMPLETE`.

## Layout
```
code/main.py              entry point
code/ghost_audit/         pipeline modules
code/evaluation/          evaluator (main.py), custom cases, evaluation_report.md, usage_report.md
```
