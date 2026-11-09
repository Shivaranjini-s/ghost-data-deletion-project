# Evaluation report

Command: `python3 code/main.py --requests dataset/sample_deletion_requests.csv --out pred.csv`
then `python3 code/evaluation/main.py pred.csv dataset/sample_output.csv -v`.

## Results on the 32 sample cases
| Metric | Value |
|---|---|
| Case-level status accuracy | 1.0000 (32/32) |
| Sequence accuracy (exact step array) | 0.8438 (27/32) |
| Step precision / recall / F1 | 0.9895 / 0.9741 / 0.9817 |
| Field-level accuracy | 0.9646 |

Full run: 518 rows (348 INCOMPLETE, 160 COMPLETE, 10 NOT_APPLICABLE), sorted by `case_id`.

## Additional team-authored cases (`code/evaluation/custom_cases.py`)
1. `case_a_mixed_incomplete` - leftover records across several systems -> INCOMPLETE.
2. `case_b_fully_compliant` - everything deleted/redacted, retained records kept -> COMPLETE.
3. `case_c_tombstone_exposed` - tombstone still holds name/email/phone/hash -> INCOMPLETE (redact).
4. `case_d_resurrected_by_sync` - active sync recreates deleted data -> INCOMPLETE (disable flow first).
5. `case_e_non_deletion_requests` - access/correction/export/marketing requests -> NOT_APPLICABLE, `[]`.
All 5 pass.

## Failures found and improvements made
* Reported workflow status was wrongly trusted -> state is now derived only from evidence dated <= `audit_at`.
* Historical e-mails were missed -> identity resolved through `user_audit_log.csv` as well as the snapshot.
* Anonymised/404 resources carried no identifier -> recovered from `system_activity.csv` (`assign.py`).
* OCR identity links were unreliable -> repaired with `LINK_RESOURCE_IDENTITY` activities.

## Known remaining errors (5 sample cases)
case_03 and case_23 pick a neighbouring resource ID for an anonymised/absent record; case_04, case_18 and
case_20 each omit one verification step (an absent account record or a retained audit record). All are
resource-attribution misses, not status errors.
