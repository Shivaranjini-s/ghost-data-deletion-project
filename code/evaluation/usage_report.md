# Token usage and cost report

Final full-dataset run that produced `output.csv` (518 requests): `python3 code/main.py`.

| Item | Value |
|---|---|
| Model providers / model names | none – the pipeline is fully deterministic (rules, SQLite, regex, `tesseract`/`pdftotext` OCR) |
| Model calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0 |
| Estimated total cost | USD 0.00 |
| Estimated cost per request | USD 0.00 |

Per-model totals: not applicable (no model used). Overall totals equal the figures above.
Local OCR (`tesseract`) is the only non-trivial compute; a full run takes well under two minutes on one CPU.
No API keys, credentials or sensitive configuration are used or stored.
