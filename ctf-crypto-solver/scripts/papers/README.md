# Paper library tooling

Scripts used to build and refresh `assets/papers/`.

| Script | Purpose |
|---|---|
| `fetch_eprint.py` | Query IACR ePrint for 2026 papers by keyword, dedupe to `eprint_raw.json` |
| `classify.py` | Assign selected papers to the six directions (`selected.json`) |
| `fetch_abstracts.py` | Fetch full abstracts for the shortlist (`selected_full.json`) |
| `build_assets.py` | Merge hand-written Chinese summaries + metadata into `assets/papers/` |
| `search.py` | Query `assets/papers/papers.json` from the CLI |

## Refresh workflow

Run from a scratch directory (the raw JSONs are not shipped):

```bash
PY=/c/code/miniconda/python.exe

"$PY" fetch_eprint.py --out eprint_raw.json        # ~260 candidates
"$PY" classify.py                                  # 91 selected, 6 directions
"$PY" fetch_abstracts.py                           # full abstracts
# edit build_assets.py: INFO (summaries), DIRS (categories), DIRS_ORDER
"$PY" build_assets.py                              # writes assets/papers/*
```

`build_assets.py` expects `selected_full.json` in the current directory and
writes into `<skill>/assets/papers/`.

## Notes

- ePrint has no public API; the scripts parse the search and paper pages.
  Keep the request rate low (`time.sleep` is already in the fetch scripts).
- `build_assets.py` is the source of truth for the Chinese summaries and the
  CTF ratings. Edit `INFO` there, then regenerate.
- `search.py` reads only `papers.json`, so it works without the raw data.
