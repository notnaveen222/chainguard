# ChainGuard — Build Progress

**Purpose:** resumable build state. If the build is interrupted, this file records
exactly what is done, what was in flight, and the next concrete step — so work
resumes without re-deriving anything.

**Last updated:** 2026-08-18, Phases 0–3 and 5–8 complete; Phase 4 (model
training) pending the dataset build.

---

## Status

| Phase | Description | Status |
|---|---|---|
| 0 | Scaffold: repo, git, venv, deps, docs | ✅ Complete |
| 1 | Registry layer: npm/PyPI clients, semver, manifests, resolver | ✅ Complete |
| 2 | Detection engine: AST analysers, signals, features, typosquatting | ✅ Complete |
| 3 | Dataset pipeline: encoded vault, corpus acquisition | ✅ Complete (1,797 samples stored) |
| 4 | Train + evaluate classifier | ⏳ Code complete; waiting on feature matrix |
| 5 | OSV integration + reachability analysis | ✅ Complete |
| 6 | FastAPI backend + scan orchestration | ✅ Complete |
| 7 | React + Tailwind dashboard | ✅ Complete |
| 8 | Tests, demo data, docs | ✅ Complete (91 tests passing) |

---

## Verified results so far

| Check | Result |
|---|---|
| Test suite | 91 passed, fully offline, < 1s |
| Demo scan (`demo/vulnerable-app`) | 92 advisories → **3 reachable, 97% ruled out** |
| Reachability proof path | `app → app.main → app.bootstrap → config.load_settings → yaml.load` |
| Remediation ordering | `pyyaml` (3 reachable fixes) ranked above `pillow` (56 fixes, 0 reachable) |
| API end-to-end | Submit → poll → result → history, all passing |
| Frontend build | `vite build` clean, 2201 modules |
| Sample vault | 1,797 samples (898 malicious, 899 benign), all hash-verified |
| False-positive check | 12 real packages score 0.00–0.41 on the rules baseline |

---

## Environment (verified 2026-08-18)

| Component | Version / state |
|---|---|
| Python | 3.10.11 (`.venv` at repo root) |
| Node / npm | v22.17.1 / 11.6.0 |
| git | 2.50.1 — local repo, **no remote configured** |
| Backend deps | 63 packages installed |
| Frontend deps | 224 packages installed |
| OSV.dev / npm / PyPI | All reachable |
| `ANTHROPIC_API_KEY` | Not set — LLM layer disabled, system fully functional |

---

## Remaining work

1. **Train the classifier.** The dataset build is the long pole. Once
   `data/corpus/features.csv` exists:

   ```
   python scripts/train_model.py
   ```

   This writes the model, model card, and six evaluation charts to `data/models/`.
   The dashboard's **Model & evaluation** tab reads them automatically.

2. **Optional polish** if time allows: HTML/PDF report export, and wiring the
   (already-written, disabled-by-default) LLM explanation layer into the UI.

Everything else is done. The system is demonstrable now — it falls back to the
rules baseline and says so in every result.

---

## Notes for resuming

- Every phase ends with a local git commit; `git log --oneline` shows the exact
  checkpoint reached. Nothing is pushed to any remote.
- Samples under `data/quarantine/` are stored encoded and are never executed. If
  that directory is missing, re-run `scripts/build_dataset.py`.
- To re-analyse the existing vault without re-downloading (e.g. after changing
  the feature schema or an analyser):

  ```
  python scripts/build_dataset.py --skip-download
  ```

- Bumping `SCHEMA_VERSION` in `analysis/features.py` requires rebuilding the
  matrix and retraining; the model refuses to score across schema versions rather
  than silently misaligning columns.
