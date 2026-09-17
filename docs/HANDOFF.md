# Handoff: ChainGuard, 2026-09-17

Read this first in the next session. It supersedes the root `HANDOFF.md`
(2026-09-16), which describes the state before the work below. Everything here
is committed and pushed to `main` (latest `cd0d1fb`) unless marked otherwise.

---

## 1. Where things stand

| Area | State |
|---|---|
| Detection model | Retrained on our corpus + the Guo et al. benchmark (15,886 packages). Deployed. |
| Headline benchmark number | **F1 0.885 off the shelf** vs GuardDog 0.924 and SAP XGBoost 0.883. See §3 before quoting any number. |
| AI layer | OpenAI (`gpt-5.6-luna`): GPT reviews flagged packages, and a chat "security consultant" in the dashboard. Tested live. |
| Dashboard | Redesigned (sidebar, stats strip, call-path trace, AI review cards, "Known malware" scan mode). |
| Tests | 124/124 pass. |
| Docs out of date | `README.md`, `PROGRESS.md`, `docs/MODEL_CARD.md` still show the older model numbers. The dashboard's Model page and `data/models/model_card.json` are current. |

---

## 2. What was done, in order

1. **Local setup on Windows.** The repo contains malware-shaped detection code, so
   Bitdefender quarantined `backend/chainguard/analysis/python_ast.py`. Fix: a
   Bitdefender exception for `C:\Projects\chainguard`, then restore the file from
   quarantine. Expect this on any machine with antivirus.
2. **Dashboard redesign** (`fc378ef`). The sidebar is adapted from 21st.dev "Dashboard
   Sidebar" (arunjdass) and the stats strip from "Statistics Card 7" (sean0205);
   number ticker and border beam come from Magic UI. The scan submit/poll logic
   was not changed.
3. **Real-world false positives fixed** (`fc378ef`). The first model flagged 10 ordinary
   packages as malicious on a real 750-package Next.js app (`@radix-ui/rect`,
   `get-nonce`, ...). Cause: the benign training sample was mostly large popular
   packages, so the model learned that small packages are malicious. Removing size
   or metadata features did not help (`scripts/experiment_features.py`). What
   worked was adding 653 real dependency-tree packages as benign
   (`scripts/augment_benign.py`): held-out real-app flags went from 7 malicious and
   71 suspicious to 0 and 2.
4. **AI layer switched to OpenAI** (`ade5cd2`, `bf027ae`, `8eedf5f`).
   - Hybrid verdicts (`backend/chainguard/llm/review.py`): the classifier screens every
     package, and GPT reviews flagged/suspicious ones with structured output
     (verdict, confidence, reasoning, recommendation). The GPT verdict is final; the
     classifier's verdict is kept in `model_verdict`. Packages the AI clears are
     listed in "Cleared by AI review", never hidden.
   - Consultant chat (`backend/chainguard/llm/assistant.py`,
     `POST /api/assistant/chat`, NDJSON stream). Its tools: list scans, scan summary,
     package details, **package history across all scans**, **live
     `check_package`** (download, analyse, review, look up CVEs), vulnerabilities,
     model card, **server logs** (in-memory ring buffer) and scan status.
   - Fixed along the way: single-package scans of `latest` now resolve to the
     real version before CVE matching (`requests@latest` previously showed 6 bogus
     vulnerabilities).
   - Tests force the AI layer off (`backend/tests/conftest.py`), so a real key in
     `.env` never causes network calls or test failures.
5. **"Known malware" scan mode** (`/api/samples`, `/api/samples/scan`). It analyses the
   898 real malware samples in the local vault from the dashboard.
   `atlasctf-21-prod-19` shows the credential-exfiltration tracer on real malware
   (`/etc/passwd` read → `requests.post`). These samples are in the training set,
   so this is a demo of evidence, not of accuracy.
6. **External benchmark** (`5fb8ee8`, `215f623`, `docs/BENCHMARK.md`). Guo et al.,
   "How Effective Are NPM Malicious Package Detectors?" (ASE 2026), DOI
   10.6084/m9.figshare.31869370, CC BY 4.0. 13,436 packages were analysed.
7. **Research on existing models.** There is no strong ML model that can be
   downloaded and has been independently validated, except SAP's cross-language
   XGBoost (Apache-2.0, repo archived May 2026, 0.883 on the benchmark). MLPro ships
   a model but has no metrics. Amalfi withheld its models. Cerebro, MalPacDetector and
   MalGuard are papers without released weights. The best open tool is GuardDog
   (rules + taint, 0.924). Industry (Socket, Phylum/Veracode, ReversingLabs) layers
   static rules, ML and LLM review; nobody relies on a single ML model.
8. **Model experiments and combined training** (`51a0218`, `cd0d1fb`). See §3.

---

## 3. Model numbers: what is true and how to quote it

**Off the shelf** (the model trained only on our corpus, never on benchmark data). This
is the only fair comparison with other tools:

| Detector | Precision | Recall | F1 |
|---|---|---|---|
| GuardDog | 0.954 | 0.895 | 0.924 |
| **ChainGuard** | 0.918 | 0.854 | **0.885** |
| SAP XGBoost | 0.952 | 0.822 | 0.883 |
| SocketAI (LLM) | 0.982 | 0.436 | 0.604 |

**Deployed model** (our corpus + benchmark). Grouped 5-fold CV; groups merge
package versions **and** identical feature vectors, because benchmark malware
contains campaigns re-published under random names (6,546 packages collapse into 2,741 groups):

| Evaluation | F1 |
|---|---|
| Combined overall | 0.959 (P 0.980, R 0.939) |
| Benchmark packages | **0.963** |
| Our corpus | 0.931 (was 0.950 with the previous model) |
| 660 held-out real-app packages | 0 malicious, 9 suspicious flags |
| Real malware samples `captcha-py`, `atlasctf-21-prod-19` | 1.000, 0.999 |

**Rules:**
- Compare against other tools only with **0.885**. 0.963 is cross-validated with
  benchmark data in training.
- **Never quote ~0.98**, which is what `scripts/benchmark_guo.py score` prints for
  the deployed model: it has already seen those packages.
- Leakage check: only 33 benchmark package names overlap our corpus; excluding them
  gives 0.884.
- Each dataset alone generalises poorly to the other (ours → benchmark 0.885;
  benchmark → our npm corpus 0.741). That is why the deployed model uses both.
- SAP features alone reach 0.972 under benchmark-only CV, and adding them to ours gives
  0.976 (about 1 point). They are not used in production because SAP's extractor is
  file-based.

**Known demo false positive:** `requests@2.19.0` scores 0.481 (suspicious) because
`setup.py` calls `os.system` (the maintainers' publish command) and `utils.py` reads
`.netrc`. GPT keeps it at suspicious/medium and asks for `setup.py:39` to be verified.

---

## 4. Running it

Requires Python 3.12 and Node 24 (versions used here).

```bash
python -m venv .venv
```

```bash
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

```bash
.venv\Scripts\python.exe -m pip install -e .
```

```bash
cd frontend && npm install
```

- API: `.venv\Scripts\python.exe -m uvicorn chainguard.api.app:app --port 8000`
- Dashboard: `node node_modules/vite/bin/vite.js` from `frontend/` (the dev server proxies `/api` to 8000)
- `.env` in the repo root (gitignored): `OPENAI_API_KEY=sk-...`, and optionally
  `CHAINGUARD_LLM_MODEL` and `CHAINGUARD_AI_REVIEW_MAX_PACKAGES` (see `.env.example`).
  **On Windows, Notepad may save it as `.env.txt`.** That name is not read and not
  gitignored.
- Restart the API after changing `.env` or the model.
- Tests: `PYTHONPATH=backend .venv/Scripts/python.exe -m pytest backend/tests -q`

**Demo, as verified tonight:**
- Project scan of `demo\vulnerable-app`: 92 advisories → 3 reachable, with the
  `yaml.load` call path.
- Known malware `captcha-py` or `atlasctf-21-prod-19`: malicious 1.0, AI review agrees.
- Ask AI, for example: "What happened to fsevents in my scans?" or "Can I use axios@0.21.1?"

---

## 5. Key files added

| File | Purpose |
|---|---|
| `backend/chainguard/llm/review.py` | GPT review of flagged packages (hybrid verdict) |
| `backend/chainguard/llm/assistant.py` | Consultant tools, log buffer, OpenAI tool-use loop |
| `frontend/src/components/AssistantPanel.jsx` | Chat panel |
| `frontend/src/components/ui/*` | 21st.dev / Magic UI components (JSX, Tailwind v3) |
| `scripts/augment_benign.py` | Real dependency-tree benign augmentation + held-out FP test |
| `scripts/evaluate_realworld.py`, `scripts/experiment_features.py` | False-positive investigation |
| `scripts/benchmark_guo.py` | Benchmark featurize / score (in-memory, never extracts malware) |
| `scripts/experiment_benchmark_models.py` | SAP vs ChainGuard vs GuardDog feature experiments |
| `scripts/train_combined.py` | Builds `features_combined.csv` with deduplicated grouped CV |
| `data/benchmarks/*` | Malware-free derived benchmark data (features, labels, other tools' verdicts, results) |
| `docs/BENCHMARK.md` | Full benchmark write-up and safety rules |

To retrain the deployed model from scratch you need `data/corpus/features_augmented.csv`,
which is gitignored and built by `build_dataset.py` + `augment_benign.py`. Then:

```bash
.venv\Scripts\python.exe scripts/train_combined.py
```

```bash
.venv\Scripts\python.exe scripts/train_model.py --matrix data/corpus/features_combined.csv
```

---

## 6. Safety notes

- **`C:\Benchmarks` on the original laptop (7.5 GB)** holds `NPMStudy_full.zip`, which
  contains **6,547 live npm malware packages**, plus 6,890 benign tarballs and SAP
  files. Nothing was extracted or executed. It is no longer needed (all features are
  extracted and committed) and **should be deleted**. Do not extract it, open files
  from it, or run `npm` or `node` there.
- Never commit the raw benchmark or vault samples (GitHub policy, LFS quota, and
  teammates' machines). Only derived numbers are in the repo.
- SAP's `.pkl` models were inspected with `pickletools` before loading (they reference
  only XGBoost/NumPy/joblib). Inspect any third-party pickle the same way.
- Local-only backups not in git: `data/models/classifier.pre-augment.joblib`,
  `classifier.augmented-2450.joblib` and their `model_card.*.json`.

---

## 7. Open items / next steps

1. **Update stale docs**: `README.md`, `PROGRESS.md`, `docs/MODEL_CARD.md` (use §3 numbers and rules).
2. **Delete `C:\Benchmarks`** (see §6).
3. GPT clearing a false positive was only tested against a mocked client, not the live API.
4. npm reachability is still import-level only (`assumed_reachable`); Python has full call graphs.
5. The credential-exfiltration tracer is Python-only and not surfaced in the CLI or HTML report
   (the dashboard shows it). Carried over from the previous handoff.
6. Optional: port SAP's feature extractor to in-memory for about +1 F1 point.
7. Optional: a time-based split (the benchmark has malware timestamps only) to test
   robustness to new attack styles, which the paper names as the main ML weakness.
8. Model files are stored in git directly (`classifier.joblib`, ~MBs). Revisit if they grow.
