# ChainGuard

**AI-Powered Software Supply Chain Security: Malicious Package Detection and
Vulnerability Reachability Analysis**

ChainGuard scans a project's dependency tree and answers two questions that
existing tooling answers badly:

1. **Is any of this deliberately malicious?** A machine-learning classifier over
   58 static-analysis features detects typosquats, install-time payloads,
   obfuscated code and credential exfiltration — including in packages it has
   never seen.
2. **Which of the reported CVEs actually matter?** Rather than dumping every
   advisory on a developer, ChainGuard performs **reachability analysis**: it
   builds a call graph of the application, determines whether each vulnerable
   function is genuinely invoked, and shows the call path as proof.

On the bundled demo project, the second question turns **92 reported advisories
into 3 that are actually reachable** — with a proof path for each:

```
app → app.main → app.bootstrap → config.load_settings → yaml.load
```

That reduction is the project's central claim. Most vulnerabilities in a
dependency tree cannot be reached from the application, and reporting them
without that distinction is why known-vulnerable dependencies stay unpatched:
the signal drowns in noise.

## Results

Detection, from grouped 5-fold cross-validation over **1,797 real packages**
(898 malicious from a published research dataset, 899 downloaded live):

| Metric | Model | Rules baseline |
|---|---|---|
| Precision | **0.962** | 0.842 |
| Recall | **0.939** | 0.428 |
| F1 | **0.950** | 0.565 |
| PR-AUC | **0.986** | 0.719 |

Every figure is out-of-fold, with splits grouped by package name so no version of
a package can appear on both sides. Full detail, including six stated
limitations, is in [docs/MODEL_CARD.md](docs/MODEL_CARD.md).

---

## Quick start

Requires Python 3.10+ and Node 18+ (Node is for the dashboard only — the backend
has no Node dependency).

```bash
python -m venv .venv
```

```bash
.venv\Scripts\activate
```

```bash
pip install -r requirements.txt
```

Run the test suite — it is fully offline and takes under a second:

```bash
python -m pytest backend/tests -q
```

Scan the demo project from the command line:

```bash
python -m chainguard scan-project demo\vulnerable-app
```

### Web dashboard

Start everything with one command:

```bash
powershell -ExecutionPolicy Bypass -File scripts\start.ps1
```

Or start the two services yourself. The API:

```bash
python -m uvicorn chainguard.api.app:app --port 8000
```

Then the dashboard, in a second terminal:

```bash
cd frontend && npm install && npm run dev
```

Open <http://localhost:5173>. Interactive API docs are at
<http://localhost:8000/docs>.

### Training the classifier (optional)

ChainGuard runs without a trained model, falling back to a rules baseline and
saying so in every result. To train the real classifier:

```bash
python scripts/build_dataset.py --malicious 450 --benign 450
```

```bash
python scripts/train_model.py
```

The dataset build downloads ~1,800 packages and takes roughly an hour. See
[docs/DATASET.md](docs/DATASET.md).

---

## How it works

```
  manifest ──▶ resolve dependency tree ──▶ download packages (in memory)
                                                    │
                        ┌───────────────────────────┴───────────────────────┐
                        ▼                                                   ▼
             STATIC ANALYSIS                                    OSV.dev ADVISORIES
      Python AST · JavaScript AST                          CVSS · fixed versions
      install hooks · typosquatting                        vulnerable symbols
                        │                                                   │
                        ▼                                                   ▼
             58-feature vector                              REACHABILITY ANALYSIS
                        │                                   call graph of your code
                        ▼                                   ↓          ↓
              ML CLASSIFIER                            REACHABLE   not reachable
        malice score + evidence                        + proof      + reason
                        │                                                   │
                        └───────────────────┬───────────────────────────────┘
                                            ▼
                              risk report · remediation plan
```

Detection and reachability are independent: a failure in one does not take out
the other.

---

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design, component rationale, technology choices, evaluation plan |
| [BUILD_LOG.md](BUILD_LOG.md) | Every design decision, the alternatives rejected, and the bugs found along the way |
| [docs/MODEL_CARD.md](docs/MODEL_CARD.md) | Classifier metrics, ablation, and what the model cannot do |
| [docs/DATASET.md](docs/DATASET.md) | Training data provenance, label-leakage prevention, known limitations |
| [docs/DEMO.md](docs/DEMO.md) | Ten-minute walkthrough for a review panel |
| [PROGRESS.md](PROGRESS.md) | Build state |

---

## What this does *not* do

Stated plainly, because a security tool that overstates its certainty is worse
than one that admits a gap.

- **npm reachability is import-level only.** ChainGuard reports whether a
  vulnerable package is imported and by which files, but does not verify symbol
  use for JavaScript. Full JS call-graph construction across dynamic `require`,
  bundlers and monkey-patching is a research problem in its own right.
- **"Not statically reachable" is weaker than "not exploitable."** The analysis
  does not resolve dynamic dispatch, `getattr` indirection, reflection, or calls
  made from templates and configuration.
- **Uncertainty always resolves to *reachable*.** A false "reachable" costs an
  engineer ten minutes; a false "unreachable" hides a real vulnerability. The two
  errors are not symmetric, so every ambiguous case is reported.
- **Vulnerable-symbol data is incomplete.** npm and PyPI advisories rarely carry
  structured symbol information. Symbols come from advisory data, a curated table
  of ~35 packages, or parsing advisory prose — and every finding reports which,
  because a verdict is only as good as the symbol list behind it.

---

## Security notice

ChainGuard analyses hostile input by design, and its training data contains real
malicious packages. Two invariants hold throughout:

- **Nothing analysed is ever executed.** No `pip install`, no `npm install`, no
  `setup.py` invocation, no `eval` of package content. All analysis is static
  parsing of source text.
- **Malicious samples are encoded at rest.** Training samples under
  `data/quarantine/` are never written to disk in runnable form and are decoded
  into memory only — so no antivirus exclusion is required and no security
  setting on the host was changed. See
  [`data/quarantine/README.md`](data/quarantine/README.md).

The scanner is itself an attack surface, so ingestion is bounded at every step:
archive size, compression ratio, member count, per-file size, AST parse size, and
per-package analysis time. Path traversal, symlinks and absolute paths are
rejected during extraction. These are security controls, not performance tuning —
see `backend/chainguard/config.py`.

---

## Repository layout

```
backend/chainguard/
  analysis/    static analysers, signal catalogue, feature extraction, typosquatting
  registry/    npm + PyPI clients, semver, manifests, archives, dependency resolver
  vulns/       OSV client, reachability engine, import-name resolution
  dataset/     encoded sample vault, corpus construction
  ml/          training, evaluation, inference
  api/         FastAPI service and background jobs
  scanner.py   scan orchestration
  cli.py       command-line interface
frontend/      React + Vite + Tailwind dashboard
demo/          sample vulnerable project for the reachability demonstration
scripts/       dataset build, model training, popular-package list generation
docs/          dataset notes, demo script, model card
```
