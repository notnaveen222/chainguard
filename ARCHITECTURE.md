# ChainGuard — System Architecture

**Project title:** AI-Powered Software Supply Chain Security: Malicious Package
Detection and Vulnerability Reachability Analysis

**Document status:** living document — updated as the system is built.
See [BUILD_LOG.md](BUILD_LOG.md) for the chronological record of decisions.

---

## 1. Problem statement

Modern applications are assembled, not written. A typical Node.js project pulls
in 800–1500 transitive packages; a Python project 200–400. Two distinct classes
of risk follow from that:

1. **Malicious packages.** An attacker publishes a package that is *deliberately*
   hostile — typosquatting a popular name (`reqeusts` for `requests`), hijacking
   an abandoned maintainer account, or slipping a payload into a minor version
   bump. The payload usually runs at *install* time (npm `postinstall`, Python
   `setup.py`) and exfiltrates environment variables, SSH keys, or cloud
   credentials. Signature-based scanning fails here because every sample is new.

2. **Known vulnerabilities (CVEs).** Dependencies accumulate published
   advisories. A real project routinely reports 150–300 CVEs. Security teams
   cannot triage that volume, so they triage nothing. This is *alert fatigue*,
   and it is the reason most known-vulnerable dependencies stay unpatched.

ChainGuard addresses both, and critically, addresses the **second problem's real
cause**: most reported CVEs are irrelevant to the specific application, because
the vulnerable *function* is never actually invoked. Reporting a CVE without
establishing reachability produces noise. Establishing reachability turns 300
findings into ~15 that genuinely matter.

### 1.1 What makes this "AI-powered"

Two independent mechanisms, deliberately separated so that neither is a black box:

| Mechanism | Role | Why not the other one |
|---|---|---|
| Supervised ML classifier (gradient-boosted trees over static-analysis features) | Decides *is this package malicious?* | Generalises to unseen malware; produces measurable precision/recall; runs offline and free |
| LLM layer (Claude, optional) | Explains *why* a flagged package is suspicious, in natural language | Cannot be evaluated with a confusion matrix; needs network + API key; unsuitable as the primary detector |

The classifier is the system of record. The LLM is a presentation layer over its
output and is **disabled by default** — the system is fully functional without it.
This split is intentional: a detector you cannot measure is not a detector.

---

## 2. High-level architecture

```
                         ┌──────────────────────────────┐
                         │   React + Tailwind Dashboard │
                         │   (Vite SPA, port 5173)      │
                         └───────────────┬──────────────┘
                                         │  REST / JSON
                         ┌───────────────▼──────────────┐
                         │      FastAPI application     │
                         │      (uvicorn, port 8000)    │
                         │  scan orchestration + jobs   │
                         └───────────────┬──────────────┘
                                         │
        ┌────────────────────────────────┼────────────────────────────────┐
        │                                │                                │
┌───────▼────────┐            ┌──────────▼─────────┐          ┌───────────▼────────┐
│  ACQUISITION   │            │   DETECTION        │          │  REACHABILITY      │
│                │            │                    │          │                    │
│ npm registry   │            │ static analysers   │          │ OSV.dev advisories │
│ PyPI JSON API  │───────────▶│ feature extractor  │          │ advisory symbol    │
│ manifest parse │  package   │ ML classifier      │          │   extraction       │
│ dep-tree solve │  contents  │ signal evidence    │          │ AST call graph     │
└───────┬────────┘            └──────────┬─────────┘          │ import resolution  │
        │                                │                    │ path proof         │
        │                                │                    └───────────┬────────┘
        │                                │                                │
        └────────────────────────────────┼────────────────────────────────┘
                                         │
                         ┌───────────────▼──────────────┐
                         │   Risk aggregation + report  │
                         │   SQLite persistence         │
                         │   JSON / HTML / PDF export   │
                         └──────────────────────────────┘
```

### 2.1 Layer responsibilities

**Acquisition** — turns "a project" into "a set of package source trees".
Parses `package.json` / `requirements.txt`, resolves the transitive dependency
graph against the live registries, downloads distributions, and unpacks them
**in memory** (tarballs are never extracted to disk in runnable form).

**Detection** — the malicious-package pipeline. Each package's files are run
through language-specific static analysers that emit a fixed-length numeric
feature vector *plus* a list of human-readable evidence signals. The vector goes
to the classifier; the signals go to the report so a human can audit the verdict.

**Reachability** — the CVE pipeline. Queries OSV.dev for advisories affecting each
resolved package version, extracts the vulnerable symbol(s) from the advisory,
then determines whether the application's own code can actually reach that
symbol. Produces a call path as proof.

**Reporting** — merges both pipelines into a single risk model and renders it.

---

## 3. Component design

### 3.1 Acquisition layer (`chainguard/registry/`)

| Module | Responsibility |
|---|---|
| `http.py` | Shared `httpx` client: connection pooling, retry with exponential backoff (`tenacity`), on-disk response cache keyed by URL+body hash |
| `npm.py` | npm registry client — packument fetch, version resolution against semver ranges, tarball download |
| `pypi.py` | PyPI JSON API client — release metadata, sdist/wheel selection and download |
| `archive.py` | In-memory extraction of `.tar.gz`, `.tgz`, `.zip`, `.whl` with zip-slip and decompression-bomb guards |
| `manifest.py` | Parsers for `package.json`, `package-lock.json`, `requirements.txt`, `pyproject.toml` |
| `resolver.py` | Transitive dependency graph construction with cycle detection and depth limits |

**Caching is mandatory, not an optimisation.** A single scan of a real project
issues hundreds of registry requests. Without a cache, a demo would be rate-limited
and slow. The cache is content-addressed under `data/cache/` and is safe to delete.

**Decompression-bomb guard:** archives are rejected if the uncompressed size
exceeds a configured ceiling or the compression ratio is implausible. A malicious
package that ships a 10 GB zip bomb must not take the scanner down — the scanner
is itself an attack surface, since by definition it processes hostile input.

### 3.2 Static analysis (`chainguard/analysis/`)

Two analysers share a common interface and emit a common feature schema.

```
FileAnalysis  ──┐
                ├──▶  PackageFeatures (fixed-length vector, versioned schema)
FileAnalysis  ──┘  +  list[Signal]  (name, severity, evidence, file, line)
```

**Python analyser** (`python_ast.py`) — uses the stdlib `ast` module. Detects:
- code executing at import time or in `setup.py` (`setup()` side effects)
- `eval` / `exec` / `compile` / `__import__` dynamic execution
- `subprocess`, `os.system`, `os.popen` process spawning
- `socket`, `urllib`, `requests`, `http.client` network egress
- environment and credential-file access (`os.environ`, `~/.ssh`, `~/.aws`)
- base64/hex/rot13 decode chains feeding into an execution sink

**JavaScript analyser** (`js_ast.py`) — uses `esprima` (pure-Python, no Node
dependency, so the backend has a single runtime). Detects the JS equivalents plus:
- `package.json` lifecycle hooks: `preinstall`, `install`, `postinstall`
- `child_process.exec/spawn`, `require('https').request`
- minification / obfuscation via identifier-length and entropy heuristics
- string-array-with-decoder-function patterns (the signature of `obfuscator.io`)

**Metadata analyser** (`metadata.py`) — ecosystem-agnostic:
- **typosquat distance**: Damerau-Levenshtein against a bundled list of the top
  N packages, with keyboard-adjacency weighting; also detects scope confusion
  and homoglyph substitution
- package age vs. download count anomalies, maintainer count, repository absence

**Why hand-engineered features and not a neural model over raw source?**
Three reasons, all defensible to an examiner: (a) the dataset is on the order of
thousands of samples, not millions — deep models overfit at that scale;
(b) tree ensembles give per-feature importances, so every verdict is explainable;
(c) it runs on a laptop with no GPU, which matters for a live demo.

### 3.3 Machine learning (`chainguard/ml/`)

- **Model:** gradient-boosted trees, with RandomForest as a benchmark baseline.
- **Split:** stratified, and **grouped by package family** so that near-duplicate
  samples from the same campaign cannot appear in both train and test. Without
  grouping, accuracy is inflated and meaningless.
- **Calibration:** probabilities are calibrated so the reported score is
  interpretable as a confidence, not an arbitrary number.
- **Class imbalance:** malicious packages are rare. Evaluation therefore leads with
  precision/recall/PR-AUC, not accuracy — a model predicting "benign" always would
  score 97% accuracy and be worthless.
- **Artifacts:** confusion matrix, ROC curve, PR curve, feature-importance chart
  written to `data/models/` as PNGs for direct use in the report and slides.
- **Model card** (`docs/MODEL_CARD.md`) records training data provenance, metrics,
  and known limitations.

### 3.4 Reachability analysis (`chainguard/vulns/`)

This is the technical core of the second half of the project.

```
  OSV advisory                  Application source
       │                               │
       ▼                               ▼
 extract vulnerable            build call graph
 symbols (functions,           (AST, per module)
 classes, modules)                     │
       │                               ▼
       │                     resolve imports ──▶ dependency
       │                                          module map
       └──────────────┬────────────────────────────┘
                      ▼
            graph reachability search
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
  REACHABLE                    NOT REACHABLE
  + proof call path            + reason (symbol never imported /
  app.py:42 → utils.py:7         never called / dead branch)
    → yaml.load
```

**Python (deep).** Build a call graph over the application's own modules, resolve
`import` statements to installed dependency modules, then search for a path from
any application entry point to a vulnerable symbol. Emits the concrete call path
as proof — this is the artifact that makes the analysis credible in a demo.

**npm (import-level).** Full JS call-graph construction is out of scope for this
timeline (dynamic `require`, bundlers, and monkey-patching make it a research
problem in itself). Instead ChainGuard reports whether the vulnerable module is
imported at all, and through which dependency path. This is a deliberate,
documented scope boundary rather than an omission.

**Honest limitations** (stated up front, and in the report):
- Dynamic dispatch, reflection, and `getattr`-style indirection are not resolved
- Conditional imports are treated as reachable (fail-safe: over-report, never
  under-report — a missed vulnerability is far worse than a false alarm)
- "Unreachable" means *not statically reachable*, which is a strictly weaker claim
  than *not exploitable*

Fail-safe direction is the important design decision here: when the analysis is
uncertain, it must resolve toward **reachable**.

### 3.5 Risk aggregation

A single package's risk combines three independent axes, kept separate in the
data model and only merged for display ordering:

- **Malice score** — classifier probability, 0–1
- **Vulnerability load** — CVEs weighted by CVSS *and* by reachability
- **Trust signals** — package age, maintainer count, repository presence

They are never collapsed into one number in storage. Merging them early destroys
the ability to explain a finding, which is the whole point of the system.

---

## 4. Data model

Persisted to SQLite (`data/chainguard.db`) via SQLAlchemy, as a single `scans`
table: queryable summary columns (target, ecosystem, status, timestamp, package
counts, reachable/unreachable vulnerability counts, detector used) plus the full
scan result stored as JSON.

Five normalised tables (`Scan`, `PackageResult`, `Signal`, `Vulnerability`,
`ReachabilityResult`) were the original plan and were rejected during
implementation. A scan result is a deeply nested document that is always read
whole — packages contain signals, vulnerabilities contain call paths — so
normalising it would mean a five-way join on every read to reconstruct exactly
what was written. The summary columns already serve every listing and filtering
query the dashboard makes.

SQLite is chosen for zero-configuration demo reliability. Nothing prevents
swapping in PostgreSQL; the SQLAlchemy layer is dialect-agnostic and JSON columns
are supported by both.

### 4.1 Distribution names vs. import names

A separate resolution layer (`vulns/import_names.py`) maps PyPI *distribution*
names to the *module* names they provide — `pyyaml` → `yaml`, `pillow` → `PIL`.
Advisories are published against distribution names while source code imports
module names, and conflating the two caused reachability to report imported
packages as unreachable (BUILD_LOG D-040). The mapping is derived from each
downloaded archive's `top_level.txt` or directory layout, with a curated table as
fallback.

---

## 5. Security posture of the scanner itself

A tool that ingests malicious packages is itself a target. Controls applied:

| Threat | Control |
|---|---|
| Sample execution | Packages are **never** installed or executed. No `pip install`, no `npm install`, no `setup.py` invocation anywhere in the codebase. Analysis is purely static. |
| Malware on disk | Training samples are stored **encoded at rest** and decoded only into memory. No plaintext malicious source is ever written to disk. |
| Zip-slip / path traversal | Archive member paths are normalised and rejected if they escape the extraction root. |
| Decompression bombs | Uncompressed-size ceiling and compression-ratio limits. |
| Parser DoS | Per-file size caps, per-package file-count caps, and analysis timeouts. |
| Accidental commit of samples | `data/quarantine/` is gitignored; a README in that directory documents the contents. |
| Secret leakage | API keys read from environment only; `.env` gitignored; `.env.example` documents required names without values. |

---

## 6. Technology choices and rationale

| Choice | Alternative considered | Why chosen |
|---|---|---|
| Python 3.10 backend | Node/TypeScript | The ML and AST-analysis ecosystem is Python-native; `ast` in stdlib is exactly the tool the reachability engine needs |
| FastAPI | Flask, Django | Async (many concurrent registry calls), automatic OpenAPI docs, Pydantic validation for free |
| `esprima` (pure Python) | Node subprocess + `acorn`, `tree-sitter` | Keeps the backend to a single runtime; no Node process management, no native build step on Windows |
| scikit-learn GBT | PyTorch/transformer | Dataset size suits trees; per-feature importances give explainability; CPU-only |
| SQLite | PostgreSQL | Zero setup — a demo must never fail because a service is not running |
| React + Vite + Tailwind | Streamlit | Produces a product-grade UI; Vite's dev server is fast; Tailwind avoids hand-written CSS |
| OSV.dev | NVD directly, GitHub Advisory | Single API covering both npm and PyPI, well-structured version ranges, no API key required |

---

## 7. Repository layout

```
college-project/
├── ARCHITECTURE.md          # this document
├── BUILD_LOG.md             # chronological decision record
├── PROGRESS.md              # resumable build state
├── README.md                # setup + demo instructions
├── requirements.txt
├── backend/
│   ├── chainguard/
│   │   ├── config.py        # settings, env, feature flags
│   │   ├── models/          # Pydantic schemas + SQLAlchemy tables
│   │   ├── registry/        # npm, PyPI, archives, manifests, resolver
│   │   ├── analysis/        # static analysers + feature extraction
│   │   ├── dataset/         # corpus building, encoded quarantine store
│   │   ├── ml/              # training, evaluation, inference
│   │   ├── vulns/           # OSV client, reachability engine
│   │   ├── llm/             # optional Claude explanation layer
│   │   ├── reporting/       # risk aggregation, HTML/PDF export
│   │   ├── api/             # FastAPI routes
│   │   └── cli.py           # command-line entry point
│   └── tests/
├── frontend/                # Vite + React + Tailwind SPA
├── data/                    # cache, corpus, quarantine, models (gitignored)
├── docs/                    # model card, dataset notes, diagrams
└── scripts/                 # dataset build, training, demo setup
```

---

## 8. Evaluation plan

The project is assessed on measurable outcomes, not on features shipped:

1. **Detection quality** — precision, recall, F1, PR-AUC on a grouped held-out
   test set; confusion matrix; comparison against a rules-only baseline to show
   the ML layer earns its place.
2. **Reachability reduction** — the headline metric: total CVEs reported vs.
   CVEs proven reachable, on a set of real sample projects. Expected reduction is
   large, and quantifying it is the project's central empirical claim.
3. **Performance** — end-to-end scan latency vs. dependency count.
4. **Ablation** — detection metrics with feature groups removed, showing which
   signal families actually carry the model.
