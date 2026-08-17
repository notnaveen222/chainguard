# ChainGuard — Build Log

A chronological record of what was built and **why**, including options that were
rejected. Written as the system is constructed, not reconstructed afterwards.

Companion documents: [ARCHITECTURE.md](ARCHITECTURE.md) (system design),
[PROGRESS.md](PROGRESS.md) (resumable build state).

---

## 2026-08-17 — Pre-build scoping

Decisions taken before any code was written.

### D-001 — Project scope: full working system

**Decision:** Build a complete end-to-end system (analysis engine, trained model,
API, dashboard, evaluation) rather than a design-only submission or a thin
prototype.

**Rationale:** Review 1 is a panel review. A working demo answers "does it
actually do anything?" in a way that slides cannot. Building the full system now
also means later reviews become refinement rather than fresh construction.

### D-002 — Stack: Python + FastAPI + React

**Decision:** Python 3.10 backend (FastAPI), React + Vite + Tailwind frontend.

**Rejected — Streamlit:** faster to build, but produces something that reads as a
script with widgets rather than a product. The UI is a substantial part of what a
panel sees.

**Rejected — MERN:** the ML and AST tooling this project depends on is
Python-native. Doing static analysis and model training in Node would mean
fighting the ecosystem for no gain.

### D-003 — AI approach: local classifier primary, LLM secondary and optional

**Decision:** A supervised classifier over static-analysis features is the system
of record. A Claude-based natural-language explanation layer sits on top, behind a
config flag, **disabled by default**.

**Rationale:** An examiner will ask "how do you know it works?". That question has
an answer for a classifier (precision, recall, PR-AUC, confusion matrix) and no
good answer for an LLM prompt. Equally, the demo must not depend on a working API
key or college wifi. The LLM adds explanation quality when available and costs
nothing when absent.

**Rejected — LLM-first:** impressive output, but unmeasurable and demo-fragile.

### D-004 — Ecosystems: npm + PyPI

**Decision:** Support both `package.json` and `requirements.txt`.

**Rationale:** OSV.dev covers both under one API, so the vulnerability half costs
little extra. Two ecosystems also demonstrate that the design generalises rather
than being hard-coded to one registry.

### D-005 — Training data: real research samples, encoded at rest

**Decision:** Use published academic malicious-package datasets, stored **encoded**
on disk and decoded only in memory during feature extraction.

**Considered — plain files + Windows Defender exclusion:** simplest pipeline, but
requires weakening antivirus on a personal laptop, and creates a scanning blind
spot. Rejected.

**Considered — plain files, no exclusion:** Defender would quarantine samples
mid-build, silently corrupting the dataset during an unattended overnight run.
Rejected — this was the deciding practical factor, more than the security concern.

**Considered — synthetic samples only:** zero risk, but weakens the answer to
"is this trained on real-world data?". Rejected as the primary source; synthetic
samples are still generated to augment thin attack categories.

**Consequence:** an encode/decode storage layer is required (`dataset/vault.py`).
Samples are never executed anywhere in the codebase, under any code path.

### D-006 — Title refinement: *reachability*, not remediation

The confirmed project title is **"…Malicious Package Detection and Vulnerability
Reachability Analysis"**. This is a materially stronger second half than
remediation advice: reachability answers *which* of the reported CVEs actually
matter to this specific application, which is the real problem in dependency
security. Remediation planning is retained as a secondary output, since the
upgrade data falls out of the same advisory queries.

**Scope boundary set deliberately:** deep AST-based call-graph reachability for
Python; import-level reachability for npm. Full JS call-graph construction
(dynamic `require`, bundler output, monkey-patching) is a research problem and is
documented as out of scope rather than attempted and left broken.

### D-007 — Fail-safe direction for reachability

**Decision:** When reachability analysis is uncertain — conditional imports,
dynamic dispatch, unresolved indirection — the result resolves to **reachable**.

**Rationale:** The two error directions are not symmetric. A false "reachable"
costs an engineer ten minutes of review. A false "unreachable" hides a real
exploitable vulnerability and actively causes harm. Every ambiguous case must
therefore resolve toward reporting.

### D-008 — Local git only

Repository is initialised locally with no remote. Nothing is pushed anywhere.
Commits serve as per-phase checkpoints so there is always a known-good state.

---

## 2026-08-17 — Phase 0: Scaffold

**Built:** directory structure, local git repo, Python virtual environment,
pinned `requirements.txt`, `.gitignore`, and the three living documents
(`ARCHITECTURE.md`, `BUILD_LOG.md`, `PROGRESS.md`).

### D-009 — Dependency pinning to exact versions

**Decision:** Pin every dependency to an exact version rather than a range.

**Rationale:** This project will be demonstrated months after it is built. A
transitive upgrade breaking the build the night before a review is a real and
common failure. Exact pins make the environment reproducible.

### D-010 — `esprima` for JavaScript parsing

**Decision:** Parse JavaScript with `esprima` (pure Python) rather than shelling
out to Node with `acorn`, or using `tree-sitter`.

**Rationale:** Keeps the backend to a single runtime. No Node subprocess
management, no native compilation step on Windows — `tree-sitter` in particular
needs a C toolchain, which is a poor dependency for a machine that must reliably
build unattended. `esprima` is slower and only supports ES5/ES6 syntax fully, but
the analyser is looking for structural patterns (calls into dangerous sinks,
obfuscation signatures) rather than needing complete modern-syntax fidelity, and
it degrades to regex-based scanning when a parse fails.

### D-011 — SQLite for persistence

**Decision:** SQLite via SQLAlchemy.

**Rationale:** A demo must not fail because a database service is not running.
The SQLAlchemy layer keeps the door open for PostgreSQL without rewriting queries.

---

## 2026-08-17 — Phase 1: Registry layer

**Built:** shared cached HTTP client, safe in-memory archive extraction, npm and
PyPI clients, an npm semver implementation, manifest/lockfile parsers, and the
breadth-first transitive dependency resolver.

**Verified against live registries:** `express@^4.18.0` resolved to 4.22.2 and
expanded to a 49-package transitive graph; `requests` fetched as an sdist with
`setup.py` present; `esbuild`'s `postinstall` hook detected from metadata alone.

### D-012 — Hand-rolled semver rather than a library

**Decision:** Implement npm's version-range grammar directly (`semver.py`).

**Rationale:** The available Python semver packages implement the *specification*
but not npm's *range grammar* — `^`, `~`, `x` wildcards, hyphen ranges, and `||`
unions are npm inventions. ChainGuard needs exactly one operation ("given a range
and a published version list, pick what npm would install"), so a focused
implementation is smaller and more testable than bending a general library.
The 0.x caret rule (`^0.2.3` → `<0.3.0`, not `<1.0.0`) is implemented explicitly
because getting it wrong silently resolves the wrong version.

### D-013 — Full packuments, not the abbreviated form

**Decision:** Request npm's full registry document rather than
`application/vnd.npm.install-v1+json`.

**Rationale:** The abbreviated document reports `hasInstallScript` as a boolean.
ChainGuard needs the *script body* — the command text in `postinstall` is one of
the strongest malicious signals available, and a boolean throws it away. The
payload is larger, but responses are cached, so the cost is one download per
package rather than per scan.

### D-014 — Prefer sdists over wheels on PyPI

**Decision:** When both are published, download the source distribution.

**Rationale:** A wheel is a *built* artifact and has already discarded
`setup.py` — which is exactly the file a malicious PyPI package uses to execute
code at install time. Analysing only wheels would blind the detector to the most
common Python supply-chain attack vector. Wheels are used only as a fallback.

### D-015 — Archive extraction is a security boundary

**Decision:** Extraction enforces four independent ceilings (uncompressed size,
compression ratio, member count, per-file size) and drops unsafe members
(path traversal, absolute paths, symlinks, non-regular files).

**Rationale:** The scanner ingests deliberately hostile archives, so it is itself
an attack surface. A zip bomb or a symlink to `/etc/passwd` must degrade to a
*truncated result*, never to a crash or a traversal. Size accounting happens
before decompression, which is what makes the bomb guard real rather than
cosmetic. Truncation is recorded on the result so downstream consumers know the
analysis was partial rather than clean.

### D-016 — Lockfiles take precedence over manifests

**Decision:** When a lockfile is present, resolve from its pinned versions and do
not re-resolve ranges.

**Rationale:** A manifest declares ranges; a lockfile records what is actually
installed. Re-resolving `^4.17.0` today may pick a different version than the one
on the developer's disk, and reporting vulnerabilities for a version the user
does not have is a false result in both directions.

**Known limitation:** a flat lockfile does not preserve depth, so lockfile-derived
graphs record every package at depth 0. Depth-based risk weighting is therefore
weaker for lockfile scans — documented rather than silently wrong.

### D-017 — Breadth-first resolution

**Decision:** Walk the dependency graph breadth-first.

**Rationale:** BFS reaches each package by its shallowest path first, which is the
correct depth to keep for risk weighting — a direct dependency is more the
developer's problem than one buried five levels down. It also makes the package
ceiling meaningful: truncating a BFS drops the deepest, least relevant packages,
whereas truncating a DFS drops an arbitrary subtree.

### D-018 — Failures are isolated per package, never fatal

**Decision:** `gather()` returns exceptions in place rather than raising, and
unresolvable requirements are recorded in `graph.unresolved`.

**Rationale:** A scan of 500 packages will always contain something deleted,
yanked, or published with broken metadata. One bad package must not abort the
scan. Equally, silently dropping it would overstate coverage — so every failure
is surfaced in the result rather than swallowed.

---

## 2026-08-17 — Phase 2: Detection engine

**Built:** the signal catalogue (40 signal types across 10 categories), Python
and JavaScript AST analysers, shell analysis for npm lifecycle hooks, typosquat
detection, the 55-feature vector, and the orchestrating engine.

### D-019 — Signals carry evidence, not just a score

**Decision:** Every detection records its file, line, source snippet and a
human-readable explanation, and the same signal set drives both the feature
vector and the report.

**Rationale:** A malice score with nothing behind it is unauditable. An examiner
asking "why did it flag this?" needs a better answer than "the model said so".
This also makes the false-positive work below possible — without per-signal
attribution there is no way to find out *what* was wrong.

### D-020 — AST parsing rather than pattern matching

**Decision:** Parse both languages properly (`ast` for Python, `esprima` for JS)
rather than grepping for dangerous strings.

**Rationale:** A regex for `eval(` matches the word in a comment, a docstring, or
a variable named `evaluate`. An AST sees a genuine call node. More importantly it
resolves aliases: `import subprocess as sp` then `sp.run(...)` is invisible to
text search. Parsing is also safe — `ast.parse` builds a tree without executing
anything, which is what makes static analysis of hostile code possible at all.

**Degradation, not failure:** `esprima` covers ES5/ES6 and rejects newer syntax
and TypeScript. A parse failure falls back to text-level scanning and sets
`parse_failed`, so the feature vector reflects *reduced visibility* rather than
reporting a clean result it did not actually verify.

### D-021 — Composite signals are the precise ones

**Decision:** Per-file analysers record behaviour *flags*; a second pass derives
co-occurrence signals (`EXFIL_CREDENTIALS_TO_NETWORK`, `EXFIL_ON_INSTALL`,
`REVERSE_SHELL_PATTERN`) from them.

**Rationale:** Reading the environment is unremarkable. Making an HTTP request is
unremarkable. Doing both in one file is the shape of credential theft. No
individual detector can observe that composition.

**This is validated by measurement.** Across twelve real packages (express,
chalk, debug, commander, axios, webpack, requests, click, urllib3, flask, pyyaml,
rich), **not one** composite signal fired. On the synthetic malicious samples,
they fired immediately and dominated the score. Individual sinks are noisy;
composition is precise.

`EXFIL_ENV_TO_NETWORK` additionally requires a third corroborating behaviour
(host reconnaissance, or the file running at install time), because environment
access plus network is genuinely common in benign configuration-loading code.

### D-022 — Detector thresholds were corrected against real packages

The initial thresholds were set by intuition and were measurably wrong. Running
the engine over twelve popular real packages exposed systematic false positives,
each of which was traced and fixed:

| Problem found | Cause | Fix |
|---|---|---|
| `HIGH_ENTROPY_STRING` fired 19× in `urllib3`, 40× in `webpack` | entropy > 4.5 over any 100-char literal — real code is full of long high-entropy strings | require length ≥ 180, whitespace < 2%, encoded alphabet ≥ 92%, entropy > 4.8 |
| `CRYPTO_WALLET_ACCESS` fired on `urllib3` and `rich` | pattern included generic `private_key`/`mnemonic`, ubiquitous in TLS and crypto code | restricted to wallet-*specific* artefacts only |
| `ENV_BULK_HARVEST` fired on `express`, `debug`, `axios`, `webpack` | **bug** — the AST walk visits `process.env` as a sub-expression of every `process.env.FOO`, so named reads were counted as whole-environment reads | track which nodes are the base of a longer member chain; flag only genuinely standalone `process.env` |
| `SETUP_PY_SIDE_EFFECTS` fired 4× on `pyyaml` | flagged *any* module-level statement; real `setup.py` files legitimately contain import guards, version parsing and platform branches | flag only statements containing calls into a process/network/exec sink |
| `BASE64_BLOB` fired 5× in `axios`, 9× in `webpack` | 60-character minimum matched hashes, integrity digests and source-map fragments | raised to 120 characters |
| `CHARCODE_OBFUSCATION` fired on `axios`, `webpack` | single `String.fromCharCode` call — routine in parsers and encoders | require ≥ 5 occurrences in one file |
| `HEX_ESCAPE_HEAVY` fired on `pyyaml`, `rich` | raw count > 40 — unicode tables exceed that legitimately | density-based: escapes must exceed 15% of file content |

Signal weights were also lowered where measurement showed the original prior was
unjustifiable (`DYNAMIC_EVAL` 2.5→1.5, `SENSITIVE_PATH_ACCESS` 4.5→3.0,
`HOST_RECON` 1.8→1.0, and others). Each lowered weight carries an inline comment
naming the packages that motivated it, because a tuned constant with no evidence
attached is indistinguishable from a guess.

**Result:** real packages moved from 0.40–1.00 down to 0.00–0.41, while the
synthetic malicious samples stayed at 0.99 and 1.00.

### D-023 — `webpack` remains a baseline false positive, and that is the point

`webpack` still scores 1.00 on the rules baseline. It ships 688 files and
genuinely writes to system paths, spawns processes, reads the environment and
calls `eval` — every individual signal is a *true* observation.

This is not treated as a bug to be tuned away. It is the clearest possible
demonstration of why the ML layer exists: a weighted-sum baseline cannot learn
that these behaviours are unremarkable in a large, mature, widely-depended-upon
build tool but alarming in a three-file package published yesterday. Suppressing
it with a hand-tuned exception would hide exactly the phenomenon the evaluation
needs to measure.

### D-024 — A critical *signal* is not a malicious *verdict*

`requests` triggers a critical-severity `SENSITIVE_PATH_ACCESS` because it reads
`.netrc` — which it genuinely does, for authentication. The analyser is correct
to observe it and correct not to escalate: no network egress occurs in that file,
so no exfiltration composite fires, and the package scores 0.36.

Severity describes how alarming a behaviour is *in isolation*. Only the aggregate
score and the composites constitute a verdict. The test suite asserts on the
verdict, never on the presence of an individual signal.

### D-025 — Typosquat detection combines four mechanisms

Edit distance alone is insufficient. The implementation adds keyboard-adjacency
weighting (adjacent-key substitutions cost 0.6, not 1.0, so `reqeusts` ranks
closer to `requests` than an arbitrary edit), transposition at 0.6 (the single
most common typing error), homoglyph substitution, separator swaps, affix
addition/removal, and scope confusion. Names on the popular list are never
flagged against themselves, and names shorter than five characters are excluded
because at that length almost everything is within distance 2 of something.

The ground-truth list (614 npm + 518 PyPI names) is generated by
`scripts/build_popular_packages.py` and committed, so scans are reproducible and
work offline. Regenerating it changes detection behaviour, so it is a deliberate
versioned action rather than something done at scan time.

### D-026 — Feature schema is versioned and every column is nameable

**Decision:** 55 features in a fixed order, with `SCHEMA_VERSION` persisted
alongside the trained model, and no anonymous dimensions.

**Rationale:** A model trained on schema v1 fed a v2 vector produces confident
nonsense rather than an error, so the version is checked at inference. Every
feature maps to something explainable, which is what makes the
feature-importance chart meaningful. Counts are `log1p`-compressed so that large
legitimate libraries do not dominate the feature space purely by being large.

### D-027 — Vendored and test directories are excluded from analysis

`node_modules`, `test/`, `__pycache__`, `vendor/`, `examples/` and similar are
skipped. Analysing them attributes another project's behaviour to this package
and inflates every count — test fixtures in particular are full of deliberately
odd strings.

---

## 2026-08-17 — Phase 3: Dataset pipeline

**Built:** the encoded-at-rest sample vault, acquisition from the DataDog
malicious-package dataset and the live registries, and the feature-matrix builder.

### D-028 — Malicious sample source: DataDog dataset

**Decision:** Use `DataDog/malicious-software-packages-dataset` (Apache-2.0) as
the malicious corpus — 1,834 PyPI and 47,406 npm packages caught attacking users.

**Rationale:** Real, published, citable, and permissively licensed. Critically,
its samples ship as **password-encrypted ZIPs** (password `infected`), which is
the dataset's own convention for keeping malware inert. That property does the
job the custom encoding was designed for, so samples arrive already opaque and
are decrypted in memory only.

`lxyeternal/pypi_malregistry` was also reachable but is PyPI-only, unlicensed,
and stores samples as plain tarballs.

### D-029 — The vault is obfuscation, and says so

`dataset/vault.py` compresses and XORs every stored blob against a BLAKE2b
keystream. The key is a constant in the source file.

**This is explicitly not cryptography**, and the module docstring says so. The
threat model is "an antivirus scanner, or a careless double-click" — not an
attacker with disk access, who can also read the key. Describing it as encryption
would be a false claim about the guarantee.

The security property that actually matters does not depend on the encoding at
all: **no code path in this project executes a sample.** Analysis is static
parsing of source text.

### D-030 — One sample per package, deterministically selected

Multiple versions of one malicious package are near-identical. Letting them span
the train/test split would inflate every reported score. Selection is seeded, so
a rebuild reproduces the same dataset.

### D-031 — Benign corpus is real popular packages, not toy examples

**Decision:** Negative examples are genuine packages downloaded live from npm and
PyPI, sampled across the whole popular list.

**Rationale:** The classifier must separate malware from *real library code* —
which is full of network calls, subprocess use, dynamic imports and minified
bundles. A benign corpus of hand-written clean examples would produce a model
that scores beautifully in evaluation and collapses on the first real scan.

A first version took a prefix of the alphabetically-sorted popular list, which
returned only packages beginning with "a". Now shuffled with a fixed seed.

### D-032 — Label leakage was designed out, not hoped away

**This is the most important decision in the training pipeline.**

Malicious samples come from an archive; those packages were removed from the
registries years ago, so they have no live metadata — no publication date, no
version count, no maintainer list. Benign samples are fetched live and have all
of it. Feeding registry metadata to the classifier would let `version_count > 0`
separate the classes perfectly, by detecting **which corpus a sample came from**
rather than whether it is malicious. The model would report near-perfect metrics
and be worthless.

Two countermeasures, both enforced in code rather than by convention:

1. Metadata is reconstructed **only from inside the archive** (`package.json`,
   `PKG-INFO`) — fields an attacker equally controls, available identically for
   both classes.
2. `age_days`, `version_count`, `maintainer_count`, `is_single_version` and
   `is_very_new` are **zeroed for every training sample**, in
   `corpus.build_matrix`, so no caller can bypass it. They stay in the schema and
   are still populated at *scan* time, where the information is real and symmetric.

The cost is that the model cannot learn "published yesterday" as evidence. That
is the right trade: a feature available for only one class in training is not a
feature, it is the label.

A related fix: `SINGLE_VERSION` was firing on 100% of *both* classes, because
archive-derived metadata always reports a version count of 0. The signal now
distinguishes 0 ("unknown") from 1 ("genuinely one version").

### D-033 — Verify the vault before training

`build_dataset.py` re-reads and hash-checks every stored sample before analysis.
Training on a silently truncated dataset is the exact failure this whole design
exists to prevent, so a corrupt blob is reported loudly rather than skipped.

---

## 2026-08-17 — Phase 5: OSV and reachability

**Built:** the OSV advisory client with CVSS scoring and symbol extraction, a
Python call-graph reachability engine, and npm import-level reachability.

### D-034 — Vulnerable symbols come from three tiers, and the tier is reported

npm and PyPI advisories almost never carry structured vulnerable-symbol data
(unlike Go). Symbols are recovered from, in order: structured
`ecosystem_specific` fields; a curated table of ~35 well-known packages; and
code spans parsed out of advisory prose.

**The tier is attached to every result.** A reachability verdict is only as
trustworthy as the symbol list it was computed against, and presenting a
prose-parsed verdict with the same confidence as a structured one would be the
most misleading thing this system could do. Commercial tools maintain thousands
of curated entries; that gap is documented, not hidden.

### D-035 — Graded verdicts, not a reachable/unreachable boolean

`NOT_IMPORTED` (high confidence — the package is in the tree but the application
never imports it) is a much stronger claim than `SYMBOL_NOT_CALLED` (medium), and
both differ from `ASSUMED_REACHABLE` (low — imported, but the advisory names no
symbols so nothing can be ruled out). Collapsing these into one boolean would
throw away the distinction that makes the output actionable.

### D-036 — Entry points, and the two-pass search

Entry points are modules **nothing else imports** — scripts, CLI commands,
plugin modules. For those modules, public functions are also treated as callable,
because something outside the analysed code invokes them. Modules that *are*
imported get no such treatment; only genuine call edges reach into them.
Without that distinction, every function would be an entry point and everything
would report as reachable.

The search then runs **twice**. The first pass starts only from module-level
code, so any path it finds is a real chain of calls — the convincing artifact.
Only if that finds nothing does the second pass add the assumed-callable public
functions. Verified on a fixture project: the proof for PyYAML is
`main → main.run → main.load_settings → yaml.load`, with file and line for each
step, rather than the one-hop path the naive seeding produced.

### D-037 — CVSS v3 base score is approximated deliberately

`_score_from_vector` implements the CVSS v3 base equation but not the full
specification (no temporal or environmental metrics). The score is used to
*order* findings, so accuracy to a severity band is sufficient, and where the
advisory states a severity label directly, the label wins. Verified against
published values: CVE-2019-20477 → 9.8, CVE-2020-8203 → 7.4, CVE-2020-7598 → 5.6.

### D-038 — npm reachability is import-level, and that boundary is stated

Full JavaScript call-graph construction across dynamic `require`, bundler output,
prototype patching and monkey-patching is a research problem in its own right.
Attempting it in this timeframe would produce something that looks like
reachability analysis and quietly returns wrong answers. Instead npm reports
whether the vulnerable package is imported at all, and by which files — a weaker
but *sound* claim, and still where most of the noise reduction comes from, since
most transitive dependencies are never imported by the application.

### D-039 — Uncertainty resolves to reachable

Implementing D-007: no source available → `NOT_ANALYSED`, which counts as
reachable. Advisory names no symbols → `ASSUMED_REACHABLE`. A parse failure drops
the file rather than the finding. `Verdict.is_reachable` returns `True` for every
uncertain state, so a future caller cannot accidentally treat "we don't know" as
"safe".

---

<!-- New entries are appended below as work proceeds. -->



