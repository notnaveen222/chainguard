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

<!-- New entries are appended below as work proceeds. -->

