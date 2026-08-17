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

<!-- New entries are appended below as work proceeds. -->
