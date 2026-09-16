# Session handoff — ChainGuard, pre-review work

**Written:** 2026-09-16, during a single long Claude Code session, to allow
clearing context and continuing cleanly. Read this first in the next session.

**Context:** the backup chat that originally built this project
(`D:\college-project`, now `D:\pjt-1`) was found and confirmed in
`C:\Users\nvn\Downloads\claude-backup-2026-08-22`. This session picked up from
there to prep for a panel review (referred to as "Review 1" in the repo's own
docs, but the user clarified live that the actual upcoming review is a later
one — Review 3ish, with more after it — so expectations are likely higher than
a first "design + early prototype" pass).

---

## 1. What this session did, in order

1. Confirmed the original build chat existed in the backup, traced its
   timeline (Aug 17–22, 2026).
2. Discussed what's "novel" about the project, fact-checked it against the web
   — **see §3, this matters, don't re-litigate it from scratch.**
3. **Part A:** rebuilt the missing trained ML model (it didn't exist on disk —
   only benchmark docs survived). Re-ran `build_dataset.py` +
   `train_model.py`. Done, verified, numbers below (§2).
4. **Part B:** designed and partially built a genuinely new detection feature
   — real data-flow tracing + reachability-style exposure classification for
   the malicious-package detector. Core engine done and tested; **report/CLI/
   dashboard surfacing is NOT done yet** — see §5 for exactly where to resume.
5. A teammate (via WhatsApp, relayed by the user) asked for an open-source,
   recent benchmark to compare against. Found a strong candidate but have
   **not yet run our model against it** — see §6.

---

## 2. Part A — dataset + model rebuild (DONE)

Ran `python scripts/build_dataset.py` then `python scripts/train_model.py`
(both already-existing scripts, no code changes). Took ~37 minutes, fully
successful (exit code 0 both).

| | |
|---|---|
| Dataset | 1,797 samples (898 malicious, 899 benign) — matches original docs exactly |
| Model file | `data/models/classifier.joblib` now exists (was missing before this session) |
| Precision / Recall / F1 | 0.960 / 0.935 / 0.9475 (original docs claim 0.962/0.939/0.950 — close, expected drift since live benign packages sampled today differ slightly from weeks ago) |
| ROC-AUC / PR-AUC | 0.979 / 0.985 |

**Open decision, never resolved:** `docs/MODEL_CARD.md`, `PROGRESS.md` etc.
still show the *old* numbers. Close enough to not matter much, but nobody
decided whether to update them to the fresh ones. Ask the user.

Logs from the run are in the scratchpad dir from that session
(`build_dataset.stdout.log`, `train_model.stdout.log`) — likely gone if the
scratchpad was cleaned; the important output (the model file + regenerated
`model_card.json` + charts) is what persisted, in `data/models/`.

---

## 3. Novelty discussion — the agreed, fact-checked framing

**Do not re-claim "nobody has done this."** Over several rounds of actually
checking (not assuming), here's what's real:

- Commercial tools (Snyk, Socket/Coana, Endor Labs) **already combine**
  malicious-package detection and reachability analysis as *separate features
  on one platform*. That combination alone is not novel — verified directly.
- What's more defensible: those tools are closed, publish no methodology, no
  precision/recall/F1, no dataset, no baseline comparison. This project
  publishes all of that. Lead with *transparency and reproducibility*, not
  "first to combine X and Y."
- **The actual thing this session built for novelty (Part B, §4–5):**
  reachability applied to the malware detector's *own findings*, not just
  CVEs. Verified this specific angle is NOT documented as a working feature
  anywhere:
  - Endor Labs' own site claims something like it in one marketing sentence
    ("we map your entire application to verify whether malicious code is
    reachable") — confirmed the quote is real, but it has **zero technical
    detail** behind it, unlike their CVE-reachability writeup which is
    detailed. Cite this honestly as "a vendor claims this, undocumented" not
    "this exists."
  - Coana's docs (the reachability engine Socket acquired) were quoted
    inconsistently across this session — first as "treats malware as
    unknown," then disputed as "always affected / reachable." **The Coana
    docs site returned HTTP 522 (down) when re-checked — neither version was
    re-verified. Don't cite a specific Coana quote without re-fetching
    `https://docs.coana.tech/scanning/reachability-analysis` successfully
    first.**
  - Closer academic prior art exists: **ProfMalPlus** (arXiv:2607.13965, July
    2026) traces malicious code reachability *within a package's own install/
    entry files* — but not against a *specific consuming application's* call
    graph, which is what this project's version does. **gorisk** (Go tool,
    github.com/1homsi/gorisk) does app-specific capability reachability for
    Go, not tied to an ML verdict. Both are real, cite them, the distinction
    from this project's version still holds.
- **The honest one-line claim to give the panel:** *"Existing tools either
  don't apply reachability to their own malware findings, or claim to without
  showing how. We built a specific, concrete, tested version of it, reusing
  our existing reachability engine, with real evaluation evidence."*

---

## 4. Part B — design (what was agreed and why)

Full back-and-forth with a second AI ("Astra") led here — skip re-deriving
this, it's settled:

- **Rejected:** a much bigger "does this proposed mitigation actually stop the
  attack across install+runtime, tracking saved secrets across separate
  processes" idea. Too large, too much new failure surface, more prior art
  collides with it (Latch, Mir), too risky to build and trust the night before
  a review.
- **Chosen, and what's built:** upgrade the malicious-package detector's
  weakest layer — three composite signals
  (`EXFIL_CREDENTIALS_TO_NETWORK`, `EXFIL_ENV_TO_NETWORK`, `EXFIL_ON_INSTALL`
  in `backend/chainguard/analysis/engine.py::_derive_composites`) currently
  fire on pure **same-file coincidence** ("this file reads a credential path
  AND makes a network call somewhere, unrelated or not").
  - Built a **real intra-procedural taint tracer** for one instantiation
    (credential-shaped reads → network sends) that proves actual data flow,
    not coincidence.
  - Built an **exposure classifier** that reuses the *existing* reachability
    engine (`vulns/reachability.py`, previously only used for CVEs) to answer:
    does this confirmed flow run automatically on install, on import, only if
    the app calls a specific function (and does it?), or is nothing knowable
    (no project supplied)?
  - **Deliberately did NOT touch the existing composite signals, their
    feature-vector mapping, or SCHEMA_VERSION.** The new signal
    (`CONFIRMED_CREDENTIAL_EXFILTRATION`) is intentionally excluded from
    `_SIGNAL_TO_FEATURE` in `analysis/features.py` — see the comment there. This
    means **the freshly-retrained model from Part A did not need to be
    retrained again** for this change; it's purely additive evidence, not a
    change to what the classifier sees. If this decision gets revisited, say
    so explicitly and re-run Part A after.
  - Scoped to **Python only**, **one behaviour family only** (credential
    exfiltration), on purpose — see the module docstring in `dataflow.py` for
    the full reasoning (intra-procedural, flow-insensitive by design, both
    documented as honest limitations in the same style as the rest of this
    codebase).

---

## 5. Part B — exact implementation status

### New files (all written, tested, working)
- `backend/chainguard/analysis/dataflow.py` — the taint tracer. Entry point:
  `find_confirmed_flows(tree, resolve, network_sinks, file=..., runs_at_install=...)`.
  Returns `list[ConfirmedFlow]`.
- `backend/chainguard/analysis/exposure.py` — the exposure classifier. Entry
  point: `classify_exposure(flow, package, analyser) -> ExposureResult`, with
  `ExposureVerdict` enum (`INSTALL_TIME`, `IMPORT_TIME`, `CALL_REACHABLE`,
  `CALL_NOT_REACHABLE`, `UNKNOWN`).
- `backend/tests/test_dataflow.py` — 14 tests, all passing. Covers: direct
  flow, coincidence (must NOT fire), multi-hop chains, env-var secrets,
  ordinary (non-secret) env vars (must NOT fire), module-level vs.
  function-level scoping, setup.py install-time tagging, comments/docstrings
  (must NOT fire), and all 5 exposure verdicts against a synthetic project.
- `scripts/evaluate_dataflow.py` — the old-vs-new evidence script the whole
  feature exists to produce. **Run it: `python scripts/evaluate_dataflow.py`.**
  Last run result: **old heuristic 4/6 correct on fixtures, new tracer 6/6
  correct, 0 false positives across 432 real files from 8 legitimate installed
  packages** (httpx, click, jinja2, anthropic, fastapi, uvicorn, requests,
  flask/yaml/rich — whichever are installed in `.venv`). This is the
  demonstrable proof-of-improvement the user asked for — **use this output
  directly in the panel materials**, don't just describe it.

### Modified files (all done, all tests pass)
- `backend/chainguard/analysis/base.py` — `FileAnalysis` gained
  `confirmed_flows: list[ConfirmedFlow]`.
- `backend/chainguard/analysis/python_ast.py` — calls the tracer at the end of
  `analyse_python_file`, after the `setup.py` pass (so `runs_at_install` is
  final), emits the new signal.
- `backend/chainguard/analysis/signals.py` — registers
  `CONFIRMED_CREDENTIAL_EXFILTRATION` (see the long comment there explaining
  why it's excluded from the feature vector — read it before changing
  anything here).
- `backend/chainguard/analysis/engine.py` — `AnalysisResult` carries
  `confirmed_flows`, collected from all per-file analyses in `analyse_package`.
- `backend/chainguard/scanner.py` — `PackageFinding` gained two fields:
  `exfiltration: list[ExfiltrationExposure]` (public, the classified result)
  and `confirmed_flows: list[ConfirmedFlow]` (internal, `exclude=True` from
  serialization, just a carrier between Stage 3 and Stage 5). Stage 3
  (`_detect`) sets a baseline classification (install-time resolves fully
  immediately; everything else starts `UNKNOWN`). Stage 5 (`_run_stages`,
  right after the reachability `analyser` is built) re-classifies everything
  using the real call graph, for PyPI projects.

### Verification already done
- Full test suite: **124/124 passing** (110 original + 14 new), no
  regressions.
- Manual validation of all 5 exposure verdicts against a synthetic
  `evilpkg`/`app.py` project — all correct, including a real call-path proof
  for the `CALL_REACHABLE` case (`app.main → evilpkg.sync_data (app.py:4)`).

### NOT done yet — resume here
Nothing has been surfaced in **user-facing output**. The engine produces
correct data, but nobody can see it in a real scan yet:
- **CLI** (`backend/chainguard/cli.py`): was mid-edit, reading the
  vulnerability-table rendering code (around the `_SEVERITY_COLOURS` /
  `call_path` handling, ~line 110–178) as a template for adding an
  "Exfiltration exposure" section. Not yet written.
- **HTML report** (`backend/chainguard/reporting/html.py`): not yet touched at
  all. Needs a section per flagged package showing `finding.exfiltration`
  entries — file, line, source→sink evidence, verdict, call path if reachable.
  Match the existing call-path display style used for CVEs.
- **API**: no changes needed — `PackageFinding.exfiltration` already
  serializes correctly (Pydantic v2 handles the nested `ConfirmedFlow`
  dataclass natively; verified via smoke test). Just needs a frontend/report
  consumer.
- **Dashboard** (`frontend/`): not touched, lowest priority per earlier
  discussion — the HTML report and CLI are what's actually used in the demo
  per `docs/review1/VIVA_PREP.md`.
- **Not yet extended to the other two composite signal families**
  (`EXFIL_ON_INSTALL`, reverse-shell) — deliberately scoped down to credentials
  only for this session, as agreed with the user. `dataflow.py`'s source/sink
  design is written to generalize (see its docstring), but only one instance
  is wired up.

### Nothing is committed to git
`git status` shows all of the above as modified/untracked, nothing staged or
committed. Decide with the user whether to commit before or after further
work — they haven't been asked yet.

---

## 6. Open task from the user — benchmark comparison (NOT started)

A teammate asked (via WhatsApp, relayed mid-session) for an **open-source,
recent benchmark** where this project's numbers can be shown to beat it, with
a citable link.

**Strongest candidate found:** Guo et al., *"Understanding NPM Malicious
Package Detection: A Benchmark-Driven Empirical Analysis"*
([arXiv:2603.27549](https://arxiv.org/abs/2603.27549), submitted March 2026,
revised August 2026 — genuinely recent). Combines 5 existing open datasets
(BKC, DONAPI, DataDog, MalOSS, Maltracker) into 6,420 malicious + 7,288 benign
npm packages; benchmarks 8 real open-source tools. Best reported: **GuardDog
(DataDog's own open-source scanner) at 93.32% F1.**

**Do NOT just write "we beat 93.32%" and stop there — that is not established
yet and would repeat the exact overclaiming mistake already caught once this
session (§3).** Our 0.9475 F1 is on a *different* dataset (ours: 898/899,
PyPI+npm mixed, DataDog source only). To make a legitimate claim:

1. Check whether Guo et al.'s combined benchmark dataset (or at least their
   npm-only subset) has a public, downloadable release — check the paper's
   GitHub/artifact link directly (not yet checked this session).
2. If it does: run our already-trained classifier (`data/models/classifier.joblib`)
   against their labelled samples — this means extracting our 58 features from
   *their* packages (reuse `analysis/engine.py::analyse_package`, our download/
   analysis pipeline already works on any npm package) and scoring with
   `ml/model.py`'s existing inference path. Report precision/recall/F1 on
   *their* data, honestly, whatever it turns out to be.
3. If their full dataset isn't public but GuardDog is (it is — DataDog's own
   open-source tool), a fallback: run our detector against a hand-picked
   sample of GuardDog's own known-malicious test cases if those are published
   separately, or at minimum cite the paper as *context* ("recent published
   benchmark puts the best open tool at 93.32% F1; ours, measured on a
   differently-sourced dataset with a comparable grouped-CV methodology,
   reports 94.75%") — with the caveat stated out loud, not hidden. A caveated
   true claim beats an uncaveated shaky one.

This is real, scoped work for next session — not something to rush now.

---

## 7. Quick commands to re-verify everything still works

```
D:\pjt-1\.venv\Scripts\python.exe -m pytest backend\tests -q
D:\pjt-1\.venv\Scripts\python.exe scripts\evaluate_dataflow.py
```

Both should show all-green / 0 false positives, matching §5's numbers above.
