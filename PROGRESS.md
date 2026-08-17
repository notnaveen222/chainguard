# ChainGuard — Build Progress

**Purpose:** resumable build state. If the build is interrupted, this file records
exactly what is done, what was in flight, and the next concrete step — so work
resumes without re-deriving anything.

**Last updated:** 2026-08-17, Phase 0 complete.

---

## Status

| Phase | Description | Status |
|---|---|---|
| 0 | Scaffold: repo, git, venv, deps, docs skeleton | ✅ Complete |
| 1 | Core config + package fetchers (npm/PyPI) | ⬜ Not started |
| 2 | Static analysis + feature extraction engine | ⬜ Not started |
| 3 | Dataset pipeline with encoded-at-rest quarantine | ⬜ Not started |
| 4 | Train + evaluate ML classifier | ⬜ Not started |
| 5 | OSV integration + reachability analysis | ⬜ Not started |
| 6 | FastAPI backend + scan orchestration | ⬜ Not started |
| 7 | React + Tailwind dashboard | ⬜ Not started |
| 8 | Tests, demo data, final docs | ⬜ Not started |

---

## Environment (verified 2026-08-17)

| Component | Version / state |
|---|---|
| Python | 3.10.11 (`.venv` created at repo root) |
| Node / npm | v22.17.1 / 11.6.0 |
| git | 2.50.1 — local repo, **no remote configured** |
| Backend deps | Installed, 63 packages, exit 0 |
| OSV.dev / npm registry / PyPI | All reachable |
| `ANTHROPIC_API_KEY` | Not set — LLM layer builds disabled by default |
| Disk free (D:) | ~46 GB |

Activate the environment with:

```
.venv\Scripts\activate
```

---

## Build order rationale

Phases are ordered so that **demo value lands early**. If the build is cut short,
the earlier phases alone still constitute a working, demonstrable system:

- Phases 1–2 give a scanner that produces real findings on real packages.
- Phase 4 gives measurable detection metrics — the core evaluation claim.
- Phase 5 gives the reachability result, the project's headline contribution.
- Phases 6–7 are presentation over data that already exists.
- Phase 8 is hardening.

A cut at any phase boundary leaves a coherent system, not a skeleton.

---

## Next step

Begin Phase 1: implement `chainguard/config.py`, the cached HTTP client, and the
npm/PyPI registry clients.

---

## Notes for resuming

- Every phase ends with a local git commit. `git log --oneline` shows the exact
  checkpoint reached.
- Nothing in this project is pushed to any remote.
- Malicious samples under `data/quarantine/` are stored encoded and are never
  executed. If that directory is missing, re-run `scripts/build_dataset.py`.
