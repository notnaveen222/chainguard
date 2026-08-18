# Review 1 — ChainGuard

**AI-Powered Software Supply Chain Security:
Malicious Package Detection and Vulnerability Reachability Analysis**

Prepared against the four review rubrics. Each section maps to one rubric.

| § | Rubric | Marks |
|---|---|---|
| 1 | Knowledge on Domain / Problem Statement | 5 |
| 2 | Literature Review (27 papers, 24 from 2023–2026) | 5 |
| 3 | Design of Proposed Methodology | 5 |
| 4 | Module Description / System Design | 5 |

---

# 1. Domain Knowledge and Problem Statement

## 1.1 The domain: software supply chain security

Modern software is **assembled, not written**. A typical Node.js application
declares 15–40 direct dependencies but installs 800–1,500 packages once
transitive dependencies are resolved; a Python application installs 200–400.
Most of the code shipped in a modern application was written by somebody outside
the organisation that ships it.

Each of those packages is code that executes with the full privileges of the
developer who installs it and, later, of the production process that runs it.
That is the **software supply chain**, and it is now a dominant attack surface in
application security.

## 1.2 Why this is an attack surface, structurally

Four properties of package ecosystems make them attractive to attackers:

1. **Install-time code execution.** npm executes `preinstall`, `install` and
   `postinstall` lifecycle hooks automatically on `npm install`. Python executes
   `setup.py` when installing from a source distribution. Code therefore runs
   *before the developer has invoked anything*, on a developer machine or a CI
   runner that typically holds cloud credentials, SSH keys and signing tokens.
2. **Transitive trust is unbounded.** Installing one package implicitly trusts
   its entire dependency closure, and every maintainer of every package in it.
   Zimmermann et al. showed a small number of npm maintainer accounts could reach
   the majority of the ecosystem.
3. **Publication is effectively unauthenticated.** Anyone can publish to npm or
   PyPI. There is no review, and name registration is first-come-first-served.
4. **Human name resolution is fuzzy.** A developer typing a dependency name
   cannot reliably distinguish `python-dateutil` from `python-dateutils`.

## 1.3 Real-world incidents that define the threat model

| Incident | Ecosystem | Mechanism | Impact |
|---|---|---|---|
| `event-stream` (2018) | npm | Maintainer handover, malicious dependency added | Targeted Bitcoin wallet theft; ~2M weekly downloads |
| `ua-parser-js` (2021) | npm | Maintainer account compromise | Cryptominer + credential stealer; ~8M weekly downloads |
| `colors` / `faker` (2022) | npm | Maintainer self-sabotage | Infinite loop broke thousands of CI pipelines |
| `ctx` / `phpass` (2022) | PyPI | Abandoned-name takeover | AWS credential exfiltration |
| PyTorch `torchtriton` (2022) | PyPI | Dependency confusion | Exfiltrated `/etc/passwd` and SSH keys from nightly users |
| XZ Utils / `liblzma` (2024) | Linux distros | Multi-year social engineering of a maintainer | Near-miss backdoor in OpenSSH on most Linux servers |

These are not exotic. They are the ordinary operation of the ecosystem turned
against its users, and they motivate the two problem classes below.

## 1.4 The two problems, stated precisely

### Problem A — Malicious packages (a *detection* problem)

An adversary publishes a deliberately hostile package. The payload is usually
delivered at install time and performs credential exfiltration, cryptocurrency
wallet theft, host reconnaissance, or second-stage download.

**Why existing defences fail:** signature-based scanning requires a known sample,
but every malicious package is new by construction — most are removed within days
of publication, so a signature arrives after the damage is done. Detection must
generalise to packages never seen before, from *behaviour* rather than identity.

### Problem B — Alert fatigue in vulnerability reporting (a *prioritisation* problem)

Software Composition Analysis (SCA) tools match installed package versions
against vulnerability databases and report every match. A real project produces
150–300 CVE findings. Security teams cannot triage that volume, so they triage
nothing, and known-vulnerable dependencies stay unpatched.

**The root cause is that the report is mostly irrelevant.** A CVE in a dependency
matters only if the application can actually *reach* the vulnerable function.
Published measurements put the fraction of dependency vulnerabilities with a
genuine reachable call path at well under 5%. Reporting the other 95% at equal
weight is what destroys the signal.

## 1.5 Formal problem statement

> Given a software project *P* with manifest *M* and source *S*, and the
> transitive dependency closure *D(M)* resolved against the public registries:
>
> **(A)** For each package *d ∈ D(M)*, decide whether *d* is malicious, using only
> statically observable properties of *d*, generalising to packages absent from
> any training corpus, and emitting human-auditable evidence for the decision.
>
> **(B)** For each known vulnerability *v* affecting some *d ∈ D(M)*, decide
> whether the vulnerable symbol of *v* is reachable from an entry point of *S*,
> and when it is, emit the call path as proof.
>
> Subject to: (i) no package in *D(M)* is ever executed; (ii) uncertainty in (B)
> always resolves to *reachable*, since a false "unreachable" conceals an
> exploitable flaw.

## 1.6 Objectives

1. Build a static analysis engine extracting security-relevant behavioural
   features from Python and JavaScript packages without executing them.
2. Train a supervised classifier on **real** malicious and benign packages that
   generalises to unseen packages, and evaluate it honestly.
3. Implement inter-procedural reachability analysis distinguishing *present*
   vulnerabilities from *reachable* ones, with call-path proof.
4. Quantify the reduction in reported findings that reachability achieves.
5. Deliver a usable system: API, dashboard, CLI, and exportable report.

## 1.7 Scope and boundaries

**In scope:** npm and PyPI; static analysis only; Python symbol-level
reachability; npm import-level reachability; OSV.dev as the advisory source.

**Explicitly out of scope**, and why:

- **Dynamic / sandbox analysis.** Complementary, but requires isolated execution
  infrastructure and is evadable by time- and environment-triggered payloads.
- **Full JavaScript call-graph construction.** Dynamic `require`, bundler output,
  prototype patching and monkey-patching make this a research problem in its own
  right; attempting it would yield something that *looks* like reachability
  analysis and silently returns wrong answers.
- **Build-system and CI compromise** (SLSA / provenance territory) — a different
  layer of the same problem, and one that proves *origin*, not *safety*.

---

# 2. Literature Review

27 papers reviewed: **24 published 2023–2026**, plus 3 foundational works
(2019–2020) included because they define the datasets and measurements the recent
literature builds on.

## 2.1 Reviewed literature

### Theme A — Threat characterisation, datasets and measurement

| # | Authors (Year) | Title / Venue | Contribution | Limitation |
|---|---|---|---|---|
| 1 | Ohm, Plate, Sykosch, Meier (2020) | *Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks* — DIMVA; arXiv:2005.09535 | The foundational dataset: 174 real malicious packages (npm/PyPI/RubyGems, 2015–2019) with an attack-tree taxonomy. Establishes install hooks as the dominant execution vector. | Small by modern standards; predates the 2021–2024 surge in volume and evasion. |
| 2 | Zimmermann, Staicu, Tenny, Pradel (2019) | *Small World with High Risks: A Study of Security Threats in the npm Ecosystem* — USENIX Security; arXiv:1902.09217 | Quantifies transitive trust: a handful of maintainer accounts can reach most of npm. Motivates why dependency depth matters. | Measures structure, not detection; npm only. |
| 3 | Guo et al. (2023) | *An Empirical Study of Malicious Code in PyPI Ecosystem* — arXiv:2309.11021 | Large-scale characterisation of malicious PyPI code and its distribution over time. | Descriptive; proposes no detector. |
| 4 | Ladisa, Plate, Martinez, Barais et al. (2023) | *The Hitchhiker's Guide to Malicious Third-Party Dependencies* — arXiv:2307.09087 | Systematises attacker techniques across ecosystems into a reusable taxonomy. | Taxonomy, not an implementation. |
| 5 | Vu et al. (2024) | *A Study of Malware Prevention in Linux Distributions* — arXiv:2411.11017 | Compares distribution review gates against registry free-for-alls; shows curation materially reduces malware. | Distro-focused; not directly transferable to npm/PyPI. |
| 6 | Ryan et al. (2025) | *Unveiling Malicious Logic: Towards a Statement-Level Taxonomy and Dataset for Securing Python Packages* — arXiv:2512.12559 | Statement-level labelling of malicious logic, finer-grained than package-level labels. | Labelling is expensive; dataset still growing. |
| 7 | Guo et al. (2026) | *How Effective Are NPM Malicious Package Detectors? A Large-Scale Empirical Study* — arXiv:2603.27549 | Benchmarks existing detectors; finds evasion-technique use grew 3.8× (94 → 358 packages) from 2020 to 2024–25, with hook abuse at 9.4%. | Evaluates detectors; does not propose one. |
| 8 | Robinson et al. (2026) | *Original Sin of npm: A Study on Vulnerability Propagation in JavaScript Dependency Networks* — arXiv:2604.17668 | Models how a single vulnerable package propagates through the dependency network. | Propagation modelled at package granularity, not call granularity. |

### Theme B — Machine learning and static-feature detection

| # | Authors (Year) | Title / Venue | Contribution | Limitation |
|---|---|---|---|---|
| 9 | Zhang et al. (2023) | *Killing Two Birds with One Stone: Malicious Package Detection in NPM and PyPI using a Single Model of Malicious Behavior Sequence* — arXiv:2309.02637 | Cross-ecosystem detection from an abstracted behaviour sequence; one model serves both registries. | Behaviour sequences need reliable extraction; obfuscation degrades them. |
| 10 | Samaana et al. (2024) | *A Machine Learning-Based Approach For Detecting Malicious PyPI Packages* — arXiv:2412.05259 | Classical ML (RF / DT / XGBoost) over metadata and code-structure features. **Closest prior work to this project.** | PyPI only; notes Levenshtein-only typosquat detection suffers high false-positive and false-negative rates. |
| 11 | Mehedi et al. (2025) | *DySec: A Machine Learning-based Dynamic Analysis for Detecting Malicious Packages in PyPI Ecosystem* — arXiv:2503.00324 | Dynamic tracing of install-time behaviour, capturing what static analysis cannot. | Requires sandboxed execution; evadable by triggered payloads; costly per package. |
| 12 | Zhang, X. et al. (2025) | *Automatically Generating Rules of Malicious Software Packages via Large Language Model* — IEEE/IFIP DSN 2025; arXiv:2504.17198 | Uses an LLM to synthesise detection rules, combining LLM generality with rule auditability. | Generated rules need human validation; drift with model version. |
| 13 | Yan et al. (2025) | *An LLM-based Quantitative Framework for Evaluating High-Stealthy Backdoor Risks in OSS Supply Chains* — arXiv:2511.13341 | Targets *stealthy* backdoors that behavioural detectors miss. | Evaluation framework rather than a deployable detector. |
| 14 | Guo, W. et al. (2026) | *Cutting the Gordian Knot: Detecting Malicious PyPI Packages via a Knowledge-Mining Framework* — arXiv:2601.16463 | Mines an API-knowledge base to ground detection in documented dangerous behaviour. | Knowledge-base construction is the bottleneck. |
| 15 | Pang et al. (2026) | *PYPILINE: Malicious PyPI Package Detection via Suspicious API Knowledge and Agent Workflow* — arXiv:2606.19063 | Agentic workflow over suspicious-API knowledge; explicitly targets interpretability. | Agent workflows are slow and costly at registry scale. |

### Theme C — Large language models for package analysis

| # | Authors (Year) | Title / Venue | Contribution | Limitation |
|---|---|---|---|---|
| 16 | Zahan, Burckhardt, Lysenko et al. (2024) | *Leveraging Large Language Models to Detect npm Malicious Packages* — arXiv:2403.12196 | Multi-stage LLM workflow (SocketAI Scanner) with iterative self-refinement and zero-shot CoT prompting. | Cost and latency per package; non-deterministic; hard to report stable precision/recall. |
| 17 | Nguyen et al. (2025) | *Taint-Based Code Slicing for LLMs-based Malicious NPM Package Detection* — arXiv:2512.12313 | Slices code by taint before prompting, so the LLM sees only relevant paths. | Depends on slicing quality; inherits LLM cost. |
| 18 | Lamprou et al. (2025) | *Lexo: Eliminating Stealthy Supply-Chain Attacks via LLM-Assisted Program Regeneration* — arXiv:2510.14522 | Regenerates package functionality from scratch, removing hidden behaviour rather than detecting it. | Regeneration correctness unproven at scale; computationally heavy. |
| 19 | Ryan et al. (2026) | *An Evaluation of Large Language Models for Detection of Malicious Python Packages* — arXiv:2602.16304 | Evaluates LLMs on high-level detection vs. fine-grained indicator identification; finds a substantial gap. | Identifies the gap rather than closing it. |
| 20 | Toda, Ishikawa (2026) | *CHASE: LLM Agents for Dissecting Malicious PyPI Packages* — arXiv:2601.06838 | LLM agents producing analyst-style dissections of malicious packages. | Explanatory rather than a primary detector. |

### Theme D — Reachability, SCA and vulnerability prioritisation

| # | Authors (Year) | Title / Venue | Contribution | Limitation |
|---|---|---|---|---|
| 21 | Foo, Chua, Yeo, Ang (2019) | *The Dynamics of Software Composition Analysis* — arXiv:1909.00973 | Argues SCA must do three things: discover dependencies, **check reachability of vulnerable code to eliminate false positives**, and automate remediation. Directly frames this project. | Predates modern ecosystem scale; no released implementation. |
| 22 | Chen et al. (2023) | *Exploiting Library Vulnerability via Migration Based Automating Test Generation* — arXiv:2312.09564 | Generates tests that actually trigger a library vulnerability from client code — dynamic confirmation of reachability. | Test generation is expensive and coverage-limited. |
| 23 | Alexopoulos et al. (2026) | *Cross-Ecosystem Vulnerability Analysis for Python Applications* — arXiv:2603.18693 | Cross-ecosystem analysis spanning PyPI and system-level dependencies. | Python-centric; system-package linkage is partial. |
| 24 | Ma et al. (2025) | *ReachCheck: Compositional Library-Aware Call Graph Reachability Analysis in the IDEs* — ACM TOSEM; doi:10.1145/3767166 | Compositional, library-aware call-graph reachability fast enough for interactive IDE use. | Requires precomputed library summaries; language-specific. |

### Theme E — Ecosystem defences, SBOM and provenance

| # | Authors (Year) | Title / Venue | Contribution | Limitation |
|---|---|---|---|---|
| 25 | Gokkaya, Aniello, Halak (2023) | *Software supply chain: review of attacks, risk assessment strategies and security controls* — arXiv:2305.14157 | Systematic review mapping attacks to controls; positions detection among defences. | Survey; no empirical evaluation. |
| 26 | Tamanna, Williams et al. (2024) | *Analyzing Challenges in Deployment of the SLSA Framework for Software Supply Chain Security* — arXiv:2409.05014 | Documents why provenance frameworks are hard to adopt in practice. | Provenance is orthogonal to *content* analysis — it proves origin, not safety. |
| 27 | O'Donoghue et al. (2025) | *Software Bill of Materials in Software Supply Chain Security: A Systematic Literature Review* — arXiv:2506.03507 | SLR over 40 studies; identifies **false positives** and **vulnerability exploitability** among the principal barriers to SBOM usefulness. | Confirms the problem; does not solve it. |

## 2.2 Synthesis

**Detection has converged on behaviour, not signatures.** Every recent detector
(#9–#20) models what a package *does* — install hooks, network egress, credential
paths, obfuscation. Signature matching has effectively been abandoned, because
malicious packages are new by construction.

**Three detector families, with a clear trade-off.** Classical ML over static
features (#10) is fast, cheap and measurable, but bounded by feature quality.
Dynamic analysis (#11) observes real behaviour but needs sandboxing and is evaded
by triggered payloads. LLM approaches (#16–#20) generalise impressively but are
slow, costly, non-deterministic and — the recurring criticism — **hard to
evaluate with stable precision and recall**.

**Evasion is escalating.** #7 measures 3.8× growth in evasion-technique use
between 2020 and 2024–25, with hook abuse reaching 9.4%. Detectors must assume
obfuscation rather than treat it as exceptional.

**The prioritisation problem is acknowledged but under-served.** #21 named
reachability as a core SCA task in 2019; #27 reports in 2025 that false positives
and exploitability remain top barriers to SBOM usefulness. Six years, same gap.
The reachability work that exists (#22, #24) is either dynamic and expensive, or
IDE-scoped and dependent on precomputed summaries.

**Datasets are the quiet bottleneck.** #1 remains widely used at 174 samples;
#6 and #7 are only now producing larger, better-labelled corpora. Evaluation
methodology — grouping, leakage, baselines — is rarely reported in detail.

## 2.3 Research gap

| Gap | Evidence | Addressed by |
|---|---|---|
| **G1 — Detection and prioritisation are studied separately.** Detectors (#9–#20) and reachability work (#21–#24) form disjoint literatures, yet a practitioner needs both on the same dependency tree. | No reviewed paper does both. | §3.1 — one pipeline, two independent analyses over a shared dependency graph. |
| **G2 — Reachability is named as the fix for alert fatigue but rarely implemented end-to-end for npm/PyPI**, largely because advisories for these ecosystems lack structured vulnerable-symbol data. | #21 (2019) vs. #27 (2025) — gap unclosed. | §3.4 — three-tier symbol extraction with the tier reported, plus graded verdicts. |
| **G3 — Evaluation methodology is under-reported.** Grouped splitting, label leakage and rules baselines are seldom discussed, so figures are hard to trust or reproduce. | Metrics commonly reported without split-grouping detail. | §3.5 — grouped CV, explicit leakage prevention, rules baseline, ablation. |
| **G4 — Explainability is asserted rather than delivered.** #15 and #20 target interpretability; most detectors emit a score with no auditable evidence. | Score-only outputs dominate. | §3.2 — every verdict carries file, line, snippet and explanation. |

## 2.4 Positioning of this work

ChainGuard sits deliberately in the **static + classical ML** family for
detection — measurable, offline, free to run — and adds the **reachability layer
the detection literature omits**. The LLM is used only to *explain* verdicts,
never to make them, precisely because the reviewed LLM literature (#16, #19)
identifies evaluation instability as its central weakness.
---

# 3. Design of Proposed Methodology

## 3.1 Overall design

The system runs **five sequential stages** over a shared dependency graph. The
two analyses that matter — detection and reachability — are deliberately
**independent**: a failure in one does not take out the other, and each records
its own errors while the scan continues. This is the direct answer to gap **G1**.

```
        Manifest (package.json / requirements.txt)  +  Application source
                                  │
      ┌───────────────────────────▼───────────────────────────┐
      │  STAGE 1 — PARSE            manifest → requirements    │
      └───────────────────────────┬───────────────────────────┘
      ┌───────────────────────────▼───────────────────────────┐
      │  STAGE 2 — RESOLVE          BFS transitive closure     │
      │                             against npm / PyPI          │
      └───────────────────────────┬───────────────────────────┘
                                  │  dependency graph D(M)
              ┌───────────────────┴────────────────────┐
              ▼                                        ▼
  ┌───────────────────────┐              ┌──────────────────────────┐
  │ STAGE 3 — DETECT      │              │ STAGE 4 — ADVISE         │
  │ download in memory    │              │ OSV.dev batch query      │
  │ AST static analysis   │              │ CVSS + fixed versions    │
  │ 58-feature vector     │              │ vulnerable-symbol extract│
  │ ML classifier         │              └────────────┬─────────────┘
  │ → score + evidence    │                           ▼
  └───────────┬───────────┘              ┌──────────────────────────┐
              │                          │ STAGE 5 — REACH          │
              │                          │ call graph of app source │
              │                          │ symbol resolution        │
              │                          │ → REACHABLE + proof path │
              │                          │ → NOT REACHABLE + reason │
              │                          └────────────┬─────────────┘
              └───────────────┬───────────────────────┘
                              ▼
              Risk aggregation · remediation plan · report
```

## 3.2 Stage 3 — Detection methodology

### 3.2.1 Why static AST analysis, not pattern matching

A regular expression for `eval(` matches the word inside a comment, a docstring,
or a variable named `evaluate`. An **abstract syntax tree** sees a genuine call
node and nothing else. More importantly, an AST resolves aliases:
`import subprocess as sp` followed by `sp.run(...)` is invisible to text search
but explicit in the tree.

Parsing is also what makes analysing hostile code *safe*: `ast.parse()` builds a
tree without evaluating anything. **No package is ever executed** — there is no
`pip install`, no `npm install`, no `setup.py` invocation anywhere in the system.

- **Python:** the standard-library `ast` module.
- **JavaScript:** `esprima` (pure Python, so the backend needs no Node runtime).
- **Degradation, not failure:** when a parse fails (newer syntax, TypeScript,
  deliberately malformed source, or a file too large to parse safely), the
  analyser falls back to text-level scanning and sets a `parse_failed` flag, so
  the feature vector records *reduced visibility* rather than reporting a file
  as clean that it never actually read.

### 3.2.2 The signal catalogue — evidence, not just a score

38 signal types across 10 behavioural categories. Every signal carries **file,
line, source snippet and a human-readable explanation** — the answer to gap
**G4**. The same signal set feeds both the numeric feature vector and the report,
so a score can always be traced to the observations that produced it.

| Category | Examples |
|---|---|
| Install-time execution | `postinstall` hooks, `curl \| bash` piping, `setup.py` side effects |
| Dynamic execution | `eval` / `exec` / `new Function`, decode-then-execute |
| Process spawning | `child_process`, `subprocess`, shell interpretation |
| Network | raw-IP endpoints, paste sites, Discord/Telegram webhooks, DNS exfiltration |
| Credential access | SSH keys, cloud credentials, browser stores, keychains |
| Cryptocurrency | wallet files, MetaMask extension IDs, recovery phrases |
| Obfuscation | opaque high-entropy literals, base64 blobs, char-code assembly, string-array decoders |
| Exfiltration (composite) | credentials **and** network egress in one file |
| Metadata | missing repository, empty description, tiny package with an install hook |
| Typosquatting | near-miss, homoglyph, separator, affix, scope confusion |

### 3.2.3 Composite signals — the key design idea

Reading the environment is unremarkable. Making an HTTP request is unremarkable.
**Doing both in the same file is the shape of credential theft**, and no
individual detector can observe that co-occurrence.

Per-file analysers therefore record behaviour *flags*; a second pass derives
composite signals from them (`EXFIL_CREDENTIALS_TO_NETWORK`, `EXFIL_ON_INSTALL`,
`REVERSE_SHELL_PATTERN`).

This was validated empirically: across twelve popular real packages (`express`,
`chalk`, `debug`, `commander`, `axios`, `webpack`, `requests`, `click`,
`urllib3`, `flask`, `pyyaml`, `rich`) **not one composite signal fired**, while
both malicious samples triggered them immediately. Individual sinks are noisy;
composition is precise.

### 3.2.4 Typosquat detection — four mechanisms, not one

Prior work (#10) notes that Levenshtein-only detection suffers high error rates.
The implementation therefore combines:

1. **Keyboard-adjacency-weighted Damerau–Levenshtein** — adjacent-key
   substitutions cost 0.6 rather than 1.0, and transposition costs 0.6, because
   swapping two adjacent characters is the most common typing error. `reqeusts`
   therefore ranks much closer to `requests` than an arbitrary edit would.
2. **Homoglyph substitution** — `1odash` vs `lodash`.
3. **Structural variants** — separator swaps, added or removed affixes
   (`-js`, `.js`, `2`), enumerated directly because they are exact-match tricks
   rather than typos.
4. **Scope confusion** — a scoped name reproduced without its scope, or vice versa.

Ground truth is 614 npm + 518 PyPI popular names, generated and committed so
scans are reproducible and work offline. A package *on* the list is never flagged
against itself, and names under five characters are excluded because at that
length almost everything is within distance 2 of something.

### 3.2.5 Feature engineering

58 features in a fixed, versioned order across 11 groups. Counts are
`log1p`-compressed so that large legitimate libraries do not dominate the feature
space purely by being large.

**Why hand-engineered features rather than a neural model over raw source?**
Three reasons, all defensible: (a) the dataset is on the order of thousands of
samples, not millions — deep models overfit at that scale; (b) tree ensembles
give per-feature importances, so every verdict is explainable; (c) it runs on a
laptop with no GPU, which matters for a live demonstration.

`SCHEMA_VERSION` is persisted with the model and **checked** at inference. A
model trained on schema v1 fed a v2 vector would not fail — it would silently
score the wrong columns and return a confident, meaningless number. A mismatch
therefore raises rather than coerces.

## 3.3 Dataset methodology

| | |
|---|---|
| Malicious | 898 real packages — DataDog malicious-software-packages-dataset (Apache-2.0) |
| Benign | 899 real packages downloaded live from npm and PyPI |
| Total | **1,797 samples across 1,796 distinct package families** |

**Benign samples are real popular packages, not toy examples.** The classifier
must separate malware from *real library code*, which is full of network calls,
subprocess use, dynamic imports and minified bundles. A benign corpus of
hand-written clean examples would produce a model that scores beautifully in
evaluation and collapses on the first real scan.

### 3.3.1 Label leakage — designed out, not hoped away

**This is the most important methodological decision in the project.**

Malicious samples come from an archive; those packages were removed from the
registries years ago, so they have **no live registry metadata** — no publication
date, no version count, no maintainer list. Benign samples are fetched live and
have all of it.

Feeding registry metadata to the classifier would let `version_count > 0`
separate the classes *perfectly* — not by detecting malware, but by detecting
**which corpus a sample came from**. The model would report near-perfect metrics
and be worthless. Worse, the failure would be invisible: the numbers would simply
look excellent.

Two countermeasures, both enforced in code rather than by convention:

1. Metadata is reconstructed **only from inside the archive** (`package.json`,
   `PKG-INFO`) — fields an attacker equally controls, available identically for
   both classes.
2. Five registry-only features (`age_days`, `version_count`, `maintainer_count`,
   `is_single_version`, `is_very_new`) are **zeroed for every training sample**
   inside the matrix builder, so no caller can bypass it. They remain in the
   schema and are still populated at *scan* time, where the information is real
   and symmetric.

The cost is that the model cannot learn "published yesterday" as evidence. That
is the correct trade: **a feature available for only one class in training is not
a feature, it is the label.**

### 3.3.2 Safe handling of live malware

Samples are stored **encoded at rest** and decoded into memory only; there is no
write-to-disk decode path anywhere in the system. This means no antivirus
exclusion was required and no security setting on the host machine was changed.

This is documented honestly as **obfuscation, not cryptography** — the key is a
constant in the source file. The threat model is an antivirus scanner or a
careless double-click, not an attacker with disk access. The property that
actually matters is enforced elsewhere and does not depend on the encoding at
all: **nothing is ever executed.**

## 3.4 Stage 5 — Reachability methodology

### 3.4.1 Algorithm (Python, symbol-level)

```
INPUT :  project source S, package p, vulnerable symbols V
OUTPUT:  verdict, call path

1  G ← build call graph over S
      nodes  = module-level scopes ∪ function/method scopes
      edges  = intra-app calls ∪ import edges
2  A ← import names actually provided by p          # pyyaml → yaml
3  if no module of S imports any name in A:
        return NOT_IMPORTED                          # strongest negative
4  if V = ∅:
        return ASSUMED_REACHABLE                     # fail-safe: cannot rule out
5  E ← entry points = modules imported by nothing else
6  # Pass 1 — module-level seeds only, so any path found is a real call chain
   path ← BFS(G, seeds = module scopes of E, target = calls into p.V)
   if path ≠ ∅: return REACHABLE, path
7  # Pass 2 — add public functions of entry modules (assumed externally callable)
   path ← BFS(G, seeds = pass-1 seeds ∪ public functions of E, target = same)
   if path ≠ ∅: return REACHABLE, path
8  return SYMBOL_NOT_CALLED
```

### 3.4.2 Three design decisions that make this work

**(a) Graded verdicts, not a boolean.** `NOT_IMPORTED` (high confidence — the
package is in the tree but the application never imports it) is a much stronger
claim than `SYMBOL_NOT_CALLED` (medium), and both differ from
`ASSUMED_REACHABLE` (low — imported, but the advisory names no symbols so nothing
can be ruled out). Collapsing these into one boolean throws away the distinction
that makes the output actionable.

**(b) Two-pass search, because proof quality differs.** Pass 1 starts only from
module-level code, so any path it finds is a genuine chain of calls — the
convincing artifact. Only if that finds nothing does pass 2 add assumed-callable
public functions. On the demo project this is the difference between reporting
`config.load_settings → yaml.load` and the full
`app → app.main → app.bootstrap → config.load_settings → yaml.load`.

**(c) Distribution names are not import names.** `pip install pyyaml` gives
`import yaml`; `pillow` gives `PIL`. Advisories are published against the
*distribution* name while source imports the *module* name. Conflating them
produces a **confident false "safe" verdict** — the single worst possible output.
Resolution is derived from each downloaded archive's `top_level.txt` or directory
layout, with a curated table as fallback.

### 3.4.3 Vulnerable-symbol extraction — three tiers, tier reported

npm and PyPI advisories rarely carry structured symbol data (gap **G2**).
Symbols are recovered from, in descending reliability:

1. structured `ecosystem_specific` advisory fields;
2. a curated table of ~35 well-known packages;
3. code spans and call-shaped tokens parsed from advisory prose.

**The tier is attached to every result.** A reachability verdict is only as
trustworthy as the symbol list it was computed against, and presenting a
prose-parsed verdict with the same confidence as a structured one would be the
most misleading thing the system could do.

### 3.4.4 Fail-safe direction

**Every uncertain case resolves to *reachable*.** The two errors are not
symmetric: a false "reachable" costs an engineer ten minutes of review; a false
"unreachable" hides a genuinely exploitable vulnerability. No source available →
`NOT_ANALYSED`, which counts as reachable. Dynamic dispatch, computed imports and
reflection are all treated as reaching everything.

Related, and found during testing: a package that **could not be downloaded**
(removed from the registry — which is the normal fate of a reported typosquat)
has no signals and therefore scores 0.0. Reporting that as clean would be a false
all-clear in exactly the case where the tool is most useful. Such packages are
now tracked and reported separately as **"Not inspected — NOT confirmed clean."**

## 3.5 Evaluation methodology (gap G3)

| Decision | Rationale |
|---|---|
| **Grouped splitting** (`StratifiedGroupKFold` by package name) | Different versions of one package, and repeat uploads from one campaign, must never span the train/test boundary. Without grouping, a near-duplicate of a test sample sits in training and every score is inflated. This single choice separates an honest number from a flattering one. |
| **Out-of-fold reporting** | Every figure comes from predictions made by a model that had not seen that sample. |
| **PR-AUC leads over accuracy** | Deployment class balance is extreme (malware is rare). A model predicting "benign" always would score high accuracy and detect nothing. |
| **Probability calibration** (isotonic, grouped folds) | The reported number is shown to a human, so "0.8" should mean something close to "80% of packages scoring this are malicious". |
| **Rules-only baseline** | A weighted-sum engine over the same signals, scored on the same data. Without it, "we used machine learning" is an assertion rather than a result. |
| **Per-family ablation** | Each feature family zeroed and the model retrained, to measure what each actually contributes. Zeroing rather than dropping keeps the feature count constant so models stay comparable. |

---

# 4. Module Description and System Design

## 4.1 Layered architecture

| Layer | Responsibility |
|---|---|
| **Presentation** | React + Tailwind dashboard · CLI · self-contained HTML report |
| **Service** | FastAPI application · background job registry · scan orchestrator |
| **Analysis** | Static analysers · feature extraction · ML inference · reachability engine |
| **Acquisition** | npm / PyPI clients · archive extraction · dependency resolver · OSV client |
| **Data** | SQLite scan store · encoded sample vault · content-addressed HTTP cache · model artifacts |

## 4.2 Module description

| # | Module | Package | Responsibility | Input | Output |
|---|---|---|---|---|---|
| M1 | Configuration | `chainguard.config` | Central settings and the resource ceilings that protect the scanner from hostile input | Environment / `.env` | `Settings`, `AnalysisLimits` |
| M2 | Registry clients | `registry.npm`, `registry.pypi` | Fetch package metadata and distributions; resolve version specifiers | Package name + range | `PackageMetadata`, distribution bytes |
| M3 | Version resolution | `registry.semver` | npm range grammar (`^`, `~`, `x`, hyphen, `\|\|`) including the 0.x caret rule | Range + published versions | Concrete version |
| M4 | Archive extraction | `registry.archive` | In-memory extraction with zip-slip, decompression-bomb, member-count and per-file guards | Archive bytes | `PackageFile[]` (+ truncation reason) |
| M5 | Manifest parsing | `registry.manifest` | `package.json`, lockfile v1/v2/v3, `requirements.txt`, `pyproject.toml` | Manifest text | `ParsedManifest` |
| M6 | Dependency resolution | `registry.resolver` | Breadth-first transitive closure; lockfile precedence; per-package failure isolation | `ParsedManifest` | `DependencyGraph` |
| M7 | Static analysis | `analysis.python_ast`, `analysis.js_ast`, `analysis.shell` | AST analysis, alias resolution, install-hook command analysis | `PackageFile[]` | `FileAnalysis` + signals |
| M8 | Typosquat detection | `analysis.typosquat` | Weighted edit distance, homoglyph, separator, affix, scope confusion | Package name | `TyposquatMatch` |
| M9 | Feature extraction | `analysis.features` | 58 versioned features across 11 groups | Signals + analyses + metadata | `PackageFeatures` |
| M10 | Analysis engine | `analysis.engine` | Orchestrates per-file analysis; derives composite signals; assembles the vector | `PackageContents` | `AnalysisResult` |
| M11 | Dataset pipeline | `dataset.vault`, `dataset.sources`, `dataset.corpus` | Encoded sample storage, corpus acquisition, leakage-free matrix construction | Research dataset + registries | `features.csv` |
| M12 | ML training | `ml.train`, `ml.plots` | Grouped CV, baseline comparison, ablation, calibration, charts | Feature matrix | Model + model card + 6 charts |
| M13 | ML inference | `ml.model` | Schema-checked scoring; degrades to rules baseline and says so | `PackageFeatures` | `Prediction` |
| M14 | Advisory client | `vulns.osv` | Batch OSV queries, CVSS parsing, three-tier symbol extraction | `PackageRef[]` | `Vulnerability[]` |
| M15 | Import-name resolution | `vulns.import_names` | Distribution → module mapping (`pyyaml` → `yaml`) | Distribution + archive | Module names |
| M16 | Reachability engine | `vulns.reachability` | Call-graph construction, entry points, two-pass BFS, proof paths | Source + package + symbols | `ReachabilityResult` |
| M17 | Scan orchestrator | `chainguard.scanner` | Five-stage pipeline, CVE dedup, risk aggregation, remediation plan | Manifest / project | `ScanResult` |
| M18 | Explanation layer | `llm.explain` | Prose explanation; local by default, optional LLM; never changes a verdict | Signals + verdict | `Explanation` |
| M19 | Reporting | `reporting.html` | Self-contained HTML report with print stylesheet | `ScanResult` | HTML document |
| M20 | API service | `api.app`, `api.jobs` | REST endpoints, background jobs, progress polling, model hot-reload | HTTP | JSON / HTML |
| M21 | Persistence | `models.db` | SQLite scan store with queryable summary columns | `ScanResult` | Stored scan |
| M22 | Dashboard | `frontend/src` | Scan submission, live progress, evidence, call-path viewer, model evaluation | REST | Rendered UI |

## 4.3 Data flow

**Level 0 (context).** Developer → [ChainGuard] → risk report. External entities:
npm registry, PyPI, OSV.dev.

**Level 1.**

```
Developer ──manifest+source──▶ 1.0 Parse & Resolve ──┬──▶ D1 HTTP cache
                                     │               └──▶ npm / PyPI
                                     ▼ dependency graph
                              2.0 Detect ──────────────▶ D2 Model artifacts
                                     │ score + evidence
                                     ▼
                              3.0 Advise ◀────────────── OSV.dev
                                     │ advisories + symbols
                                     ▼
                              4.0 Reach ◀────────────── application source
                                     │ verdict + call path
                                     ▼
                              5.0 Aggregate & Report ──▶ D3 SQLite scan store
                                     │
                                     ▼
                              Developer (dashboard / CLI / HTML report)
```

## 4.4 Database schema

Single `scans` table: queryable summary columns (target, ecosystem, status,
timestamp, package counts, reachable/unreachable counts, detector used) plus the
full result as JSON.

Five normalised tables were the original plan and were **rejected during
implementation**: a scan result is a deeply nested document always read whole, so
normalising would require a five-way join on every read to reconstruct exactly
what was written, while the summary columns already serve every listing and
filtering query the dashboard makes.

## 4.5 API surface

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/scans/project` | Scan a project directory (**enables reachability**) |
| `POST` | `/api/scans/manifest` | Scan a pasted manifest |
| `POST` | `/api/scans/package` | Analyse a single package |
| `GET` | `/api/scans/{id}/status` | Poll progress (stage, percentage, message) |
| `GET` | `/api/scans/{id}` | Full scan result |
| `GET` | `/api/scans/{id}/report` | Self-contained HTML report |
| `GET` | `/api/scans` | Scan history |
| `GET` | `/api/model` | Model card: metrics, ablation, feature importances |
| `GET` | `/api/signals` | Signal catalogue |
| `GET` | `/api/health` | Liveness and active detector |

## 4.6 Security design of the scanner itself

A tool that ingests malicious packages is itself a target.

| Threat | Control |
|---|---|
| Sample execution | Never installed or executed; static parsing only |
| Malware on disk | Training samples encoded at rest, decoded in memory only |
| Zip-slip / path traversal | Member paths normalised; escaping paths, symlinks and absolute paths rejected |
| Decompression bombs | Uncompressed-size ceiling and compression-ratio limit, checked *before* decompression |
| Parser denial-of-service | Per-file size caps, file-count caps, AST parse-size ceiling, per-package timeout |
| Report injection | All interpolated values HTML-escaped (package names are attacker-controlled) |
| Cross-origin abuse | CORS restricted to dev-server origins; the dev server proxies so no cross-origin request is made at all |
| Secret leakage | API keys from environment only; `.env` gitignored |

## 4.7 Technology stack

| Layer | Technology | Justification |
|---|---|---|
| Backend | Python 3.10, FastAPI, uvicorn | ML and AST tooling are Python-native; `ast` in stdlib is exactly what the reachability engine needs; async suits many concurrent registry calls |
| JS parsing | `esprima` (pure Python) | Keeps the backend to one runtime — no Node subprocess, no native build step |
| ML | scikit-learn (gradient boosting) | Dataset size suits tree ensembles; per-feature importances give explainability; CPU-only |
| Frontend | React 18, Vite, Tailwind | Product-grade UI; fast dev server; no hand-written CSS |
| Database | SQLite + SQLAlchemy | Zero setup — a demo must never fail because a service is not running |
| Advisories | OSV.dev | One API covering npm and PyPI, structured version ranges, no API key |

---

# 5. Results achieved so far

## 5.1 Detection

Grouped 5-fold cross-validation, out-of-fold, n = 1,797:

| Metric | Model | Rules baseline | Improvement |
|---|---|---|---|
| Precision | **0.9623** ± 0.0119 | 0.8421 | +0.120 |
| Recall | **0.9388** ± 0.0113 | 0.4276 | +0.511 |
| F1 | **0.9504** ± 0.0064 | 0.5650 | **+0.385** |
| ROC-AUC | **0.9803** | — | — |
| PR-AUC | **0.9856** | 0.7191 | +0.267 |

Confusion matrix: **TP 843 · FP 33 · FN 55 · TN 866**.

## 5.2 Reachability — the central claim

On the demo project: **92 advisories reported → 3 actually reachable (97% ruled
out)**, each with a call-path proof:

```
app → app.main → app.bootstrap → config.load_settings → yaml.load
     app.py:31        app.py:26         app.py:21        config.py:18
```

The remediation plan ranks `pyyaml` (3 fixes, all reachable) **above** `pillow`
(56 fixes, none reachable). Ordering by raw count inverts that and sends the
developer to fix the wrong thing first.

## 5.3 Detector comparison in practice

On the same demo project, the rules baseline flags **six** packages; the trained
model flags **one**. Large mature libraries genuinely do call `eval`, spawn
processes and read config paths — the model has learned this is unremarkable at
that scale, and a weighted-sum engine cannot.

## 5.4 Engineering

110 offline tests passing · `ruff` clean · 21 checkpointed commits ·
~11,200 lines of Python · full decision log of 53 recorded decisions.

# 6. Limitations and future work

Stated plainly, because a security tool that overstates its certainty is worse
than one that admits a gap.

1. **npm reachability is import-level only.** Symbol-level JavaScript analysis
   requires solving dynamic `require`, bundler output and monkey-patching.
2. **"Not statically reachable" ≠ "not exploitable."** Dynamic dispatch,
   `getattr` indirection and reflection are not resolved.
3. **Survivorship bias.** Training malware is malware that was *caught*; real
   recall is likely below the measured 0.939.
4. **Artificial class balance.** The corpus is ~50/50; a real registry is closer
   to 1-in-10,000, so deployment precision would be lower.
5. **Structural features rank high** partly because malicious samples are small
   droppers and popular benign packages are large libraries — a corpus property
   as well as real signal.
6. **The curated symbol table covers ~35 packages**, so many advisories resolve
   to `ASSUMED_REACHABLE` rather than a precise verdict.

**Planned for Review 2:** expand the symbol table; investigate the 55 false
negatives; offline mode with a bundled advisory snapshot; CI/CD integration
(GitHub Action); evaluation across a wider set of real projects.

---

# References

1. M. Ohm, H. Plate, A. Sykosch, M. Meier, "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks," DIMVA 2020. arXiv:2005.09535
2. M. Zimmermann, C.-A. Staicu, C. Tenny, M. Pradel, "Small World with High Risks: A Study of Security Threats in the npm Ecosystem," USENIX Security 2019. arXiv:1902.09217
3. W. Guo et al., "An Empirical Study of Malicious Code in PyPI Ecosystem," 2023. arXiv:2309.11021
4. P. Ladisa, H. Plate, M. Martinez, O. Barais et al., "The Hitchhiker's Guide to Malicious Third-Party Dependencies," 2023. arXiv:2307.09087
5. D.-L. Vu et al., "A Study of Malware Prevention in Linux Distributions," 2024. arXiv:2411.11017
6. A. Ryan et al., "Unveiling Malicious Logic: Towards a Statement-Level Taxonomy and Dataset for Securing Python Packages," 2025. arXiv:2512.12559
7. W. Guo et al., "How Effective Are NPM Malicious Package Detectors? A Large-Scale Empirical Study," 2026. arXiv:2603.27549
8. M. Robinson et al., "Original Sin of npm: A Study on Vulnerability Propagation in JavaScript Dependency Networks," 2026. arXiv:2604.17668
9. J. Zhang et al., "Killing Two Birds with One Stone: Malicious Package Detection in NPM and PyPI using a Single Model of Malicious Behavior Sequence," 2023. arXiv:2309.02637
10. H. Samaana et al., "A Machine Learning-Based Approach For Detecting Malicious PyPI Packages," 2024. arXiv:2412.05259
11. S. T. Mehedi et al., "DySec: A Machine Learning-based Dynamic Analysis for Detecting Malicious Packages in PyPI Ecosystem," 2025. arXiv:2503.00324
12. X. Zhang et al., "Automatically Generating Rules of Malicious Software Packages via Large Language Model," IEEE/IFIP DSN 2025. arXiv:2504.17198
13. Z. Yan et al., "An LLM-based Quantitative Framework for Evaluating High-Stealthy Backdoor Risks in OSS Supply Chains," 2025. arXiv:2511.13341
14. W. Guo et al., "Cutting the Gordian Knot: Detecting Malicious PyPI Packages via a Knowledge-Mining Framework," 2026. arXiv:2601.16463
15. S. Pang et al., "PYPILINE: Malicious PyPI Package Detection via Suspicious API Knowledge and Agent Workflow," 2026. arXiv:2606.19063
16. N. Zahan, P. Burckhardt, M. Lysenko et al., "Leveraging Large Language Models to Detect npm Malicious Packages," 2024. arXiv:2403.12196
17. D.-K. Nguyen et al., "Taint-Based Code Slicing for LLMs-based Malicious NPM Package Detection," 2025. arXiv:2512.12313
18. E. Lamprou et al., "Lexo: Eliminating Stealthy Supply-Chain Attacks via LLM-Assisted Program Regeneration," 2025. arXiv:2510.14522
19. A. Ryan et al., "An Evaluation of Large Language Models for Detection of Malicious Python Packages," 2026. arXiv:2602.16304
20. T. Toda, F. Ishikawa, "CHASE: LLM Agents for Dissecting Malicious PyPI Packages," 2026. arXiv:2601.06838
21. D. Foo, J. Chua, J. Yeo, M. Y. Ang, "The Dynamics of Software Composition Analysis," 2019. arXiv:1909.00973
22. Z. Chen et al., "Exploiting Library Vulnerability via Migration Based Automating Test Generation," 2023. arXiv:2312.09564
23. G. Alexopoulos et al., "Cross-Ecosystem Vulnerability Analysis for Python Applications," 2026. arXiv:2603.18693
24. Y. Ma et al., "ReachCheck: Compositional Library-Aware Call Graph Reachability Analysis in the IDEs," ACM TOSEM, 2025. doi:10.1145/3767166
25. B. Gokkaya, L. Aniello, B. Halak, "Software supply chain: review of attacks, risk assessment strategies and security controls," 2023. arXiv:2305.14157
26. M. Tamanna, L. Williams et al., "Analyzing Challenges in Deployment of the SLSA Framework for Software Supply Chain Security," 2024. arXiv:2409.05014
27. E. O'Donoghue et al., "Software Bill of Materials in Software Supply Chain Security: A Systematic Literature Review," 2025. arXiv:2506.03507

**Data sources**

- DataDog, *malicious-software-packages-dataset* (Apache-2.0) — training corpus
- OSV.dev — vulnerability advisories
- npm registry, PyPI — benign corpus and live scanning
