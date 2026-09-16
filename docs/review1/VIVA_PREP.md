# Viva prep — questions a strict panel will ask

Answers you can give in your own words. Where an answer is "we don't do that",
say so plainly — a panel respects a known boundary far more than a bluff, and
they will find the boundary anyway.

---

## On the problem statement

**"Isn't this just antivirus for packages?"**
No. Antivirus matches signatures of known samples. Every malicious package is new
by construction — most are removed within days of being reported, so a signature
arrives after the damage. Our classifier decides from *behaviour*, so it
generalises to packages it has never seen. That is why it is trained and
evaluated rather than curated.

**"Tools like Snyk and Dependabot already exist. What's new?"**
Two things. First, they solve half the problem each — Dependabot reports known
CVEs, Socket-type tools detect malicious packages; we do both over one dependency
graph. Second, and more importantly, they report *presence*, not *reachability*.
Commercial reachability exists (Endor Labs, Snyk Reachability) but is proprietary;
the academic literature named it as the fix for alert fatigue in 2019 and a 2025
systematic review still lists false positives as a top barrier. That six-year gap
is what we targeted.

**"Why does reachability matter so much?"**
Because a report you can't act on is worse than no report. A real project shows
150–300 CVEs. Nobody triages 300 items, so they triage zero and the vulnerable
dependencies stay. On our demo, 92 advisories reduce to 3 that are actually
reachable. Three is a morning's work. Ninety-two is a backlog nobody opens.

---

## On the literature review

**"Which paper is closest to your work, and how are you different?"**
Samaana et al. 2024 (arXiv:2412.05259) — classical ML over static features for
PyPI. Three differences: we cover npm as well as PyPI; we add composite
co-occurrence signals that single-feature detectors cannot express; and we add
the entire reachability half, which no detection paper in our review does.

**"Why not use an LLM, since that's the trend?"**
We do — but only to *explain* verdicts, never to make them, and it is off by
default. The reason is in the literature: the LLM detection papers (#16, #19)
consistently report cost, latency, non-determinism and — the recurring criticism
— difficulty producing stable precision and recall. If an examiner asks "how well
does it work?", a classifier has an answer and a prompt does not.

**"Your review has papers from 2026. Are those real?"**
Yes — every one was verified against the arXiv API for title, authors and date
before citation. The list spans 2019 to 2026 with 24 of 27 from 2023 onward.

---

## On methodology — expect the hardest questions here

**"How do you know your model isn't just memorising?"**
Three defences. Splits are grouped by package name using `StratifiedGroupKFold`,
so no version of a package can appear on both sides — 1,796 distinct families
across 1,797 samples. Every reported figure is out-of-fold. And we report the
fold standard deviation (±0.006 on F1), which would be large if the model were
memorising.

**"Isn't 95% F1 suspiciously high?"**
It would be if we hadn't handled leakage — and that is the more interesting
answer. Our malicious samples are archived, so they have *no live registry
metadata*; benign samples are fetched live and have all of it. If we had left
those features in, `version_count > 0` alone would separate the classes perfectly
— the model would detect *which dataset a sample came from*, score near 1.0, and
be worthless. We zero five registry-only features for every training sample,
inside the matrix builder, so no caller can bypass it. **A feature available for
only one class in training is not a feature, it is the label.**

**"What's your baseline?"**
A rules-only weighted-sum engine over the same signals, scored on the same data:
F1 0.565 against the model's 0.950. Without that comparison, "we used machine
learning" is an assertion, not a result.

**"How does this compare to published, open-source tools — not just your own baseline?"**
The closest recent independent benchmark is Guo et al., *"How Effective Are NPM
Malicious Package Detectors? A Large-Scale Empirical Study"* (arXiv:2603.27549,
March 2026, dataset public on Figshare). They evaluate 11 tools on 6,420
malicious + 7,288 benign npm packages. **Best conventional/static tool: GuardDog
at 93.32% F1. Best overall: IntelGuard, an LLM-based tool, at 95.98% F1.** Our
model reports 94.75% F1 — ahead of every non-LLM tool in their benchmark,
0.77 points off their best LLM-based tool, without needing an LLM at inference
time. **Caveat we say out loud, not hide:** this is not a head-to-head run —
their packages, ours, and PyPI-vs-npm mix all differ. Their dataset being public
means the rigorous next step is to actually run our trained classifier on their
labelled samples and report precision/recall/F1 on *their* data directly; that
hasn't been done yet. Until then this is a same-ballpark comparison against the
strongest available open, methodologically transparent benchmark — not a
verified win.

**"Which features matter most?"**
Structural ones rank highest — and I'll be honest about why that is only partly a
real signal. Malicious samples are overwhelmingly small single-purpose droppers;
popular benign packages are large libraries. So `file_count` is doing real work
*and* reflecting a property of the corpus. A large malicious package or a tiny
legitimate utility is where the model has least evidence. That's on the model
card.

**"What did the ablation show?"**
That no single signal family is load-bearing — the largest F1 loss from removing
a family is 0.012. The honest reading is that the signal is *redundant*: a
malicious package usually trips several families at once, so removing one leaves
the others to compensate. Good robustness, but it means the ablation shows there
*isn't* a decisive group rather than identifying one.

**"Why classical ML instead of deep learning?"**
Three reasons. The dataset is ~1,800 samples, not millions — deep models overfit
at that scale. Tree ensembles give per-feature importances, so every verdict is
explainable. And it runs on a laptop with no GPU, which matters for this demo.

---

## On reachability

**"How does the call graph actually work?"**
We parse every application `.py` file into an AST, build nodes for module scopes
and function scopes, and edges for intra-application calls and imports. Entry
points are modules nothing else imports — scripts and CLI commands. Then it's a
breadth-first search from those entry points looking for a call into the
vulnerable symbol. If we find one, we return the path.

**"Can reachability be wrong?"**
Yes, and it is deliberately designed to fail in one direction. We can't resolve
dynamic dispatch, `getattr` indirection, reflection, or calls from templates.
Every uncertain case resolves to **reachable**. A false "reachable" costs an
engineer ten minutes; a false "unreachable" hides an exploitable vulnerability.
And I'd stress that "not statically reachable" is a weaker claim than "not
exploitable" — the report says so.

**"What if a package isn't imported but is still dangerous?"**
Then reachability says `NOT_IMPORTED` for its *CVEs* — but the malicious-package
detector runs on it regardless. That's why the two halves are independent. An
install-time payload doesn't need to be imported; it runs on `pip install`.

**"Show me it isn't just string matching."**
The proof path is four hops through three files:
`app → app.main → app.bootstrap → config.load_settings → yaml.load`, with file
and line at each step. The vulnerable call is three levels below the entry point
— string matching cannot produce that.

---

## On the system

**"You have real malware on your laptop. Is that safe?"**
Nothing is ever executed — there is no `pip install`, no `npm install`, no
`setup.py` invocation anywhere in the codebase. All analysis is static parsing.
Samples are stored encoded and decoded into memory only, so no antivirus
exclusion was needed and no security setting on the machine was changed.

**"Could a malicious package attack your scanner?"**
That's a real threat and we designed for it. Archive extraction rejects path
traversal, symlinks and absolute paths; there are ceilings on uncompressed size,
compression ratio, member count and per-file size, checked *before* decompression.
We cap AST parse size after a real incident — one large minified file pegged a
CPU indefinitely during the dataset build, because the per-package timeout is only
checked between files. And package names are HTML-escaped in the report because
they're attacker-controlled.

**"Why SQLite? Why not Postgres?"**
Because a demo must never fail because a service isn't running. The SQLAlchemy
layer is dialect-agnostic, so swapping is a config change.

---

## Traps to be ready for

**"Scan this package right now."** — Fine, but pick something that still exists.
If they name a taken-down typosquat, the tool reports **"Not inspected — NOT
confirmed clean"**, and that's the right answer: the package couldn't be
downloaded, so it scores zero, and reporting zero as clean would be a false
all-clear. Use `scan-sample captcha-py` for a guaranteed live demonstration on
real malware.

**"Your tool flagged `requests` as suspicious. Isn't that a false positive?"**
It scores 0.576 — *suspicious*, not malicious, and the thresholds are 0.30 and
0.60. It genuinely reads `.netrc` and its `setup.py` calls `os.system`. The model
is less confident rather than silent, which is correct for a borderline case. And
note the rules baseline called it malicious at 0.928 — that's the ML layer earning
its place.

**"What doesn't work?"** — Answer immediately, don't hedge: npm reachability is
import-level only; the curated symbol table covers ~35 packages so many advisories
land on `ASSUMED_REACHABLE`; 55 of 898 malicious samples are missed; and the
50/50 class balance is artificial, so deployment precision would be lower.

**"How much of this did you actually build?"** — Every design decision is logged
in `BUILD_LOG.md` with the alternatives that were rejected and the bugs found —
53 entries. Point at D-040: PyPI distribution names aren't import names, so
`pyyaml` searched as `pyyaml` found nothing and three critical CVEs were reported
as safe. Explaining a bug you found and fixed is the most convincing thing you can
show.

---

## Numbers to have memorised

| | |
|---|---|
| Dataset | 1,797 samples · 898 malicious · 899 benign · 1,796 families |
| Precision / Recall / F1 | 0.962 / 0.939 / 0.950 |
| PR-AUC / ROC-AUC | 0.986 / 0.980 |
| Confusion | TP 843 · FP 33 · FN 55 · TN 866 |
| Baseline F1 | 0.565 (model adds +0.385) |
| Reachability | 92 advisories → 3 reachable (97% cut) |
| Detector comparison | baseline flags 6 packages, model flags 1 |
| Features / signals | 58 features · 38 signal types · 11 groups |
| Tests | 110, fully offline |
| Papers reviewed | 27 (24 from 2023–2026) |
