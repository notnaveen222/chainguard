# Demo script

A ten-minute walkthrough for a review panel. Every command is copy-pasteable, and
each section says **what to point at** and **what question it answers**.

---

## 0. Before the review (once)

```bash
.venv\Scripts\activate
```

Confirm the test suite is green — it runs offline and takes under a second:

```bash
python -m pytest backend/tests -q
```

Start the backend:

```bash
python -m uvicorn chainguard.api.app:app --port 8000
```

And in a second terminal, the dashboard:

```bash
cd frontend && npm run dev
```

Open <http://localhost:5173>.

> **Fallback if anything breaks:** the CLI needs neither server nor browser and
> produces the same results. Skip to section 4.

---

## 1. The problem (30 seconds, no tooling)

> "A typical project pulls in hundreds of dependencies. Two things can go wrong:
> one of them may be *deliberately malicious*, and many carry *known
> vulnerabilities*. Existing tools report 200+ CVEs on a real project, which is
> why nobody fixes any of them. ChainGuard addresses both — and for the second,
> it works out which CVEs actually matter."

---

## 2. Malicious package detection (2 minutes)

Use a **real** malicious package from the research dataset. Live typosquats are
removed from the registries within days of being reported, so scanning one by
name finds nothing — the package is gone. The archived samples are both more
reliable to demo and more honest: these genuinely attacked users.

```bash
python -m chainguard scan-sample captcha-py
```

**Point at:**

- Score **1.000**, 20 signals, and the sample's provenance line
  (`DataDog/malicious-software-packages-dataset, Apache-2.0`).
- The evidence, which tells the whole story of the attack in four lines:
  **MetaMask extension ID**, **browser credential store** (`/Login Data`),
  **Discord webhook**, and all of it in `setup.py` — so it runs on
  `pip install`, before the developer executes anything.
- The two **composite** signals: `EXFIL_CREDENTIALS_TO_NETWORK` and
  `EXFIL_ON_INSTALL`. Make the point that reading credentials is unremarkable
  and making a network call is unremarkable — *doing both in one file* is what
  makes it conclusive, and no individual detector can see that.

To browse what else is in the vault:

```bash
python -m chainguard scan-sample
```

**Say this:** the samples are stored encoded on disk and decoded into memory
only. Nothing is ever executed — all analysis is static parsing.

Then scan a legitimate package to show it is *not* flagged:

```bash
python -m chainguard scan-package express --ecosystem npm
```

> **If asked "does it just look for known bad names?"** — no. Name similarity is
> 4 of 58 features. Show the Model tab's feature-importance chart.

> **If asked to scan a live typosquat** — try it (`scan-package reqeusts`). It
> reports **"Not inspected — NOT confirmed clean"**, because the package has been
> taken down. That is deliberate: a package that could not be downloaded scores
> zero, and reporting that as clean would be the most dangerous possible output.

---

## 3. Reachability analysis — the core contribution (4 minutes)

This is the part to spend time on.

In the dashboard, choose **Project directory**:

```
D:\college-project\demo\vulnerable-app
```

**Point at, in order:**

1. **The headline band.** "92 advisories reported → 3 actually reachable. 97%
   ruled out." That ratio is the project's central empirical claim.

2. **The vulnerability table, filtered to "Reachable".** Expand the PyYAML row.
   Show the **proof path**:

   ```
   app → app.main → app.bootstrap → config.load_settings → yaml.load
   ```

   with a file and line for every step. This is a real call-graph traversal, not
   a string match — the vulnerable call is three levels below the entry point.

3. **Switch the filter to "Not reachable".** Show that each one carries a
   *reason*: `pillow` is never imported; `jinja2` is imported but its vulnerable
   API is never called. Emphasise: these are **de-prioritised, not dismissed**.

4. **The remediation plan.** Point out that `pyyaml` (3 fixes, all reachable) is
   ranked **above** `pillow` (56 fixes, none reachable). Ordering by raw count
   would invert that and send the developer to fix the wrong thing first.

---

## 4. Same result, no browser (CLI fallback)

```bash
python -m chainguard scan-project demo\vulnerable-app
```

```bash
python -m chainguard scan-package reqeusts --ecosystem PyPI
```

---

## 5. "How do you know it works?" (3 minutes)

Open the **Model & evaluation** tab.

**The headline numbers**, from grouped 5-fold CV over 1,797 real packages:
precision **0.962**, recall **0.939**, F1 **0.950**, PR-AUC **0.986** — against a
rules baseline of F1 **0.565**.

**The most persuasive single demonstration** is the before/after on the demo
project. The rules baseline flags six packages (`pillow`, `requests`, `lxml`,
`urllib3`, `flask`, `jinja2`); the trained model flags **one**. Large mature
libraries genuinely do call `eval`, spawn processes and read config paths — the
model has learned that this is unremarkable at that scale, and a weighted-sum
rules engine cannot.

**Point at:**

- **Precision / recall / F1 / PR-AUC**, with fold standard deviations.
- **Confusion matrix**, and explain that false negatives are the expensive error:
  a wrongly flagged package costs a developer minutes, a missed one ships malware.
- **Model vs. rules baseline.** The baseline is a weighted-sum rules engine over
  the same signals, scored on the same data. Without this comparison, "we used
  machine learning" would be an assertion rather than a result.
- **Ablation chart** — and say the honest thing about it: no single family is
  load-bearing (the largest loss is 0.012 F1). A malicious package usually trips
  several families at once, so removing one leaves the others to compensate.
  That is good robustness, and it also means the ablation shows there *isn't* a
  single decisive feature group rather than identifying one.

**Then state the methodology unprompted**, because it is the strongest thing to
volunteer:

> "Splits are grouped by package name, so different versions of the same package
> can't appear on both sides. And five registry-metadata features are zeroed
> during training — the malicious samples are archived so they have no live
> registry data, and if I'd left those features in, the model would have learned
> to detect *which dataset a sample came from* rather than whether it's
> malicious. It would have scored near-perfectly and been worthless."

---

## 6. Questions to expect, and honest answers

**"Is this trained on real malware?"**
Yes — 898 real malicious packages from DataDog's published research dataset
(Apache-2.0), samples that were genuinely caught attacking users, balanced
against 899 real packages downloaded live from npm and PyPI. They are stored
encoded on disk and never executed.

**"How do you know the model isn't just memorising the dataset?"**
Splits are grouped by package name, so no version of a package can appear on
both sides, and every reported figure is out-of-fold. There are 1,796 distinct
package families across 1,797 samples.

**"Are there false negatives?"**
55 of 898 malicious samples were missed. That is the number that matters most,
and it is on the model card rather than buried — a wrongly flagged package costs
a developer minutes, a missed one ships malware.

**"Isn't running malware on your laptop dangerous?"**
Nothing is ever executed. All analysis is static parsing of source text — no
`pip install`, no `npm install`, no `setup.py`. Samples are stored encoded, so no
antivirus exclusion was needed and no security setting on the machine was
changed.

**"What about false positives?"**
Real, and measured rather than hidden. Show `BUILD_LOG.md` D-022: seven
systematic false positives found by running against real packages, each traced to
a cause and fixed. `webpack` still trips the *rules baseline* — and that is left
in deliberately, because it is exactly what the ML layer exists to fix.

**"Can reachability be wrong?"**
Yes, and it is designed to fail in the safe direction. It cannot resolve dynamic
dispatch, `getattr` indirection, or reflection. Every uncertain case resolves to
**reachable**. "Not statically reachable" is a weaker claim than "not
exploitable", and the report says so.

**"Why not use an LLM for the detection?"**
Because there is no way to report precision and recall for a prompt. The
classifier is the system of record precisely because it can be measured. There
*is* an LLM explanation layer, but it is off by default and the system is fully
functional without it.

**"What's not done?"**
npm reachability is import-level only — full JavaScript call-graph construction
across dynamic `require`, bundlers and monkey-patching is a research problem, and
attempting it would have produced something that looks like reachability analysis
and quietly returns wrong answers.

---

## 7. If something goes wrong live

| Symptom | Do this |
|---|---|
| Dashboard shows "backend unreachable" | Restart uvicorn; the dashboard reconnects on the next action |
| Scan is slow on first run | The registry cache is cold. Re-run the same scan — it will be seconds |
| Model tab says "no trained model" | Scans still work on the rules baseline; say so and move on |
| Network is down | Run the test suite instead — 91 tests, fully offline, under a second |
