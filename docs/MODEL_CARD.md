# Model card — ChainGuard malicious-package classifier

Generated from a training run on 2026-08-18. Regenerate with
`python scripts/train_model.py`; the machine-readable version is written to
`data/models/model_card.json` and served at `GET /api/model`.

---

## 1. What it does

Given a package's static-analysis feature vector (58 features, schema v1), it
outputs a calibrated probability that the package is malicious. Above 0.60 it is
reported as **malicious**; between 0.30 and 0.60 as **suspicious**; below that as
**benign**.

It is the system of record for the malicious-package half of ChainGuard. The
optional LLM layer only renders its verdict as prose and never changes it.

## 2. Training data

| | |
|---|---|
| Samples | 1,797 (898 malicious, 899 benign) |
| Package families | 1,796 distinct |
| Ecosystems | PyPI 898 · npm 899 |
| Malicious source | [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (Apache-2.0) |
| Benign source | Live npm and PyPI registries, sampled from the popular-package list with a fixed seed |

Full provenance and limitations: [DATASET.md](DATASET.md).

## 3. Results

Grouped 5-fold cross-validation (`StratifiedGroupKFold` by package name). Every
figure is from **out-of-fold** predictions, so no sample was scored by a model
that had seen it.

| Metric | Model | Rules baseline | Δ |
|---|---|---|---|
| Precision | **0.9623** ± 0.0119 | 0.8421 | +0.120 |
| Recall | **0.9388** ± 0.0113 | 0.4276 | +0.511 |
| F1 | **0.9504** ± 0.0064 | 0.5650 | **+0.385** |
| ROC-AUC | **0.9803** | — | — |
| PR-AUC | **0.9856** | 0.7191 | +0.267 |

Confusion matrix (out-of-fold, n = 1,797):

|  | Predicted benign | Predicted malicious |
|---|---|---|
| **Actually benign** | 866 | 33 |
| **Actually malicious** | 55 | 843 |

**55 false negatives** is the number that matters. A wrongly flagged package
costs a developer a few minutes; a missed one ships malware into production.

## 4. Effect in practice

On `demo/vulnerable-app`, seven ordinary PyPI packages pinned to old versions:

| Detector | Flagged |
|---|---|
| Rules baseline | 4 malicious, 2 suspicious |
| Trained model | 1 suspicious (`requests` at 0.576) |

The baseline flags `pillow`, `lxml`, `urllib3` and `flask` because large mature
libraries genuinely do call `eval`, spawn processes and read config paths. The
model has learned that those behaviours are unremarkable at that scale. This is
the concrete case for the ML layer, and it is why the `webpack` false positive
was left in the baseline rather than tuned away (BUILD_LOG D-023).

`requests` at 0.576 sits between the thresholds — reported as *suspicious*, not
*malicious*. It reads `.netrc` and its `setup.py` calls `os.system`. The model is
less confident rather than silent, which is the correct behaviour for a
genuinely borderline case.

On a real malicious sample (`captcha-py`, a PyPI credential stealer): **0.994**.

## 5. Ablation

F1 lost when each signal family is zeroed and the model retrained:

| Family | F1 lost |
|---|---|
| structure | 0.012 |
| metadata | 0.007 |
| obfuscation | 0.006 |
| credentials | 0.005 |
| process | 0.004 |
| dynamic_execution | 0.003 |
| install_execution | 0.003 |
| aggregate | 0.002 |
| typosquat | 0.002 |
| exfiltration | 0.001 |
| network | 0.000 |

**No single family is load-bearing.** The largest loss is 0.012 F1. The honest
reading is that the signal is *redundant*: a malicious package usually trips
several families at once, so removing one leaves the others to compensate. That
is a good robustness property, and it also means this ablation does not identify
a single decisive feature group — it shows there isn't one.

## 6. Known limitations

- **Survivorship bias.** Training malware is malware that was *caught*. Samples
  sophisticated enough to evade detection are absent by construction, so
  real-world recall is likely below the 0.939 reported here.
- **Class balance is artificial.** The corpus is ~50/50; a real registry is
  closer to 1-in-10,000. Precision at deployment scale would be lower, which is
  why PR-AUC leads over accuracy throughout.
- **Structural features rank highest.** `file_count` and `total_bytes` are among
  the top features because malicious samples are overwhelmingly small
  single-purpose droppers while popular benign packages are large libraries.
  Real signal, but partly a corpus property — a large malicious package or a tiny
  legitimate utility sits where the model has little evidence.
- **The baseline score is itself a feature.** The model is a stacked learner over
  the rules engine rather than an independent alternative, so "model vs.
  baseline" should be read as what the learned layer adds on top. Removing the
  aggregate family costs only 0.002 F1, so the model is not merely leaning on it.
- **Registry metadata is excluded from training** to prevent label leakage
  (DATASET.md §3), so the model cannot use "published yesterday" as evidence even
  though that is genuinely informative at scan time.
- **Temporal skew.** Malicious samples are historical (mostly 2022–2024); benign
  samples are current.

## 7. Reproducing

```bash
python scripts/build_dataset.py --malicious 450 --benign 450
```

```bash
python scripts/train_model.py --folds 5
```

Seeds are fixed (`RANDOM_STATE = 20260817`), sample selection is seeded, and the
popular-package list is committed, so a rebuild reproduces the same dataset and
the same split. Charts are written to `data/models/`.
