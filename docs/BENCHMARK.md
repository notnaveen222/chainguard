# External benchmark: Guo et al. npm malicious package detectors (ASE 2026)

Cross-validation on our own corpus measures the model against data drawn the same
way as its training set. This benchmark measures it against someone else's data,
alongside the published tools, on identical packages.

**Source:** "How Effective Are NPM Malicious Package Detectors? A Large-Scale
Empirical Study" (arXiv:2603.27549). Replication package:
[doi.org/10.6084/m9.figshare.31869370](https://doi.org/10.6084/m9.figshare.31869370),
CC BY 4.0. 6,420+ malicious and 7,288 benign npm package versions, with each
evaluated tool's per-package verdict.

## Results (2026-09-16, deployed model)

13,436 packages analysed: 6,546 malicious, 6,890 benign. 133 benign versions are
no longer on npm; 28 malware entries could not be analysed (27 have no tarball in the archive, 1 failed to parse).
Threshold 0.60, the same as production.

| Detector | Type | Precision | Recall | F1 |
|---|---|---|---|---|
| GuardDog | rules + taint (open source) | 0.954 | 0.895 | **0.924** |
| **ChainGuard (ours)** | ML over static-analysis features | 0.918 | 0.854 | **0.885** |
| SAP XGBoost | ML (open source) | 0.952 | 0.822 | 0.883 |
| SAP Random Forest | ML (open source) | 0.999 | 0.650 | 0.788 |
| Packj (static) | rules | 0.523 | 0.987 | 0.684 |
| OSSGadget | rules | 0.521 | 0.914 | 0.664 |
| GENIE | taint analysis | 0.998 | 0.453 | 0.623 |
| SocketAI | LLM (proprietary) | 0.982 | 0.436 | 0.604 |

Other tools' figures are recomputed from their published per-package verdicts
restricted to the same packages, so they differ slightly from the paper's tables.
The paper's best system, IntelGuard (LLM + retrieval, proprietary), reports 0.960
F1; its per-package verdicts are not in the comparison above.

**Leakage check.** 33 benchmark packages share a name with our training corpus
(28 malicious, 5 benign). Excluding them gives F1 0.884; the result is not
inflated by overlap.

**Complementarity.** ChainGuard catches 272 malicious packages that GuardDog
misses; GuardDog catches 537 that ChainGuard misses. Naive combinations do not
beat GuardDog alone (either-flags: F1 0.913; both-flag: 0.895), which motivates a
learned combination rather than a rule.

Our own grouped cross-validation reports F1 0.950. The gap to 0.885 is the
expected cost of moving to independently collected data, and 0.885 is the number
to quote externally.

## Combined training (deployed model, 2026-09-17)

Neither dataset alone generalises to the other: our corpus-trained model scores
F1 0.885 on the benchmark, and a benchmark-trained model scores only 0.741 on
our npm corpus. The deployed model is therefore trained on both (15,886 samples:
7,444 malicious, 8,442 benign) with `scripts/train_combined.py` and
`scripts/train_model.py --matrix data/corpus/features_combined.csv`.

Grouped 5-fold cross-validation. Groups merge versions of a package **and**
packages with identical feature vectors, because benchmark malware contains
campaigns re-published under random names (6,546 malicious packages collapse
to 2,741 groups):

| Evaluation | Precision | Recall | F1 |
|---|---|---|---|
| Combined, overall | 0.980 | 0.939 | **0.959** |
| Benchmark packages | 0.990 | 0.938 | **0.963** |
| Our corpus | 0.967 | 0.899 | **0.931** |
| Real applications, 660 held-out packages | | | 0 malicious flags, 9 suspicious |

**How to quote this.** 0.963 is cross-validated with benchmark data in training,
so it is not directly comparable to GuardDog's off-the-shelf 0.924. The
comparable claim is the off-the-shelf table above (0.885). Running
`benchmark_guo.py score` on the deployed model now reports ~0.98, which is a
training-set score and must not be quoted.

**What else was tested** (`scripts/experiment_benchmark_models.py`, benchmark-only
grouped CV): SAP's features alone reach 0.972 and ours 0.966; combining them
gives 0.976, and adding GuardDog's verdict 0.977. SAP features are not used in
production (their extractor is file-based and the gain is about one point).

**Known false positive.** `requests@2.19.0` in the demo project scores 0.481
(suspicious): its `setup.py` calls `os.system(...)` for the maintainers' publish
command and `utils.py` reads `.netrc`. The GPT review keeps it at
suspicious/medium and asks for the `setup.py` line to be verified.

## Reproducing

The repository contains everything needed to **score** models, without any malware:

| File | Contents |
|---|---|
| `data/benchmarks/guo2026_npm_features.csv` | One row per package: key, label and ChainGuard's 58 features |
| `data/benchmarks/guo2026_npm_labels.json` | Benchmark labels |
| `data/benchmarks/guo2026_published_verdicts.json` | Other tools' per-package verdicts |

```bash
python scripts/benchmark_guo.py score
```

```bash
python scripts/benchmark_guo.py score --model path/to/other_model.joblib --threshold 0.5
```

Re-extracting features (needed only after changing the analyser) requires the raw
archive; see safety below.

## Safety: the raw dataset contains live malware

The Figshare archive holds thousands of real malicious npm packages. It is
**never committed** to this repository, and must not be:

- GitHub's acceptable use policy prohibits hosting malware for distribution, and
  the archive (4.8 GB) exceeds Git LFS quotas.
- Everyone who pulled it would receive the malware, and the repo folder may be
  excluded from antivirus scanning on developer machines.

If you re-extract features:

1. Download to a directory **outside** the repository and outside any antivirus
   exclusion (default `C:/Benchmarks`, or set `CHAINGUARD_BENCHMARK_DIR`).
2. Do not extract the zip, open its files, or run `npm` or `node` in that directory.
   `benchmark_guo.py` reads tarballs from the zip into memory and parses them only.
3. Delete the archive when finished.

```bash
python scripts/benchmark_guo.py download-benign --labels C:/Benchmarks/labels.json
```

```bash
python scripts/benchmark_guo.py featurize --zip C:/Benchmarks/NPMStudy_full.zip --labels C:/Benchmarks/labels.json
```

`labels.json` is `data/benchmarks/guo2026_npm_labels.json`.
