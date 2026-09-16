"""Augment the benign corpus with real dependency-tree packages, and evaluate.

Why
---
The original benign samples are popular top-level packages, which are large:
only ~12% are as small as the median package in a real application's
dependency tree, against ~45% of malicious samples. The classifier therefore
learned "small package => suspicious", and on a real 750-package Next.js app it
flagged ordinary tiny utilities (`get-nonce`, `@radix-ui/rect`, `leac`, ...).
Removing size/metadata features did not fix it (see experiment_features.py):
the bias is in the *sample*, so the fix is a representative benign sample.

Method
------
* Training augmentation: every analysable package from the scan histories of
  real projects passed with --train-scan (legitimate published dependencies),
  added as benign rows grouped by package name.
* Held-out evaluation: packages from *different* projects' lockfiles
  (--test-lock), with every package name that appears in training removed, so no
  test package was ever seen. Each flag there is a false positive.
* Cross-validation is re-run on the augmented matrix with the same grouped
  5-fold protocol, so benchmark numbers stay comparable and honest.

Outputs data/corpus/features_augmented.csv and a JSON report.

Run:
  python scripts/augment_benign.py --train-scan 8b633133cf62 --train-scan 0182205067e2 \
      --test-lock C:/HealthPIlotWebApp/backend/package-lock.json \
      --test-lock C:/HealthPIlotWebApp/mobile-app/package-lock.json
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np  # noqa: E402

from chainguard.analysis.features import FEATURE_NAMES  # noqa: E402
from chainguard.config import get_settings  # noqa: E402
from chainguard.ml.train import Dataset, cross_validate, load_dataset, train_final  # noqa: E402
from chainguard.models.db import load_scan  # noqa: E402
from evaluate_realworld import featurize  # noqa: E402

MALICIOUS, SUSPICIOUS = 0.60, 0.30


def lockfile_packages(path: Path) -> list[tuple[str, str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = set()
    for key, meta in (data.get("packages") or {}).items():
        if not key or "node_modules/" not in key or meta.get("link") or not meta.get("version"):
            continue
        name = key.rsplit("node_modules/", 1)[1]
        out.add(("npm", name, meta["version"]))
    return sorted(out)


def flags(model, X: np.ndarray, keys: list[str]) -> dict[str, list]:
    scores = model.predict_proba(X)[:, 1]
    mal = sorted(((keys[i], round(float(s), 3)) for i, s in enumerate(scores) if s >= MALICIOUS), key=lambda x: -x[1])
    sus = sorted(((keys[i], round(float(s), 3)) for i, s in enumerate(scores) if SUSPICIOUS <= s < MALICIOUS), key=lambda x: -x[1])
    return {"malicious": mal, "suspicious": sus}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train-scan", action="append", required=True)
    parser.add_argument("--test-lock", action="append", required=True, type=Path)
    parser.add_argument("--max-test", type=int, default=700)
    args = parser.parse_args()
    corpus = get_settings().corpus_dir

    train_pkgs: set[tuple[str, str, str]] = set()
    for scan_id in args.train_scan:
        for p in (load_scan(scan_id) or {}).get("packages") or []:
            if p.get("files_analysed"):
                train_pkgs.add((p["ecosystem"], p["name"], p["version"]))
    train_names = {(e, n) for e, n, _ in train_pkgs}

    test_pkgs: set[tuple[str, str, str]] = set()
    for lock in args.test_lock:
        test_pkgs.update(p for p in lockfile_packages(lock) if (p[0], p[1]) not in train_names)
    test_list = sorted(test_pkgs)[: args.max_test]
    print(f"train augmentation: {len(train_pkgs)} packages | held-out test: {len(test_list)} name-disjoint packages")

    train_vec = asyncio.run(featurize(sorted(train_pkgs)))
    test_vec = asyncio.run(featurize(test_list))
    print(f"featurized: train {len(train_vec)}, test {len(test_vec)}")

    base = load_dataset(corpus / "features.csv")
    keys_train = list(train_vec)
    aug = Dataset(
        X=np.vstack([base.X, np.asarray([train_vec[k] for k in keys_train], dtype=float)]),
        y=np.concatenate([base.y, np.zeros(len(keys_train), dtype=int)]),
        groups=np.concatenate([base.groups, np.asarray([f"rw:{k.split('|')[0]}:{k.split('|')[1]}" for k in keys_train])]),
        sample_ids=base.sample_ids + [f"realworld:{k}" for k in keys_train],
        feature_names=base.feature_names,
    )

    with (corpus / "features_augmented.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["sample_id", "label", "group", *FEATURE_NAMES])
        for sid, label, group, row in zip(aug.sample_ids, aug.y, aug.groups, aug.X):
            writer.writerow([sid, int(label), group, *[repr(float(v)) for v in row]])

    keys_test = list(test_vec)
    X_test = np.asarray([test_vec[k] for k in keys_test], dtype=float)

    report = {"train_augmentation": len(keys_train), "held_out_packages": len(keys_test)}
    print(f"\n{'model':<22} {'CV prec':>8} {'recall':>7} {'f1':>7} {'pr_auc':>7} | {'held-out FP mal':>15} {'sus':>5}")
    for label, dataset in (("original corpus", base), ("augmented benign", aug)):
        metrics, _ = cross_validate(dataset)
        model, _ = train_final(dataset)
        f = flags(model, X_test, keys_test)
        report[label] = {"cv": {k: metrics[k] for k in ("precision", "recall", "f1", "roc_auc", "pr_auc", "confusion_matrix")}, "held_out": f}
        print(f"{label:<22} {metrics['precision']:>8.4f} {metrics['recall']:>7.4f} {metrics['f1']:>7.4f} {metrics['pr_auc']:>7.4f} | "
              f"{len(f['malicious']):>15} {len(f['suspicious']):>5}")

    (corpus / "augment_report.json").write_text(json.dumps(report, indent=2))
    print(f"\nwrote {corpus / 'features_augmented.csv'} and augment_report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
