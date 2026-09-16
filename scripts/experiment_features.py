"""Compare classifier variants that ignore "shortcut" feature groups.

The deployed model over-flagged small, legitimate npm utilities on a real
750-package project. The flagged packages had no critical/high code signals;
their scores came from package size and in-archive metadata (repository link,
description), which separate the training corpora (small archived malware vs.
large popular packages) rather than malicious from benign behaviour.

This script measures, with the same grouped cross-validation as training, what
each candidate exclusion costs on the benchmark. Real-world false positives are
measured separately by re-scanning a real project with the chosen model.

Run:  python scripts/experiment_features.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import numpy as np  # noqa: E402

from chainguard.config import get_settings  # noqa: E402
from chainguard.ml.train import Dataset, cross_validate, load_dataset  # noqa: E402

METADATA_SHORTCUTS = ["has_repository", "description_length", "has_empty_description", "dependency_count"]
SIZE_SHORTCUTS = ["file_count", "total_bytes", "avg_file_bytes", "source_file_count", "source_file_ratio"]

VARIANTS = {
    "current (all features)": [],
    "no metadata shortcuts": METADATA_SHORTCUTS,
    "no size shortcuts": SIZE_SHORTCUTS,
    "no metadata + no size": METADATA_SHORTCUTS + SIZE_SHORTCUTS,
}


def zeroed(dataset: Dataset, names: list[str]) -> Dataset:
    X = dataset.X.copy()
    for name in names:
        X[:, dataset.feature_names.index(name)] = 0.0
    return Dataset(X=X, y=dataset.y, groups=dataset.groups,
                   sample_ids=dataset.sample_ids, feature_names=dataset.feature_names)


def main() -> int:
    dataset = load_dataset(get_settings().corpus_dir / "features.csv")
    print(f"{len(dataset.y)} samples ({dataset.n_malicious} malicious, {dataset.n_benign} benign)\n")
    print(f"{'variant':<26} {'precision':>9} {'recall':>7} {'f1':>7} {'pr_auc':>7} {'FP':>4} {'FN':>4}")
    for label, names in VARIANTS.items():
        metrics, _ = cross_validate(zeroed(dataset, names))
        cm = metrics["confusion_matrix"]
        print(f"{label:<26} {metrics['precision']:>9.4f} {metrics['recall']:>7.4f} {metrics['f1']:>7.4f} "
              f"{metrics['pr_auc']:>7.4f} {cm['false_positive']:>4} {cm['false_negative']:>4}")
    return 0


if __name__ == "__main__":
    np.set_printoptions(suppress=True)
    raise SystemExit(main())
