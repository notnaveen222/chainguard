"""Can we build a better detector on top of SAP, ChainGuard and GuardDog?

All experiments use the Guo et al. npm benchmark (docs/BENCHMARK.md) and are
restricted to the packages every source covers, so numbers are comparable.

Reference rows (no training on the benchmark):
  * SAP XGBoost as published, ChainGuard as deployed, GuardDog as published.

Learned rows (grouped 5-fold cross-validation on the benchmark, grouped by
package name so no version of a package is on both sides of a split):
  * SAP features only, ChainGuard features only, both, and both + GuardDog's
    verdict as one extra input.

Cross-validated rows are trained on benchmark-distribution data, so they are
compared with each other; they answer "which inputs carry the signal", not
"which off-the-shelf tool is best".

Inputs: data/benchmarks/guo2026_npm_features.csv, guo2026_published_verdicts.json,
and SAP's extracted features for the benchmark (from the benchmark archive,
NPMStudy/Tools/sap/scripts/feature_extraction/*_npm_feature_extracted.csv).

Run:  python scripts/experiment_benchmark_models.py --sap-dir C:/Benchmarks/sap_guo
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from chainguard.analysis.features import FEATURE_NAMES  # noqa: E402


def load_ours() -> tuple[dict[str, np.ndarray], dict[str, int]]:
    X, y = {}, {}
    with (REPO / "data/benchmarks/guo2026_npm_features.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            X[row["key"]] = np.array([float(row[f]) for f in FEATURE_NAMES])
            y[row["key"]] = int(row["label"])
    return X, y


def load_sap(sap_dir: Path) -> tuple[dict[str, np.ndarray], list[str]]:
    X: dict[str, np.ndarray] = {}
    columns: list[str] = []
    for name in ("malware_npm_feature_extracted.csv", "benign_npm_feature_extracted.csv"):
        with (sap_dir / name).open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            cols = [c for c in reader.fieldnames if c not in ("Package Name", "repository")]
            columns = columns or cols
            for row in reader:
                key = row["Package Name"].replace("$$", "/")
                values = []
                for c in columns:
                    try:
                        values.append(float(row.get(c) or 0))
                    except ValueError:
                        values.append(0.0)
                X[key] = np.array(values)
    return X, columns


def report(label: str, y: np.ndarray, pred: np.ndarray) -> dict[str, float]:
    m = {
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
    }
    print(f"{label:<44} {m['precision']:>9.4f} {m['recall']:>7.4f} {m['f1']:>7.4f}")
    return m


def grouped_cv(X: np.ndarray, y: np.ndarray, groups: np.ndarray, threshold: float = 0.5) -> np.ndarray:
    oof = np.zeros(len(y))
    for train, test in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=20260917).split(X, y, groups):
        model = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.06, random_state=20260917)
        model.fit(X[train], y[train])
        oof[test] = model.predict_proba(X[test])[:, 1]
    return (oof >= threshold).astype(int)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sap-dir", type=Path, required=True)
    args = parser.parse_args()

    ours_X, labels = load_ours()
    sap_X, sap_cols = load_sap(args.sap_dir)
    published = json.loads((REPO / "data/benchmarks/guo2026_published_verdicts.json").read_text())
    guarddog, sap_pub = published["guarddog"], published["sap_XGB"]

    keys = sorted(k for k in ours_X if k in sap_X and k in guarddog and k in sap_pub)
    y = np.array([labels[k] for k in keys])
    groups = np.array([k.rsplit("/", 1)[0] for k in keys])
    O = np.vstack([ours_X[k] for k in keys])
    S = np.vstack([sap_X[k] for k in keys])
    G = np.array([[guarddog[k]] for k in keys], dtype=float)
    print(f"{len(keys)} packages covered by every source ({int(y.sum())} malicious, {int(len(y) - y.sum())} benign); "
          f"{O.shape[1]} ChainGuard + {S.shape[1]} SAP features\n")

    print(f"{'detector':<44} {'precision':>9} {'recall':>7} {'F1':>7}")
    print("-- off the shelf (no training on the benchmark)")
    report("SAP XGBoost (published verdicts)", y, np.array([sap_pub[k] for k in keys]))
    deployed = joblib.load(REPO / "data/models/classifier.joblib")
    report("ChainGuard (deployed model, t=0.60)", y, (deployed.predict_proba(O)[:, 1] >= 0.6).astype(int))
    report("GuardDog (published verdicts)", y, G[:, 0].astype(int))

    print("-- grouped 5-fold CV on the benchmark")
    results = {
        "sap_features": report("SAP features", y, grouped_cv(S, y, groups)),
        "chainguard_features": report("ChainGuard features", y, grouped_cv(O, y, groups)),
        "both": report("ChainGuard + SAP features", y, grouped_cv(np.hstack([O, S]), y, groups)),
        "both_guarddog": report("ChainGuard + SAP + GuardDog verdict", y, grouped_cv(np.hstack([O, S, G]), y, groups)),
    }
    (REPO / "data/benchmarks/experiment_results.json").write_text(json.dumps(
        {"packages": len(keys), "cv": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
