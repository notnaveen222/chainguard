"""Training and evaluation of the malicious-package classifier.

Methodology, and why each choice is made
----------------------------------------
**Grouped splitting.** Splits are grouped by package name via
``StratifiedGroupKFold``, so different versions of one package — and repeat
uploads from one attack campaign — never land on both sides. Random splitting
would let a near-duplicate of a test sample sit in training, inflating every
score. This single choice is the difference between an honest number and a
flattering one.

**Precision and recall lead, not accuracy.** In deployment the class balance is
extreme: malicious packages are a tiny fraction of a registry. Accuracy is
uninformative there — always predicting "benign" scores well and detects nothing.
PR-AUC is the headline metric.

**Calibration.** The reported probability is calibrated so that "0.8" means
something close to "80% of packages scoring this are malicious". An uncalibrated
tree ensemble produces scores that order correctly but cannot be read as
confidence, which matters because the UI shows the number to a human.

**Two comparisons, both required.** Against a rules-only baseline (does ML earn
its place?) and against feature-group ablations (which signals carry the model?).
A classifier reported without a baseline is an assertion, not a result.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedGroupKFold

from chainguard.analysis.features import FEATURE_GROUPS, FEATURE_NAMES, SCHEMA_VERSION
from chainguard.logging_setup import get_logger
from chainguard.ml.model import ModelMetadata

logger = get_logger(__name__)

RANDOM_STATE = 20260817


@dataclass
class Dataset:
    """A loaded feature matrix."""

    X: np.ndarray
    y: np.ndarray
    groups: np.ndarray
    sample_ids: list[str]
    feature_names: list[str]

    @property
    def n_malicious(self) -> int:
        return int(self.y.sum())

    @property
    def n_benign(self) -> int:
        return int(len(self.y) - self.y.sum())


def load_dataset(path: Path) -> Dataset:
    """Read the feature matrix written by ``scripts/build_dataset.py``."""
    rows: list[list[float]] = []
    labels: list[int] = []
    groups: list[str] = []
    sample_ids: list[str] = []

    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        feature_names = header[3:]

        if feature_names != FEATURE_NAMES:
            raise ValueError(
                "Feature matrix columns do not match the current schema. "
                "Rebuild the dataset with scripts/build_dataset.py."
            )

        for row in reader:
            if len(row) != len(header):
                continue
            sample_ids.append(row[0])
            labels.append(int(row[1]))
            groups.append(row[2])
            rows.append([float(v) for v in row[3:]])

    return Dataset(
        X=np.asarray(rows, dtype=float),
        y=np.asarray(labels, dtype=int),
        groups=np.asarray(groups),
        sample_ids=sample_ids,
        feature_names=feature_names,
    )


def _metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5) -> dict[str, Any]:
    """Compute the full metric set for one set of predictions."""
    y_pred = (y_prob >= threshold).astype(int)
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()

    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4) if len(set(y_true)) > 1 else None,
        "pr_auc": round(float(average_precision_score(y_true, y_prob)), 4)
        if len(set(y_true)) > 1
        else None,
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
        "threshold": threshold,
        "support": {"benign": int((y_true == 0).sum()), "malicious": int((y_true == 1).sum())},
    }


def _build_estimator(algorithm: str) -> Any:
    if algorithm == "random_forest":
        return RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
    return GradientBoostingClassifier(
        n_estimators=250,
        learning_rate=0.08,
        max_depth=3,
        subsample=0.9,
        random_state=RANDOM_STATE,
    )


def cross_validate(
    dataset: Dataset, algorithm: str = "gradient_boosting", n_splits: int = 5
) -> tuple[dict[str, Any], np.ndarray]:
    """Grouped, stratified cross-validation.

    Returns aggregate metrics and the out-of-fold predictions. Out-of-fold
    predictions are used for every reported figure, so no sample is ever scored
    by a model that saw it during training.
    """
    n_groups = len(set(dataset.groups))
    n_splits = max(2, min(n_splits, n_groups, int(dataset.y.sum()), int((dataset.y == 0).sum())))

    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)
    out_of_fold = np.zeros(len(dataset.y), dtype=float)
    per_fold: list[dict[str, Any]] = []

    for fold, (train_index, test_index) in enumerate(
        splitter.split(dataset.X, dataset.y, groups=dataset.groups), start=1
    ):
        estimator = _build_estimator(algorithm)
        estimator.fit(dataset.X[train_index], dataset.y[train_index])
        probabilities = estimator.predict_proba(dataset.X[test_index])[:, 1]
        out_of_fold[test_index] = probabilities

        fold_metrics = _metrics(dataset.y[test_index], probabilities)
        per_fold.append(fold_metrics)
        logger.info(
            "  fold %d/%d: precision=%.3f recall=%.3f f1=%.3f pr_auc=%s",
            fold, n_splits,
            fold_metrics["precision"], fold_metrics["recall"], fold_metrics["f1"],
            fold_metrics["pr_auc"],
        )

    aggregate = _metrics(dataset.y, out_of_fold)
    aggregate["n_splits"] = n_splits
    aggregate["per_fold"] = per_fold
    aggregate["fold_std"] = {
        metric: round(float(np.std([f[metric] for f in per_fold])), 4)
        for metric in ("precision", "recall", "f1")
    }
    return aggregate, out_of_fold


def evaluate_baseline(dataset: Dataset) -> dict[str, Any]:
    """Score the rules-only baseline on the same data.

    ``rules_baseline_score`` is already a feature column, computed by the same
    engine at analysis time, so this is a like-for-like comparison rather than a
    re-implementation.
    """
    try:
        index = dataset.feature_names.index("rules_baseline_score")
    except ValueError:
        return {}
    scores = dataset.X[:, index]
    metrics = _metrics(dataset.y, scores)
    metrics["note"] = "Weighted-sum rules engine with no learning; see analysis/signals.py"
    return metrics


def run_ablation(
    dataset: Dataset, algorithm: str = "gradient_boosting", n_splits: int = 5
) -> dict[str, Any]:
    """Retrain with each feature group zeroed, to measure its contribution.

    Zeroing rather than dropping columns keeps the feature count constant, so
    every ablated model is directly comparable to the full one.
    """
    results: dict[str, Any] = {}
    for group, names in FEATURE_GROUPS.items():
        indices = [dataset.feature_names.index(n) for n in names if n in dataset.feature_names]
        if not indices:
            continue

        ablated = Dataset(
            X=dataset.X.copy(),
            y=dataset.y,
            groups=dataset.groups,
            sample_ids=dataset.sample_ids,
            feature_names=dataset.feature_names,
        )
        ablated.X[:, indices] = 0.0

        metrics, _ = cross_validate(ablated, algorithm=algorithm, n_splits=n_splits)
        results[group] = {
            "f1": metrics["f1"],
            "pr_auc": metrics["pr_auc"],
            "recall": metrics["recall"],
            "precision": metrics["precision"],
        }
        logger.info("  ablate %-20s f1=%.4f (removed %d features)", group, metrics["f1"], len(indices))

    return results


def train_final(
    dataset: Dataset, algorithm: str = "gradient_boosting"
) -> tuple[Any, list[tuple[str, float]]]:
    """Fit the deployed model on all data, with probability calibration."""
    base = _build_estimator(algorithm)
    base.fit(dataset.X, dataset.y)

    # strict=True: a length mismatch here would silently mislabel every feature
    # importance, producing a chart that looks fine and is entirely wrong.
    importances = sorted(
        zip(dataset.feature_names, base.feature_importances_, strict=True),
        key=lambda item: -item[1],
    )
    importances = [(name, round(float(value), 6)) for name, value in importances]

    # Calibrate with grouped folds so calibration never sees a package family it
    # was fitted on.
    n_groups = len(set(dataset.groups))
    n_splits = max(2, min(3, n_groups, int(dataset.y.sum()), int((dataset.y == 0).sum())))
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)
    folds = list(splitter.split(dataset.X, dataset.y, groups=dataset.groups))

    calibrated = CalibratedClassifierCV(_build_estimator(algorithm), method="isotonic", cv=folds)
    calibrated.fit(dataset.X, dataset.y)

    return calibrated, importances


def build_metadata(
    dataset: Dataset,
    algorithm: str,
    cv_metrics: dict[str, Any],
    baseline_metrics: dict[str, Any],
    ablation: dict[str, Any],
    importances: list[tuple[str, float]],
    holdout_metrics: Optional[dict[str, Any]] = None,
) -> ModelMetadata:
    notes = [
        "Splits are grouped by package name (StratifiedGroupKFold): different "
        "versions of one package, and repeat uploads from one campaign, never "
        "appear on both sides of a split.",
        "All reported figures come from out-of-fold predictions, so no sample was "
        "scored by a model that had seen it.",
        "Five registry-only features (age_days, version_count, maintainer_count, "
        "is_single_version, is_very_new) are zeroed in training to prevent label "
        "leakage — archived malicious samples have no live registry metadata "
        "while benign samples do. See BUILD_LOG D-032.",
        "Malicious samples: DataDog/malicious-software-packages-dataset (Apache-2.0). "
        "Benign samples: real packages from the live npm and PyPI registries.",
        "PR-AUC leads over accuracy: in deployment the class balance is extreme, "
        "and a model predicting 'benign' always would score high accuracy while "
        "detecting nothing.",
        "Structural features (file_count, total_bytes, source_file_count) rank "
        "highly because malicious samples are overwhelmingly small single-purpose "
        "droppers while popular benign packages are large libraries. This is a real "
        "signal, but it is partly a property of the corpus: a large malicious "
        "package, or a tiny legitimate utility, sits where the model has little "
        "evidence. The behavioural features are what should generalise, and the "
        "ablation study measures how much work each family is doing.",
        "The rules-baseline score is itself one of the features, so the model "
        "is a stacked learner over the rules engine rather than an independent "
        "alternative to it. The 'model vs. baseline' comparison should therefore "
        "be read as 'what the learned layer adds on top of the rules', not as two "
        "unrelated detectors competing. The 'aggregate' row of the ablation study "
        "measures exactly how much that feature contributes.",
    ]

    return ModelMetadata(
        schema_version=SCHEMA_VERSION,
        feature_names=list(dataset.feature_names),
        algorithm=algorithm,
        trained_at=datetime.now(timezone.utc).isoformat(),
        n_samples=len(dataset.y),
        n_malicious=dataset.n_malicious,
        n_benign=dataset.n_benign,
        metrics=holdout_metrics or cv_metrics,
        cv_metrics=cv_metrics,
        baseline_metrics=baseline_metrics,
        ablation=ablation,
        feature_importances=importances[:40],
        notes=notes,
    )


def curve_data(y_true: np.ndarray, y_prob: np.ndarray) -> dict[str, Any]:
    """ROC and precision-recall curve points, for plotting."""
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    precision, recall, _ = precision_recall_curve(y_true, y_prob)
    return {
        "roc": {"fpr": fpr.tolist(), "tpr": tpr.tolist()},
        "pr": {"precision": precision.tolist(), "recall": recall.tolist()},
    }


def save_curves(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
