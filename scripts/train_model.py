"""Train and evaluate the malicious-package classifier.

Reads the feature matrix produced by ``scripts/build_dataset.py``, runs grouped
cross-validation, compares against the rules-only baseline, runs a per-family
ablation, fits the deployed calibrated model, and writes the evaluation charts.

Run:  python scripts/train_model.py [--algorithm gradient_boosting|random_forest]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from chainguard.config import get_settings  # noqa: E402
from chainguard.logging_setup import get_logger  # noqa: E402
from chainguard.ml import plots  # noqa: E402
from chainguard.ml.model import save_model  # noqa: E402
from chainguard.ml.train import (  # noqa: E402
    build_metadata,
    cross_validate,
    curve_data,
    evaluate_baseline,
    load_dataset,
    run_ablation,
    train_final,
)
from sklearn.metrics import (  # noqa: E402
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

logger = get_logger("train_model")


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the ChainGuard classifier")
    parser.add_argument("--algorithm", default="gradient_boosting",
                        choices=["gradient_boosting", "random_forest"])
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--skip-ablation", action="store_true",
                        help="skip the per-family ablation study (it retrains once per family)")
    args = parser.parse_args()

    settings = get_settings()
    matrix_path = settings.corpus_dir / "features.csv"
    if not matrix_path.exists():
        logger.error("No feature matrix at %s. Run scripts/build_dataset.py first.", matrix_path)
        return 1

    dataset = load_dataset(matrix_path)
    logger.info(
        "Loaded %d samples (%d malicious, %d benign) across %d package families",
        len(dataset.y), dataset.n_malicious, dataset.n_benign, len(set(dataset.groups)),
    )
    if dataset.n_malicious < 10 or dataset.n_benign < 10:
        logger.error("Not enough samples of each class to train meaningfully.")
        return 1

    # --- cross-validation ---------------------------------------------------- #
    logger.info("Grouped cross-validation (%s):", args.algorithm)
    cv_metrics, out_of_fold = cross_validate(dataset, args.algorithm, args.folds)
    logger.info(
        "  OVERALL  precision=%.4f recall=%.4f f1=%.4f roc_auc=%s pr_auc=%s",
        cv_metrics["precision"], cv_metrics["recall"], cv_metrics["f1"],
        cv_metrics["roc_auc"], cv_metrics["pr_auc"],
    )

    # --- baseline comparison -------------------------------------------------- #
    baseline_metrics = evaluate_baseline(dataset)
    if baseline_metrics:
        logger.info(
            "Rules baseline: precision=%.4f recall=%.4f f1=%.4f pr_auc=%s",
            baseline_metrics["precision"], baseline_metrics["recall"],
            baseline_metrics["f1"], baseline_metrics["pr_auc"],
        )
        delta = cv_metrics["f1"] - baseline_metrics["f1"]
        logger.info("  model improves F1 by %+.4f over the rules baseline", delta)

    # --- ablation ------------------------------------------------------------- #
    ablation: dict = {}
    if not args.skip_ablation:
        logger.info("Ablation study (retrains once per feature family):")
        ablation = run_ablation(dataset, args.algorithm, args.folds)

    # --- final model ---------------------------------------------------------- #
    logger.info("Fitting the deployed model with probability calibration...")
    model, importances = train_final(dataset, args.algorithm)

    metadata = build_metadata(
        dataset=dataset,
        algorithm=args.algorithm,
        cv_metrics=cv_metrics,
        baseline_metrics=baseline_metrics,
        ablation=ablation,
        importances=importances,
    )
    model_path, card_path = save_model(model, metadata)
    logger.info("  model  -> %s", model_path)
    logger.info("  card   -> %s", card_path)

    # --- charts ---------------------------------------------------------------- #
    logger.info("Rendering evaluation charts...")
    models_dir = settings.models_dir
    curves = curve_data(dataset.y, out_of_fold)

    baseline_roc = baseline_pr = None
    if baseline_metrics:
        index = dataset.feature_names.index("rules_baseline_score")
        scores = dataset.X[:, index]
        fpr, tpr, _ = roc_curve(dataset.y, scores)
        precision, recall, _ = precision_recall_curve(dataset.y, scores)
        baseline_roc = (fpr.tolist(), tpr.tolist(), float(roc_auc_score(dataset.y, scores)))
        baseline_pr = (
            recall.tolist(), precision.tolist(), float(average_precision_score(dataset.y, scores))
        )

    positive_rate = float(dataset.y.mean())
    written = [
        plots.plot_confusion_matrix(cv_metrics["confusion_matrix"], models_dir / "confusion_matrix.png"),
        plots.plot_roc(curves, cv_metrics["roc_auc"], models_dir / "roc_curve.png", baseline_roc),
        plots.plot_precision_recall(
            curves, cv_metrics["pr_auc"], positive_rate, models_dir / "pr_curve.png", baseline_pr
        ),
        plots.plot_feature_importance(importances, models_dir / "feature_importance.png"),
        plots.plot_score_distribution(
            dataset.y, out_of_fold, models_dir / "score_distribution.png",
            settings.malicious_threshold,
        ),
    ]
    if ablation:
        written.append(plots.plot_ablation(ablation, cv_metrics["f1"], models_dir / "ablation.png"))

    for path in written:
        logger.info("  chart  -> %s", path.name)

    (models_dir / "curves.json").write_text(json.dumps(curves), encoding="utf-8")

    # --- summary ---------------------------------------------------------------- #
    matrix = cv_metrics["confusion_matrix"]
    logger.info("=" * 62)
    logger.info("RESULTS (out-of-fold, grouped by package family)")
    logger.info("  samples        : %d (%d malicious / %d benign)",
                len(dataset.y), dataset.n_malicious, dataset.n_benign)
    logger.info("  precision      : %.4f  (+/- %.4f across folds)",
                cv_metrics["precision"], cv_metrics["fold_std"]["precision"])
    logger.info("  recall         : %.4f  (+/- %.4f across folds)",
                cv_metrics["recall"], cv_metrics["fold_std"]["recall"])
    logger.info("  f1             : %.4f  (+/- %.4f across folds)",
                cv_metrics["f1"], cv_metrics["fold_std"]["f1"])
    logger.info("  roc_auc        : %s", cv_metrics["roc_auc"])
    logger.info("  pr_auc         : %s", cv_metrics["pr_auc"])
    logger.info("  confusion      : TP=%d FP=%d FN=%d TN=%d",
                matrix["true_positive"], matrix["false_positive"],
                matrix["false_negative"], matrix["true_negative"])
    if baseline_metrics:
        logger.info("  rules baseline : f1=%.4f pr_auc=%s",
                    baseline_metrics["f1"], baseline_metrics["pr_auc"])
    logger.info("  top features   : %s", ", ".join(n for n, _ in importances[:6]))
    logger.info("=" * 62)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
