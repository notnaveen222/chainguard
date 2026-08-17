"""Evaluation charts.

Rendered to PNG so they can go straight into the report and slides. Matplotlib
runs headless (``Agg``) because this executes in a script, not a notebook.

Chart choices follow from what each is meant to answer, not from what is easy to
draw: a confusion matrix shows *where* errors fall, a PR curve is the honest
summary under class imbalance, feature importances grouped by behaviour family
show which signals carry the model, and the ablation chart shows what breaks when
each family is removed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from chainguard.analysis.features import group_of  # noqa: E402
from chainguard.logging_setup import get_logger  # noqa: E402

logger = get_logger(__name__)

# A single palette, used consistently across every chart.
_MALICIOUS = "#c0392b"
_BENIGN = "#2980b9"
_ACCENT = "#16a085"
_MUTED = "#7f8c8d"
_GRID = "#dfe4e8"

_GROUP_COLOURS = {
    "install_execution": "#c0392b",
    "exfiltration": "#8e44ad",
    "dynamic_execution": "#d35400",
    "credentials": "#c2185b",
    "network": "#2980b9",
    "obfuscation": "#f39c12",
    "process": "#e74c3c",
    "typosquat": "#16a085",
    "metadata": "#7f8c8d",
    "structure": "#95a5a6",
    "aggregate": "#34495e",
}


def _style(ax: Any) -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(_GRID)
    ax.spines["bottom"].set_color(_GRID)
    ax.grid(True, color=_GRID, linewidth=0.7, alpha=0.7)
    ax.set_axisbelow(True)


def plot_confusion_matrix(matrix: dict[str, int], path: Path, title: str = "") -> Path:
    """Confusion matrix with counts and row-normalised percentages."""
    tn, fp = matrix["true_negative"], matrix["false_positive"]
    fn, tp = matrix["false_negative"], matrix["true_positive"]
    data = np.array([[tn, fp], [fn, tp]], dtype=float)
    row_totals = data.sum(axis=1, keepdims=True)
    normalised = np.divide(data, row_totals, out=np.zeros_like(data), where=row_totals > 0)

    fig, ax = plt.subplots(figsize=(5.6, 4.8))
    ax.imshow(normalised, cmap="Blues", vmin=0, vmax=1)

    labels = ["Benign", "Malicious"]
    ax.set_xticks([0, 1], labels=labels)
    ax.set_yticks([0, 1], labels=labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(title or "Confusion matrix (out-of-fold)", fontweight="bold", pad=14)

    for i in range(2):
        for j in range(2):
            colour = "white" if normalised[i, j] > 0.55 else "#2c3e50"
            ax.text(
                j, i - 0.08, f"{int(data[i, j]):,}",
                ha="center", va="center", fontsize=19, fontweight="bold", color=colour,
            )
            ax.text(
                j, i + 0.22, f"{normalised[i, j]:.1%}",
                ha="center", va="center", fontsize=11, color=colour, alpha=0.85,
            )

    ax.set_xticks(np.arange(-0.5, 2, 1), minor=True)
    ax.set_yticks(np.arange(-0.5, 2, 1), minor=True)
    ax.grid(which="minor", color="white", linewidth=2)
    ax.tick_params(which="minor", length=0)

    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def plot_roc(curves: dict[str, Any], auc: Optional[float], path: Path,
             baseline: Optional[tuple[list[float], list[float], Optional[float]]] = None) -> Path:
    """ROC curve, with the rules baseline overlaid for comparison."""
    fig, ax = plt.subplots(figsize=(5.6, 4.8))

    ax.plot(curves["roc"]["fpr"], curves["roc"]["tpr"], color=_MALICIOUS, linewidth=2.4,
            label=f"ChainGuard model (AUC = {auc:.3f})" if auc else "ChainGuard model")

    if baseline:
        fpr, tpr, base_auc = baseline
        ax.plot(fpr, tpr, color=_MUTED, linewidth=1.8, linestyle="--",
                label=f"Rules baseline (AUC = {base_auc:.3f})" if base_auc else "Rules baseline")

    ax.plot([0, 1], [0, 1], color=_GRID, linewidth=1.2, linestyle=":", label="Random")
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.set_title("ROC curve", fontweight="bold", pad=12)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.02)
    ax.legend(loc="lower right", frameon=False, fontsize=9)
    _style(ax)

    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def plot_precision_recall(
    curves: dict[str, Any], pr_auc: Optional[float], positive_rate: float, path: Path,
    baseline: Optional[tuple[list[float], list[float], Optional[float]]] = None,
) -> Path:
    """Precision-recall curve — the headline metric under class imbalance."""
    fig, ax = plt.subplots(figsize=(5.6, 4.8))

    ax.plot(curves["pr"]["recall"], curves["pr"]["precision"], color=_MALICIOUS, linewidth=2.4,
            label=f"ChainGuard model (AP = {pr_auc:.3f})" if pr_auc else "ChainGuard model")

    if baseline:
        recall, precision, base_ap = baseline
        ax.plot(recall, precision, color=_MUTED, linewidth=1.8, linestyle="--",
                label=f"Rules baseline (AP = {base_ap:.3f})" if base_ap else "Rules baseline")

    ax.axhline(positive_rate, color=_GRID, linestyle=":", linewidth=1.2,
               label=f"No-skill ({positive_rate:.2f})")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-recall curve", fontweight="bold", pad=12)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.02)
    ax.legend(loc="lower left", frameon=False, fontsize=9)
    _style(ax)

    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def plot_feature_importance(
    importances: list[tuple[str, float]], path: Path, top_n: int = 20
) -> Path:
    """Top features, coloured by the behaviour family each belongs to."""
    top = [(n, v) for n, v in importances if v > 0][:top_n]
    if not top:
        logger.warning("No non-zero feature importances to plot")
        return path

    names = [n for n, _ in top][::-1]
    values = [v for _, v in top][::-1]
    colours = [_GROUP_COLOURS.get(group_of(n) or "", _MUTED) for n in names]

    fig, ax = plt.subplots(figsize=(8.2, max(4.5, 0.34 * len(names) + 1.4)))
    ax.barh(names, values, color=colours, height=0.72)
    ax.set_xlabel("Relative importance")
    ax.set_title("Feature importance, coloured by signal family", fontweight="bold", pad=12)
    _style(ax)
    ax.grid(axis="y", visible=False)

    groups_present = {group_of(n) for n in names if group_of(n)}
    handles = [
        plt.Rectangle((0, 0), 1, 1, color=_GROUP_COLOURS.get(g, _MUTED))
        for g in sorted(groups_present)
    ]
    ax.legend(handles, sorted(groups_present), frameon=False, fontsize=8,
              loc="lower right", ncol=2)

    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def plot_ablation(ablation: dict[str, Any], full_f1: float, path: Path) -> Path:
    """How much F1 each feature family contributes, measured by removing it."""
    if not ablation:
        return path

    entries = sorted(ablation.items(), key=lambda item: item[1].get("f1", 0.0))
    names = [name for name, _ in entries]
    drops = [full_f1 - metrics.get("f1", 0.0) for _, metrics in entries]
    colours = [_GROUP_COLOURS.get(n, _MUTED) for n in names]

    fig, ax = plt.subplots(figsize=(8.2, max(4.0, 0.42 * len(names) + 1.4)))
    ax.barh(names, drops, color=colours, height=0.7)
    ax.axvline(0, color=_MUTED, linewidth=1)
    ax.set_xlabel(f"F1 lost when the family is removed  (full model F1 = {full_f1:.3f})")
    ax.set_title("Ablation: contribution of each signal family", fontweight="bold", pad=12)
    _style(ax)
    ax.grid(axis="y", visible=False)

    for index, value in enumerate(drops):
        offset = 0.0006 if value >= 0 else -0.0006
        ax.text(value + offset, index, f"{value:+.3f}", va="center",
                ha="left" if value >= 0 else "right", fontsize=8.5, color="#2c3e50")

    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def plot_score_distribution(
    y_true: np.ndarray, y_prob: np.ndarray, path: Path, threshold: float = 0.5
) -> Path:
    """Score distribution by true class — shows how separable the classes are."""
    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    bins = np.linspace(0, 1, 41)

    ax.hist(y_prob[y_true == 0], bins=bins, color=_BENIGN, alpha=0.75, label="Benign")
    ax.hist(y_prob[y_true == 1], bins=bins, color=_MALICIOUS, alpha=0.75, label="Malicious")
    ax.axvline(threshold, color=_ACCENT, linestyle="--", linewidth=1.8,
               label=f"Threshold ({threshold:.2f})")

    ax.set_xlabel("Predicted probability of being malicious")
    ax.set_ylabel("Packages")
    ax.set_title("Score distribution by true class (out-of-fold)", fontweight="bold", pad=12)
    ax.legend(frameon=False, fontsize=9)
    _style(ax)

    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path
