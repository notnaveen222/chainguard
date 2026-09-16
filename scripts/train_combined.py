"""Train on our corpus + the Guo et al. benchmark, and evaluate honestly.

Why: a model trained on either dataset alone transfers poorly to the other
(ours -> benchmark F1 0.885; benchmark -> our npm corpus F1 0.741). Each misses
malware families the other contains, so the deployable model is trained on both.

Evaluation (all reported, nothing tuned on the test numbers):
  1. Grouped 5-fold CV over the union, where groups merge (a) versions of the
     same package and (b) packages with identical feature vectors (campaign
     copies under random names), reported overall and per source.
  2. False positives on held-out real applications (packages from app lockfiles
     whose names never appear in training; data/corpus/augment_report.json).

Writes data/corpus/features_combined.csv for scripts/train_model.py --matrix.

Run:  python scripts/train_combined.py
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from chainguard.analysis.features import FEATURE_NAMES  # noqa: E402
from chainguard.ml.train import Dataset, cross_validate  # noqa: E402

CORPUS = REPO / "data/corpus/features_augmented.csv"
BENCH = REPO / "data/benchmarks/guo2026_npm_features.csv"
OUT = REPO / "data/corpus/features_combined.csv"


def _groups(ids: list[str], names: list[str], X: np.ndarray) -> np.ndarray:
    parent = list(range(len(ids)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    first: dict[tuple, int] = {}
    for i in range(len(ids)):
        for token in (("name", names[i]), ("vec", X[i].round(4).tobytes())):
            if token in first:
                parent[find(i)] = find(first[token])
            else:
                first[token] = i
    return np.array([f"g{find(i)}" for i in range(len(ids))])


def main() -> int:
    ids, y, names, rows, source = [], [], [], [], []
    with CORPUS.open(encoding="utf-8") as fh:
        reader = csv.reader(fh)
        next(reader)
        for r in reader:
            ids.append(r[0]); y.append(int(r[1])); rows.append([float(v) for v in r[3:]])
            names.append(r[2].split(":")[-1].lower() if ":" in r[2] else r[2].lower())
            source.append("ours")
    with BENCH.open(encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            key = r["key"]
            ids.append(f"guo2026:{key}"); y.append(int(r["label"]))
            rows.append([float(r[f]) for f in FEATURE_NAMES])
            names.append(key.rsplit("/", 1)[0].replace("##", "/").lower())
            source.append("benchmark")

    X = np.asarray(rows, dtype=float)
    yv = np.asarray(y, dtype=int)
    groups = _groups(ids, names, X)
    src = np.asarray(source)
    print(f"combined: {len(yv)} samples ({yv.sum()} malicious, {len(yv) - yv.sum()} benign); "
          f"{len(set(groups))} dedup groups")

    dataset = Dataset(X=X, y=yv, groups=groups, sample_ids=ids, feature_names=list(FEATURE_NAMES))
    metrics, oof = cross_validate(dataset)
    print(f"\nCombined grouped CV (threshold 0.5): P={metrics['precision']:.4f} R={metrics['recall']:.4f} "
          f"F1={metrics['f1']:.4f} PR-AUC={metrics['pr_auc']}")

    from sklearn.metrics import f1_score, precision_score, recall_score
    per_source = {}
    for s in ("ours", "benchmark"):
        m = src == s
        for t in (0.5, 0.6):
            pred = (oof[m] >= t).astype(int)
            p, r, f = precision_score(yv[m], pred), recall_score(yv[m], pred), f1_score(yv[m], pred)
            per_source[f"{s}@{t}"] = {"precision": p, "recall": r, "f1": f}
            print(f"  {s:<10} t={t}: P={p:.4f} R={r:.4f} F1={f:.4f} (n={m.sum()})")

    with OUT.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sample_id", "label", "group", *FEATURE_NAMES])
        for sid, label, g, row in zip(ids, yv, groups, X):
            w.writerow([sid, int(label), g, *[repr(float(v)) for v in row]])
    (REPO / "data/benchmarks/combined_cv.json").write_text(json.dumps(
        {"overall": {k: metrics[k] for k in ("precision", "recall", "f1", "pr_auc")}, "per_source": per_source}, indent=2))
    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
