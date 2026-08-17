"""Model persistence and inference.

The inference side is deliberately small and strict. Two invariants:

* **Schema version is checked, never coerced.** A model trained on feature
  schema v1 fed a v2 vector would not fail — it would silently score the wrong
  columns and return a confident, meaningless number. That is worse than an
  exception, so a mismatch raises.
* **A missing model degrades to the rules baseline**, and says which one produced
  the score. A scan that silently returns 0.0 for every package because no model
  was trained would look like a clean result.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np

from chainguard.analysis.features import FEATURE_NAMES, SCHEMA_VERSION, PackageFeatures
from chainguard.config import get_settings
from chainguard.logging_setup import get_logger

logger = get_logger(__name__)

MODEL_FILENAME = "classifier.joblib"
METADATA_FILENAME = "model_card.json"


class SchemaMismatchError(RuntimeError):
    """The stored model was trained on a different feature schema."""


@dataclass
class ModelMetadata:
    """What a trained model is, and how well it did."""

    schema_version: int
    feature_names: list[str]
    algorithm: str
    trained_at: str
    n_samples: int
    n_malicious: int
    n_benign: int
    metrics: dict[str, Any] = field(default_factory=dict)
    cv_metrics: dict[str, Any] = field(default_factory=dict)
    baseline_metrics: dict[str, Any] = field(default_factory=dict)
    ablation: dict[str, Any] = field(default_factory=dict)
    feature_importances: list[tuple[str, float]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "feature_names": self.feature_names,
            "algorithm": self.algorithm,
            "trained_at": self.trained_at,
            "n_samples": self.n_samples,
            "n_malicious": self.n_malicious,
            "n_benign": self.n_benign,
            "metrics": self.metrics,
            "cv_metrics": self.cv_metrics,
            "baseline_metrics": self.baseline_metrics,
            "ablation": self.ablation,
            "feature_importances": self.feature_importances,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ModelMetadata:
        return cls(
            schema_version=int(data.get("schema_version", 0)),
            feature_names=list(data.get("feature_names", [])),
            algorithm=str(data.get("algorithm", "unknown")),
            trained_at=str(data.get("trained_at", "")),
            n_samples=int(data.get("n_samples", 0)),
            n_malicious=int(data.get("n_malicious", 0)),
            n_benign=int(data.get("n_benign", 0)),
            metrics=data.get("metrics", {}),
            cv_metrics=data.get("cv_metrics", {}),
            baseline_metrics=data.get("baseline_metrics", {}),
            ablation=data.get("ablation", {}),
            feature_importances=[tuple(x) for x in data.get("feature_importances", [])],
            notes=list(data.get("notes", [])),
        )


@dataclass
class Prediction:
    """A malice verdict for one package."""

    probability: float
    verdict: str  # "malicious" | "suspicious" | "benign"
    source: str  # "model" | "rules-baseline"
    top_contributors: list[tuple[str, float]] = field(default_factory=list)

    @property
    def is_flagged(self) -> bool:
        return self.verdict in ("malicious", "suspicious")


class MalwareClassifier:
    """Loads a trained model and scores packages."""

    def __init__(
        self, model: Optional[Any] = None, metadata: Optional[ModelMetadata] = None
    ) -> None:
        self.model = model
        self.metadata = metadata
        self.settings = get_settings()

    # ------------------------------------------------------------------ #

    @classmethod
    def load(cls, models_dir: Optional[Path] = None) -> MalwareClassifier:
        """Load the trained model, or return an unloaded classifier.

        An unloaded classifier still scores — via the rules baseline — and
        reports ``source="rules-baseline"`` so callers and reports can say which
        detector produced the number.
        """
        directory = models_dir or get_settings().models_dir
        model_path = directory / MODEL_FILENAME
        metadata_path = directory / METADATA_FILENAME

        if not model_path.exists():
            logger.warning(
                "No trained model at %s — falling back to the rules baseline. "
                "Run scripts/train_model.py to train one.",
                model_path,
            )
            return cls()

        try:
            model = joblib.load(model_path)
        except Exception as exc:  # noqa: BLE001 — a corrupt artifact must not crash a scan
            logger.error("Could not load model from %s: %s", model_path, exc)
            return cls()

        metadata = None
        if metadata_path.exists():
            try:
                metadata = ModelMetadata.from_dict(
                    json.loads(metadata_path.read_text(encoding="utf-8"))
                )
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Could not read model card: %s", exc)

        if metadata and metadata.schema_version != SCHEMA_VERSION:
            raise SchemaMismatchError(
                f"Model was trained on feature schema v{metadata.schema_version}, "
                f"but this build uses v{SCHEMA_VERSION}. Retrain with "
                f"scripts/train_model.py — scoring across schema versions would "
                f"silently misalign feature columns."
            )

        logger.info(
            "Loaded %s trained on %d samples",
            metadata.algorithm if metadata else "model",
            metadata.n_samples if metadata else 0,
        )
        return cls(model=model, metadata=metadata)

    @property
    def is_trained(self) -> bool:
        return self.model is not None

    # ------------------------------------------------------------------ #

    def predict(self, features: PackageFeatures, rules_score: float = 0.0) -> Prediction:
        """Score one package."""
        if features.schema_version != SCHEMA_VERSION:
            raise SchemaMismatchError(
                f"Feature vector is schema v{features.schema_version}, "
                f"expected v{SCHEMA_VERSION}"
            )

        if self.model is None:
            return Prediction(
                probability=rules_score,
                verdict=self._verdict(rules_score),
                source="rules-baseline",
            )

        vector = np.asarray([features.to_vector()], dtype=float)
        try:
            probability = float(self.model.predict_proba(vector)[0][1])
        except Exception as exc:  # noqa: BLE001
            logger.error("Prediction failed, using rules baseline: %s", exc)
            return Prediction(
                probability=rules_score,
                verdict=self._verdict(rules_score),
                source="rules-baseline",
            )

        return Prediction(
            probability=probability,
            verdict=self._verdict(probability),
            source="model",
            top_contributors=self._contributors(features),
        )

    def predict_many(self, batch: list[PackageFeatures]) -> list[float]:
        """Score a batch. Returns probabilities in input order."""
        if self.model is None or not batch:
            return [0.0] * len(batch)
        vectors = np.asarray([f.to_vector() for f in batch], dtype=float)
        return [float(p) for p in self.model.predict_proba(vectors)[:, 1]]

    def _verdict(self, probability: float) -> str:
        if probability >= self.settings.malicious_threshold:
            return "malicious"
        if probability >= self.settings.suspicious_threshold:
            return "suspicious"
        return "benign"

    def _contributors(self, features: PackageFeatures, limit: int = 6) -> list[tuple[str, float]]:
        """Which features most plausibly drove this score.

        Global feature importances weighted by this package's own non-zero
        values. This is an *attribution heuristic*, not a SHAP value: it explains
        which learned-important features are actually present here, which is what
        a reviewer wants to see next to the evidence list.
        """
        if not self.metadata or not self.metadata.feature_importances:
            return []

        values = dict(zip(FEATURE_NAMES, features.to_vector()))
        scored = [
            (name, importance * values.get(name, 0.0))
            for name, importance in self.metadata.feature_importances
            if values.get(name, 0.0) > 0
        ]
        scored.sort(key=lambda item: -item[1])
        return [(name, round(value, 4)) for name, value in scored[:limit] if value > 0]


def save_model(
    model: Any, metadata: ModelMetadata, models_dir: Optional[Path] = None
) -> tuple[Path, Path]:
    """Persist a trained model and its card."""
    directory = models_dir or get_settings().models_dir
    directory.mkdir(parents=True, exist_ok=True)

    model_path = directory / MODEL_FILENAME
    metadata_path = directory / METADATA_FILENAME

    joblib.dump(model, model_path)
    metadata_path.write_text(json.dumps(metadata.to_dict(), indent=2), encoding="utf-8")
    return model_path, metadata_path
