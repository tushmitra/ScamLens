"""Optional text-classifier wrapper.

The API keeps working without a model (rules + URL signals only) unless
SCAMLENS_REQUIRE_MODEL=true. Client-facing output never contains filesystem
paths or stack traces; details go to the server log by exception type only.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("scamlens.model")


class ModelUnavailable(RuntimeError):
    """Raised when classification is requested but no model is loaded."""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ModelService:
    def __init__(self, model_path: Path, metadata_path: Path, require_model: bool = False):
        self.model_path = Path(model_path)
        self.metadata_path = Path(metadata_path)
        self.require_model = require_model
        self.model: Any = None
        self.metadata: Dict[str, Any] = {}
        self.labels: Dict[str, str] = {}
        self.artifact_sha256: Optional[str] = None
        self.unavailable_reason: Optional[str] = "not_loaded"

    @property
    def available(self) -> bool:
        return self.model is not None

    def load(self) -> "ModelService":
        """Load and verify the artifact. Never raises unless require_model is set."""
        try:
            self._load()
            self.unavailable_reason = None
        except Exception as exc:  # noqa: BLE001 - reason is recorded, then re-raised if required
            self.model = None
            self.unavailable_reason = _reason_code(exc)
            logger.warning("Model not loaded (%s: %s)", type(exc).__name__, self.unavailable_reason)
            if self.require_model:
                raise RuntimeError(
                    f"ScamLens model is required but could not be loaded ({self.unavailable_reason}). "
                    "Check SCAMLENS_MODEL_DIR / SCAMLENS_MODEL_PATH / SCAMLENS_METADATA_PATH."
                ) from exc
        return self

    def _load(self) -> None:
        if not self.model_path.is_file():
            raise FileNotFoundError("artifact_missing")
        if not self.metadata_path.is_file():
            raise FileNotFoundError("metadata_missing")

        import joblib  # imported lazily so rule/URL-only deployments stay light

        metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        labels = metadata["labels"]
        model = joblib.load(self.model_path)

        expected = {int(k) for k in labels}
        actual = {int(v) for v in getattr(model, "classes_", [])}
        if actual != expected:
            raise ValueError("class_mismatch")
        if 0 not in actual:
            raise ValueError("no_legitimate_class")

        trained_with = metadata.get("sklearn_version")
        if trained_with:
            import sklearn

            if sklearn.__version__ != trained_with:
                logger.warning(
                    "scikit-learn version differs from training (%s vs %s); verify predictions.",
                    sklearn.__version__, trained_with,
                )

        self.model = model
        self.metadata = metadata
        self.labels = labels
        self.artifact_sha256 = sha256_of(self.model_path)

    def classify(self, message: str) -> Dict[str, Any]:
        if not self.available:
            raise ModelUnavailable(self.unavailable_reason or "not_loaded")
        label = int(self.model.predict([message])[0])
        probabilities = self.model.predict_proba([message])[0]
        classes = [int(c) for c in self.model.classes_]
        # Scam score is 1 - P(legitimate); locate class 0 rather than assuming a column.
        score = float(1.0 - probabilities[classes.index(0)])
        return {
            "predicted_label": label,
            "category": self.labels[str(label)],
            "model_scam_score": round(score, 4),
            "model_scam_score_percent": round(score * 100, 2),
            "model_score_is_calibrated": False,
        }

    def health(self) -> Dict[str, Any]:
        return {
            "model_loaded": self.available,
            "model_artifact": self.model_path.name if self.available else None,
            "model_candidate": self.metadata.get("selected_model", "unspecified") if self.available else None,
            "model_artifact_sha256": self.artifact_sha256,
            "model_unavailable_reason": self.unavailable_reason,
            "model_score_is_calibrated": False,
        }


def _reason_code(exc: Exception) -> str:
    text = str(exc)
    if text in {"artifact_missing", "metadata_missing", "class_mismatch", "no_legitimate_class"}:
        return text
    if isinstance(exc, (json.JSONDecodeError, KeyError)):
        return "metadata_invalid"
    return "load_failed"
