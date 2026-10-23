"""Runtime configuration, read from environment variables only (no secrets here)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

BACKEND_DIR = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _list(name: str, default: str) -> List[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    model_dir: Path = field(default_factory=lambda: BACKEND_DIR / "models")
    model_path: Optional[Path] = None
    metadata_path: Optional[Path] = None
    # False: the API still runs (rules + URL signals) when no model artifact exists.
    # True: fail at startup, which is the safer choice for a deployment that must have the model.
    require_model: bool = False
    cors_origins: List[str] = field(default_factory=lambda: ["http://localhost:5173"])
    max_message_chars: int = 10_000
    rate_limit_per_minute: int = 60  # 0 disables
    trust_proxy_headers: bool = False  # honour X-Forwarded-For only behind a trusted proxy
    log_level: str = "INFO"
    # None (default) keeps the v3 policy: the model never changes the risk band. A value such as
    # 0.5 lifts an otherwise-empty result to "Review carefully" when the model predicts a scam class.
    model_review_threshold: Optional[float] = None

    @property
    def resolved_model_path(self) -> Path:
        return self.model_path or self.model_dir / "word_char_candidate.joblib"

    @property
    def resolved_metadata_path(self) -> Path:
        return self.metadata_path or self.model_dir / "word_char_candidate_metadata.json"

    @classmethod
    def from_env(cls) -> "Settings":
        model_dir = Path(os.getenv("SCAMLENS_MODEL_DIR", str(BACKEND_DIR / "models")))
        model_path = os.getenv("SCAMLENS_MODEL_PATH")
        metadata_path = os.getenv("SCAMLENS_METADATA_PATH")
        raw_threshold = os.getenv("SCAMLENS_MODEL_REVIEW_THRESHOLD", "").strip()
        try:
            threshold = float(raw_threshold) if raw_threshold else None
        except ValueError:
            threshold = None
        if threshold is not None and not 0.0 <= threshold <= 1.0:
            threshold = None
        return cls(
            model_review_threshold=threshold,
            model_dir=model_dir,
            model_path=Path(model_path) if model_path else None,
            metadata_path=Path(metadata_path) if metadata_path else None,
            require_model=_bool("SCAMLENS_REQUIRE_MODEL", False),
            cors_origins=_list("SCAMLENS_CORS_ORIGINS", "http://localhost:5173"),
            max_message_chars=_int("SCAMLENS_MAX_MESSAGE_CHARS", 10_000),
            rate_limit_per_minute=_int("SCAMLENS_RATE_LIMIT_PER_MINUTE", 60),
            trust_proxy_headers=_bool("SCAMLENS_TRUST_PROXY_HEADERS", False),
            log_level=os.getenv("SCAMLENS_LOG_LEVEL", "INFO").upper(),
        )
