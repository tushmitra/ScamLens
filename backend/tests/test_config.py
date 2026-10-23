import os

from helpers import BACKEND  # noqa: F401

from app.config import Settings


def _with_env(**env):
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update({k: v for k, v in env.items() if v is not None})
    try:
        return Settings.from_env()
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_defaults_are_safe():
    settings = Settings.from_env()
    assert settings.require_model is False
    assert settings.model_review_threshold is None
    assert settings.rate_limit_per_minute == 60
    assert settings.trust_proxy_headers is False
    assert settings.cors_origins == ["http://localhost:5173"]
    assert settings.resolved_model_path.name == "word_char_candidate.joblib"


def test_env_overrides_and_bad_values_fall_back():
    s = _with_env(SCAMLENS_MODEL_REVIEW_THRESHOLD="0.5", SCAMLENS_REQUIRE_MODEL="true",
                  SCAMLENS_CORS_ORIGINS="https://a.example, https://b.example")
    assert s.model_review_threshold == 0.5 and s.require_model is True
    assert s.cors_origins == ["https://a.example", "https://b.example"]
    assert _with_env(SCAMLENS_MODEL_REVIEW_THRESHOLD="banana").model_review_threshold is None
    assert _with_env(SCAMLENS_MODEL_REVIEW_THRESHOLD="7").model_review_threshold is None
    assert _with_env(SCAMLENS_RATE_LIMIT_PER_MINUTE="x").rate_limit_per_minute == 60
