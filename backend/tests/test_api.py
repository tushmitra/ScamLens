"""HTTP-level tests. Require fastapi + httpx (see requirements-dev.txt); skipped if absent."""
import tempfile
from pathlib import Path

import pytest

from helpers import BACKEND, make_tiny_model  # noqa: F401

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from app.model_service import ModelService  # noqa: E402

SCAM = "Your bank account will be blocked. Share your OTP now: https://bit.ly/example."


def client_without_model(**overrides):
    tmp = Path(tempfile.mkdtemp())
    settings = Settings(model_dir=tmp, rate_limit_per_minute=overrides.pop("rate", 0), **overrides)
    service = ModelService(tmp / "missing.joblib", tmp / "missing.json").load()
    return TestClient(create_app(settings, service), raise_server_exceptions=False)


def client_with_model():
    tmp = Path(tempfile.mkdtemp())
    directory = make_tiny_model(tmp)
    settings = Settings(model_dir=directory, rate_limit_per_minute=0)
    service = ModelService(directory / "word_char_candidate.joblib",
                           directory / "word_char_candidate_metadata.json").load()
    return TestClient(create_app(settings, service), raise_server_exceptions=False)


def test_root_and_health_without_model():
    client = client_without_model()
    assert client.get("/").json()["project"] == "ScamLens"
    health = client.get("/health").json()
    assert health["status"] == "healthy" and health["model_loaded"] is False
    assert health["model_unavailable_reason"] == "artifact_missing"
    assert "missing.joblib" not in str(health)


def test_check_without_model_returns_rule_and_url_signals():
    body = client_without_model().post("/check", json={"message": SCAM}).json()
    assert body["overall_risk"] == "Suspicious"
    assert body["model_available"] is False and body["model_scam_score"] is None
    assert body["url_analysis"]["url_count"] == 1
    assert body["advice"] and body["drivers"]


def test_predict_is_503_without_model():
    response = client_without_model().post("/predict", json={"message": "hello"})
    assert response.status_code == 503
    assert "not available" in response.json()["detail"]


def test_check_and_predict_with_model():
    client = client_with_model()
    body = client.post("/check", json={"message": "Hello there"}).json()
    assert body["model_available"] is True and body["model_score_is_calibrated"] is False
    legacy = client.post("/predict", json={"message": "Hello there"})
    assert legacy.status_code == 200
    assert {"scam_probability", "risk_level", "category"} <= set(legacy.json())


def test_validation_errors_are_clean_and_do_not_echo_input():
    client = client_without_model()
    for payload, fragment in [
        ({"message": ""}, "non-empty"),
        ({"message": "   "}, "non-empty"),
        ({"message": "x" * 10_001}, "10,000"),
        ({}, "non-empty"),
    ]:
        response = client.post("/check", json=payload)
        assert response.status_code == 422, payload
        detail = response.json()["detail"]
        assert isinstance(detail, str) and fragment in detail
    malformed = client.post("/check", content="not json", headers={"Content-Type": "application/json"})
    assert malformed.status_code == 422 and isinstance(malformed.json()["detail"], str)


def test_internal_errors_do_not_leak_details(monkeypatch=None):
    import app.main as main_module

    client = client_without_model()

    def boom(*args, **kwargs):
        raise ValueError("/secret/path/model.joblib exploded")

    original = main_module.analyze
    main_module.analyze = boom
    try:
        response = client.post("/check", json={"message": "hello"})
    finally:
        main_module.analyze = original
    assert response.status_code == 500
    assert "/secret" not in response.text and "Traceback" not in response.text


def test_rate_limit_returns_429():
    client = client_without_model(rate=2)
    codes = [client.post("/check", json={"message": "hello"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert client.get("/health").status_code == 200  # GETs are not limited


def test_security_headers_present():
    response = client_without_model().get("/")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"]


def test_cors_only_allows_configured_origin():
    client = client_without_model(cors_origins=["https://app.example"])
    allowed = client.options("/check", headers={"Origin": "https://app.example",
                                                "Access-Control-Request-Method": "POST"})
    assert allowed.headers.get("access-control-allow-origin") == "https://app.example"
    blocked = client.options("/check", headers={"Origin": "https://evil.example",
                                                "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in blocked.headers
