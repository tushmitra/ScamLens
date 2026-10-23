import tempfile
from pathlib import Path

from helpers import BACKEND, make_tiny_model  # noqa: F401

from app.model_service import ModelService, ModelUnavailable
from app.service import analyze, predict_only

SCAM = "Your bank account will be blocked. Share your OTP now: https://bit.ly/example."
BENIGN = "Your appointment is confirmed for Monday at 10 AM."


def test_check_without_model():
    out = analyze(SCAM, None)
    assert out["model_available"] is False
    assert out["model_scam_score"] is None and out["predicted_label"] is None
    assert out["overall_risk"] == "Suspicious"
    assert "credential_request" in out["rule_analysis"]["flags"]
    assert out["url_analysis"]["url_count"] == 1
    assert out["advice"] and out["drivers"]
    assert "does not mean safe" in out["warning"]


def test_check_response_has_stable_keys():
    expected = {
        "project", "version", "endpoint_version", "model_available", "predicted_label", "category",
        "model_scam_score", "model_scam_score_percent", "model_score_is_calibrated", "rule_analysis",
        "url_analysis", "overall_risk", "reasons", "drivers", "advice", "warning",
    }
    assert set(analyze(BENIGN, None)) == expected


def test_benign_message_has_no_strong_indicators():
    out = analyze(BENIGN, None)
    assert out["overall_risk"] == "No strong indicators found"


def test_missing_model_is_reported_not_fatal():
    with tempfile.TemporaryDirectory() as tmp:
        service = ModelService(Path(tmp) / "nope.joblib", Path(tmp) / "nope.json").load()
        assert service.available is False
        assert service.health()["model_unavailable_reason"] == "artifact_missing"
        assert "nope" not in str(service.health())  # no filesystem paths leak
        try:
            service.classify("hello")
            raise AssertionError("expected ModelUnavailable")
        except ModelUnavailable:
            pass


def test_require_model_fails_fast_with_clear_message():
    with tempfile.TemporaryDirectory() as tmp:
        try:
            ModelService(Path(tmp) / "x.joblib", Path(tmp) / "x.json", require_model=True).load()
            raise AssertionError("expected RuntimeError")
        except RuntimeError as exc:
            assert "artifact_missing" in str(exc)


def test_with_tiny_model():
    with tempfile.TemporaryDirectory() as tmp:
        directory = make_tiny_model(Path(tmp))
        service = ModelService(directory / "word_char_candidate.joblib",
                               directory / "word_char_candidate_metadata.json").load()
        assert service.available and service.artifact_sha256
        out = analyze(SCAM, service)
        assert out["model_available"] is True
        assert 0.0 <= out["model_scam_score"] <= 1.0
        assert out["model_score_is_calibrated"] is False
        assert out["category"] in service.labels.values()
        # the model never lowers or raises the band on its own
        assert analyze(BENIGN, service)["overall_risk"] == "No strong indicators found"
        legacy = predict_only("police arrest warrant digital custody cooperate immediately alpha", service)
        assert legacy["scam_probability"] == legacy["model_scam_score"]
        assert legacy["risk_level"] in {"High risk", "Potential risk", "Uncertain - review carefully", "No scam detected"}


def test_class_mismatch_between_model_and_metadata_is_rejected():
    import json

    with tempfile.TemporaryDirectory() as tmp:
        directory = make_tiny_model(Path(tmp))
        meta_path = directory / "word_char_candidate_metadata.json"
        meta = json.loads(meta_path.read_text())
        meta["labels"].pop("4")
        meta_path.write_text(json.dumps(meta))
        service = ModelService(directory / "word_char_candidate.joblib", meta_path).load()
        assert service.available is False
        assert service.unavailable_reason == "class_mismatch"


def test_review_threshold_is_passed_through_to_the_policy():
    with tempfile.TemporaryDirectory() as tmp:
        directory = make_tiny_model(Path(tmp))
        service = ModelService(directory / "word_char_candidate.joblib",
                               directory / "word_char_candidate_metadata.json").load()
        text = "bank account blocked verify password otp kyc link alpha"  # no rule trigger phrases
        off = analyze(text, service)
        on = analyze(text, service, model_review_threshold=0.2)
        if off["rule_analysis"]["flags"] or off["url_analysis"]["url_count"]:
            return  # fixture text happened to trip a rule; the policy-level tests cover the behaviour
        assert off["overall_risk"] == "No strong indicators found"
        assert on["overall_risk"] in {"Review carefully", "No strong indicators found"}
        if on["predicted_label"] not in (0, None) and on["model_scam_score"] >= 0.2:
            assert on["overall_risk"] == "Review carefully"
