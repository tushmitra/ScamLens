from fastapi.testclient import TestClient
from scamlens_api_v3 import app, _combine_risk
from scam_rules import check_message_rules

def test_rule_cases():
    assert "credential_request" not in check_message_rules(
        "Never share your OTP or password with anyone."
    )["flags"]
    assert "credential_request" in check_message_rules(
        "Please share your OTP to verify your bank account."
    )["flags"]
    assert "authority_plus_action" not in check_message_rules(
        "Please share your OTP to verify your bank account."
    )["flags"]
    assert "authority_plus_action" in check_message_rules(
        "We are your bank. Click here to verify your account now."
    )["flags"]
    assert "authority_plus_action" not in check_message_rules(
        "I work at a bank and can explain savings accounts."
    )["flags"]

def test_api_routes():
    client = TestClient(app)
    assert client.get("/").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.post("/predict", json={"message": "Hello there"}).status_code == 200
    assert client.post("/check", json={"message": "Hello there"}).status_code == 200

def test_model_score_alone_does_not_escalate():
    model_result = {"model_scam_score": 0.99}
    rules = {"flags": [], "reasons": []}
    urls = {"urls": []}
    risk, reasons = _combine_risk(model_result, rules, urls)
    assert risk == "No strong indicators found"
    assert any("not calibrated" in reason for reason in reasons)

def test_shortener_is_review_not_proof():
    model_result = {"model_scam_score": 0.1}
    rules = {"flags": [], "reasons": []}
    urls = {"urls": [{"flags": ["url_shortener"], "reasons": ["Shortener indicator."]}]}
    risk, _ = _combine_risk(model_result, rules, urls)
    assert risk == "Review carefully"
