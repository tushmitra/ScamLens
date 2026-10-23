from helpers import BACKEND  # noqa: F401

from app.risk_engine import RISK_NONE, RISK_REVIEW, RISK_SUSPICIOUS, STRONG_RULE_FLAGS, combine_risk


def rules(*flags):
    return {"flags": list(flags), "reasons": [f"reason:{f}" for f in flags]}


def urls(*flag_lists):
    return {"urls": [{"flags": list(f), "reasons": [f"url-reason:{x}" for x in f]} for f in flag_lists]}


NO_URLS = {"urls": []}


def test_nothing_triggered_is_not_called_safe():
    out = combine_risk({"model_scam_score": 0.1}, rules(), NO_URLS)
    assert out["risk"] == RISK_NONE
    text = " ".join(out["reasons"]).lower()
    assert "does not mean" in text
    assert "safe" not in RISK_NONE.lower()


def test_model_score_alone_never_escalates():
    out = combine_risk({"model_scam_score": 0.99}, rules(), NO_URLS)
    assert out["risk"] == RISK_NONE
    assert any("not calibrated" in r for r in out["reasons"])


def test_works_without_a_model():
    out = combine_risk(None, rules(), NO_URLS)
    assert out["risk"] == RISK_NONE
    assert any("No text model is loaded" in r for r in out["reasons"])


def test_each_strong_rule_flag_is_suspicious():
    for flag in STRONG_RULE_FLAGS:
        assert combine_risk(None, rules(flag), NO_URLS)["risk"] == RISK_SUSPICIOUS, flag


def test_single_weak_rule_flag_is_review():
    for flag in ("urgent_action", "remote_access_request", "advance_fee_scam", "investment_claim", "money_mule_request"):
        assert combine_risk(None, rules(flag), NO_URLS)["risk"] == RISK_REVIEW, flag


def test_two_weak_rule_flags_are_suspicious():
    assert combine_risk(None, rules("urgent_action", "investment_claim"), NO_URLS)["risk"] == RISK_SUSPICIOUS


def test_shortener_alone_is_review_not_proof():
    out = combine_risk({"model_scam_score": 0.1}, rules(), urls(["url_shortener"]))
    assert out["risk"] == RISK_REVIEW


def test_strong_url_flags_are_suspicious():
    for flag in ("userinfo_present", "ip_host", "punycode_hostname", "brand_in_subdomain"):
        assert combine_risk(None, rules(), urls([flag]))["risk"] == RISK_SUSPICIOUS, flag


def test_other_single_url_flags_are_review():
    for flag in ("not_https", "uncommon_tld", "many_subdomains", "brand_in_domain_label"):
        assert combine_risk(None, rules(), urls([flag]))["risk"] == RISK_REVIEW, flag


def test_two_non_shortener_url_flags_are_suspicious():
    assert combine_risk(None, rules(), urls(["not_https", "uncommon_tld"]))["risk"] == RISK_SUSPICIOUS
    assert combine_risk(None, rules(), urls(["url_shortener", "not_https"]))["risk"] == RISK_REVIEW


def test_rule_plus_url_signal_is_suspicious():
    assert combine_risk(None, rules("urgent_action"), urls(["url_shortener"]))["risk"] == RISK_SUSPICIOUS


def test_drivers_explain_the_decision():
    out = combine_risk(None, rules("credential_request", "urgent_action"), urls(["ip_host", "not_https"]))
    drivers = {(d["source"], d["id"]): d["strength"] for d in out["drivers"]}
    assert drivers[("rule", "credential_request")] == "strong"
    assert drivers[("rule", "urgent_action")] == "supporting"
    assert drivers[("url", "ip_host")] == "strong"
    assert drivers[("url", "not_https")] == "supporting"


def test_reasons_are_deduplicated_across_urls():
    out = combine_risk(None, rules(), urls(["ip_host"], ["ip_host"]))
    assert out["reasons"].count("url-reason:ip_host") == 1


def test_advice_never_tells_user_to_click_or_promises_safety():
    out = combine_risk(None, rules("credential_request"), urls(["url_shortener"]))
    joined = " ".join(out["advice"]).lower()
    assert "never share an otp" in joined
    assert "do not open the link" in joined
    assert "guaranteed safe" not in joined


def model(label, score):
    return {"predicted_label": label, "model_scam_score": score}


def test_model_review_lift_is_off_by_default():
    out = combine_risk(model(3, 0.95), rules(), NO_URLS)
    assert out["risk"] == RISK_NONE


def test_model_review_lift_when_enabled():
    out = combine_risk(model(3, 0.95), rules(), NO_URLS, model_review_threshold=0.5)
    assert out["risk"] == RISK_REVIEW  # never Suspicious from the model alone
    assert {"source": "model", "id": "model_above_review_threshold", "strength": "supporting"} in out["drivers"]
    assert any("not calibrated" in r for r in out["reasons"])
    assert "does not mean" not in " ".join(out["reasons"]).lower()  # it is not a "nothing found" result


def test_model_review_lift_requires_scam_label_and_threshold():
    assert combine_risk(model(0, 0.95), rules(), NO_URLS, model_review_threshold=0.5)["risk"] == RISK_NONE
    assert combine_risk(model(3, 0.40), rules(), NO_URLS, model_review_threshold=0.5)["risk"] == RISK_NONE
    assert combine_risk(None, rules(), NO_URLS, model_review_threshold=0.5)["risk"] == RISK_NONE


def test_model_review_lift_never_lowers_or_overrides_stronger_bands():
    assert combine_risk(model(3, 0.99), rules("credential_request"), NO_URLS, 0.5)["risk"] == RISK_SUSPICIOUS
    assert combine_risk(model(0, 0.01), rules("urgent_action"), NO_URLS, 0.5)["risk"] == RISK_REVIEW
