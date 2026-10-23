"""Transparent signal-combination policy for ScamLens.

Pure functions, no model or framework imports, so the policy can be unit-tested
on its own. The policy is the one adopted in the v3 API:

  * An uncalibrated model score NEVER raises the risk band by itself. It is
    reported for context only (a score on a different scale from boolean flags).
  * "Suspicious"       = a strong rule flag, a strong URL flag, or multiple
                         independent signals.
  * "Review carefully" = at least one weaker rule or URL signal.
  * "No strong indicators found" = nothing triggered. This is NOT "safe".

Optional (OFF by default): ``model_review_threshold``. When set, a model that predicts a
non-legitimate class with score >= threshold lifts an otherwise empty result to "Review
carefully" (never to "Suspicious"). This exists because rules + URL checks alone miss many
scams that use no trigger keywords; it is a product decision, so it is opt-in and the
threshold must be chosen on general grounds, not tuned on a frozen set.

Edit STRONG_RULE_FLAGS / STRONG_URL_FLAGS to change the policy; tests pin the defaults.
Thresholds were chosen on general policy grounds, not tuned on the frozen pilot set.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

RISK_SUSPICIOUS = "Suspicious"
RISK_REVIEW = "Review carefully"
RISK_NONE = "No strong indicators found"

STRONG_RULE_FLAGS = frozenset({
    "credential_request",
    "payment_demand",
    "threat_or_consequence",
    "authority_plus_action",
})
STRONG_URL_FLAGS = frozenset({
    "userinfo_present",
    "ip_host",
    "punycode_hostname",
    "brand_in_subdomain",
})

GENERAL_ADVICE = [
    "Do not reply, click links, or call numbers in the message. Verify through the official app, "
    "a number printed on your card or bill, or a website address you type yourself.",
    "Never share an OTP, PIN, password, CVV, or banking credential with anyone, including someone claiming to be your bank.",
]

_FLAG_ADVICE = {
    "credential_request": "Banks, police and government offices never ask for your OTP, PIN or password by message or call.",
    "payment_demand": "Do not pay fees, deposits or fines requested by message to release a prize, refund, parcel or job.",
    "threat_or_consequence": "Threats of arrest, blocking or disconnection are a pressure tactic. Pause and verify independently.",
    "authority_plus_action": "Official bodies do not demand immediate action by link or payment. Contact them through their published channels.",
    "remote_access_request": "Never install remote-access software (AnyDesk, TeamViewer and similar) at a stranger's request.",
    "money_mule_request": "Do not receive or forward money for someone else. It can make you liable for fraud.",
    "advance_fee_scam": "A real prize, job, visa or inheritance does not require an upfront fee.",
    "investment_claim": "Guaranteed or very high returns are a hallmark of investment fraud.",
}


def _url_flags(url_result: Dict[str, Any]) -> set:
    return {flag for item in url_result.get("urls", []) for flag in item.get("flags", [])}


def combine_risk(
    model_result: Optional[Dict[str, Any]],
    rule_result: Dict[str, Any],
    url_result: Dict[str, Any],
    model_review_threshold: Optional[float] = None,
) -> Dict[str, Any]:
    """Combine signal groups into a risk band, reasons, drivers and advice.

    ``model_result`` may be None when no model artifact is loaded.
    """
    rule_flags = set(rule_result.get("flags", []))
    url_flags = _url_flags(url_result)

    reasons: List[str] = list(rule_result.get("reasons", []))
    for item in url_result.get("urls", []):
        for reason in item.get("reasons", []):
            if reason not in reasons:
                reasons.append(reason)

    strong_rules = rule_flags & STRONG_RULE_FLAGS
    strong_urls = url_flags & STRONG_URL_FLAGS
    non_shortener_url_flags = url_flags - {"url_shortener"}
    multiple_signals = (
        len(rule_flags) >= 2
        or (bool(rule_flags) and bool(url_flags))
        or len(non_shortener_url_flags) >= 2
    )

    if strong_rules or strong_urls or multiple_signals:
        risk = RISK_SUSPICIOUS
    elif rule_flags or url_flags:
        risk = RISK_REVIEW
    else:
        risk = RISK_NONE

    model_lift = (
        risk == RISK_NONE
        and model_review_threshold is not None
        and model_result is not None
        and model_result.get("predicted_label") not in (None, 0)
        and float(model_result["model_scam_score"]) >= model_review_threshold
    )
    if model_lift:
        risk = RISK_REVIEW

    drivers: List[Dict[str, str]] = []
    if model_lift:
        drivers.append({"source": "model", "id": "model_above_review_threshold", "strength": "supporting"})
    for flag in sorted(strong_rules):
        drivers.append({"source": "rule", "id": flag, "strength": "strong"})
    for flag in sorted(rule_flags - strong_rules):
        drivers.append({"source": "rule", "id": flag, "strength": "supporting"})
    for flag in sorted(strong_urls):
        drivers.append({"source": "url", "id": flag, "strength": "strong"})
    for flag in sorted(url_flags - strong_urls):
        drivers.append({"source": "url", "id": flag, "strength": "supporting"})

    if model_lift:
        reasons.append(
            "The experimental text model leaned toward a scam category; no rule or link indicator "
            "triggered, so this is a prompt to check, not a finding. The score is not calibrated."
        )
    elif model_result is not None and not rule_flags and not url_flags:
        score = float(model_result["model_scam_score"])
        reasons.append(
            f"The text model's experimental score is {score:.2f} and is not calibrated; it is shown "
            "for context but does not independently determine this risk band."
        )
    elif model_result is None and not rule_flags and not url_flags:
        reasons.append("No text model is loaded on this server; only rule and URL checks were run.")

    if risk == RISK_NONE:
        reasons.append("No configured message-rule or URL indicator was triggered. This does not mean the message is safe.")

    advice: List[str] = []
    for flag in sorted(rule_flags):
        if flag in _FLAG_ADVICE:
            advice.append(_FLAG_ADVICE[flag])
    if url_flags:
        advice.append("Do not open the link to 'test' it. Look up the organisation yourself and use its official site or app.")
    advice.extend(GENERAL_ADVICE)

    return {"risk": risk, "reasons": reasons, "drivers": drivers, "advice": advice}
