"""Orchestration: model + rules + URL checks + risk policy -> one response dict.

Framework-free, so the whole /check behaviour is testable without FastAPI.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from . import ENDPOINT_VERSION, __version__
from .link_checker import check_message_urls
from .model_service import ModelService
from .risk_engine import combine_risk
from .scam_rules import check_message_rules

CHECK_WARNING = (
    "Experimental screening can miss scams or flag legitimate messages. "
    "'No strong indicators found' does not mean safe. Verify via official channels and "
    "never share OTPs, PINs, passwords, or banking credentials."
)
PREDICT_WARNING = (
    "Experimental, uncalibrated AI output. It is not a guarantee. "
    "Never share OTPs, PINs, passwords, or banking credentials."
)


def analyze(
    message: str,
    model_service: Optional[ModelService],
    model_review_threshold: Optional[float] = None,
) -> Dict[str, Any]:
    """Run every signal group on ``message`` and return the /check response body."""
    model_result = model_service.classify(message) if model_service and model_service.available else None
    rule_result = check_message_rules(message)
    url_result = check_message_urls(message)
    assessment = combine_risk(model_result, rule_result, url_result, model_review_threshold)

    response: Dict[str, Any] = {
        "project": "ScamLens",
        "version": __version__,
        "endpoint_version": ENDPOINT_VERSION,
        "model_available": model_result is not None,
        "predicted_label": None,
        "category": None,
        "model_scam_score": None,
        "model_scam_score_percent": None,
        "model_score_is_calibrated": False,
    }
    if model_result is not None:
        response.update(model_result)
    response.update({
        "rule_analysis": rule_result,
        "url_analysis": url_result,
        "overall_risk": assessment["risk"],
        "reasons": assessment["reasons"],
        "drivers": assessment["drivers"],
        "advice": assessment["advice"],
        "warning": CHECK_WARNING,
    })
    return response


def predict_only(message: str, model_service: ModelService) -> Dict[str, Any]:
    """Legacy /predict body (text model only), kept compatible with existing clients."""
    result = model_service.classify(message)
    score, label = result["model_scam_score"], result["predicted_label"]
    if label == 0:
        risk_level = "No scam detected"
    elif score >= 0.70:
        risk_level = "High risk"
    elif score >= 0.30:
        risk_level = "Potential risk"
    else:
        risk_level = "Uncertain - review carefully"
    return {
        "project": "ScamLens",
        **result,
        "scam_probability": result["model_scam_score"],
        "scam_probability_percent": result["model_scam_score_percent"],
        "risk_level": risk_level,
        "warning": PREDICT_WARNING,
    }
