"""ScamLens combined FastAPI application.

Requires link_checker.py and scam_rules.py in the same directory or on PYTHONPATH.
The model score is uncalibrated and must not be presented as a verified probability.
"""

import json
import os
from pathlib import Path
from typing import Any

import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from link_checker import check_message_urls
from scam_rules import check_message_rules

MODEL_DIR = Path(os.getenv("SCAMLENS_MODEL_DIR", "/content/scamlens_model"))
MODEL_PATH = Path(os.getenv(
    "SCAMLENS_MODEL_PATH",
    str(MODEL_DIR / "word_char_candidate.joblib"),
))
METADATA_PATH = Path(os.getenv(
    "SCAMLENS_METADATA_PATH",
    str(MODEL_DIR / "word_char_candidate_metadata.json"),
))

if not MODEL_PATH.is_file():
    raise FileNotFoundError(
        f"ScamLens model not found at {MODEL_PATH}. "
        "Check the artifact path or set SCAMLENS_MODEL_PATH."
    )
if not METADATA_PATH.is_file():
    raise FileNotFoundError(
        f"ScamLens metadata not found at {METADATA_PATH}. "
        "Check the metadata path or set SCAMLENS_METADATA_PATH."
    )

model = joblib.load(MODEL_PATH)
with METADATA_PATH.open("r", encoding="utf-8") as file:
    metadata = json.load(file)

LABELS = metadata["labels"]
expected_classes = {int(key) for key in LABELS}
actual_classes = {int(value) for value in getattr(model, "classes_", [])}
if actual_classes != expected_classes:
    raise RuntimeError(
        f"Model classes {sorted(actual_classes)} do not match metadata "
        f"labels {sorted(expected_classes)}."
    )

app = FastAPI(
    title="ScamLens API",
    description=(
        "Experimental scam screening combining text classification, "
        "message-pattern indicators, and static URL inspection."
    ),
    version="1.1.0",
)


class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)


def _classify(message: str) -> dict[str, Any]:
    predicted_label = int(model.predict([message])[0])
    probabilities = model.predict_proba([message])[0]
    classes = [int(value) for value in model.classes_]
    legitimate_index = classes.index(0)
    score = float(1.0 - probabilities[legitimate_index])

    return {
        "predicted_label": predicted_label,
        "category": LABELS[str(predicted_label)],
        "model_scam_score": round(score, 4),
        "model_scam_score_percent": round(score * 100, 2),
        "model_score_is_calibrated": False,
    }


def _combine_risk(
    model_result: dict[str, Any],
    rule_result: dict[str, Any],
    url_result: dict[str, Any],
) -> tuple[str, list[str]]:
    """Transparent initial escalation policy; not tuned on the pilot set."""
    rule_flags = set(rule_result.get("flags", []))
    url_flags = {
        flag
        for item in url_result.get("urls", [])
        for flag in item.get("flags", [])
    }

    reasons = list(rule_result.get("reasons", []))
    for item in url_result.get("urls", []):
        for reason in item.get("reasons", []):
            if reason not in reasons:
                reasons.append(reason)

    strong_rule_flags = {
        "credential_request",
        "payment_demand",
        "threat_or_consequence",
        "authority_plus_action",
    }
    strong_url_flags = {
        "userinfo_present",
        "ip_host",
        "punycode_hostname",
        "brand_in_subdomain",
    }
    strong_rule = bool(rule_flags & strong_rule_flags)
    strong_url = bool(url_flags & strong_url_flags)
    multiple_signals = len(rule_flags) >= 2 or (
        bool(rule_flags) and bool(url_flags)
    )
    score = float(model_result["model_scam_score"])

    if strong_rule or strong_url or multiple_signals or score >= 0.70:
        risk = "Suspicious"
    elif rule_flags or url_flags or score >= 0.30:
        risk = "Review carefully"
    else:
        risk = "No strong indicators found"

    if score >= 0.30:
        reasons.append(
            "The text model produced a non-trivial experimental score; "
            "this score is not calibrated."
        )
    if not reasons:
        reasons.append("No configured message-rule or URL indicator was triggered.")

    return risk, reasons


@app.get("/")
def home():
    return {
        "project": "ScamLens",
        "status": "running",
        "documentation": "/docs",
        "version": app.version,
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "model_artifact": MODEL_PATH.name,
        "model_candidate": metadata.get("selected_model", "unspecified"),
        "model_score_is_calibrated": False,
    }


@app.post("/predict")
def predict(request: MessageRequest):
    """Compatibility endpoint: text-model prediction only."""
    message = request.message.strip()
    if not message:
        raise HTTPException(
            status_code=422,
            detail="Please provide a non-empty message.",
        )

    try:
        result = _classify(message)
        score = result["model_scam_score"]
        label = result["predicted_label"]

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
            # Compatibility aliases retained for existing clients.
            "scam_probability": result["model_scam_score"],
            "scam_probability_percent": result["model_scam_score_percent"],
            "risk_level": risk_level,
            "warning": (
                "Experimental AI prediction only. The score is uncalibrated "
                "and is not a guarantee. Never share OTPs, PINs, passwords, "
                "or banking credentials."
            ),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {type(exc).__name__}",
        )


@app.post("/check")
def check(request: MessageRequest):
    """Combined model, message-rule, and static URL inspection."""
    message = request.message.strip()
    if not message:
        raise HTTPException(
            status_code=422,
            detail="Please provide a non-empty message.",
        )

    try:
        model_result = _classify(message)
        rule_result = check_message_rules(message)
        url_result = check_message_urls(message)
        overall_risk, reasons = _combine_risk(
            model_result, rule_result, url_result
        )

        return {
            "project": "ScamLens",
            "version": app.version,
            **model_result,
            "rule_analysis": rule_result,
            "url_analysis": url_result,
            "overall_risk": overall_risk,
            "reasons": reasons,
            "warning": (
                "ScamLens is experimental. Checks can miss scams or flag "
                "legitimate messages. 'No strong indicators found' does not "
                "mean safe. Verify through official channels and never share "
                "OTPs, PINs, passwords, or banking credentials."
            ),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Combined check failed: {type(exc).__name__}",
        )
