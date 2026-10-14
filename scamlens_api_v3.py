"""ScamLens API v3: model, rule and static URL signals."""
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
    "SCAMLENS_MODEL_PATH", str(MODEL_DIR / "word_char_candidate.joblib")
))
METADATA_PATH = Path(os.getenv(
    "SCAMLENS_METADATA_PATH",
    str(MODEL_DIR / "word_char_candidate_metadata.json")
))

if not MODEL_PATH.is_file():
    raise FileNotFoundError(f"ScamLens model not found: {MODEL_PATH}")
if not METADATA_PATH.is_file():
    raise FileNotFoundError(f"ScamLens metadata not found: {METADATA_PATH}")

model = joblib.load(MODEL_PATH)
with METADATA_PATH.open(encoding="utf-8") as file:
    metadata = json.load(file)

LABELS = metadata["labels"]
classes = {int(x) for x in getattr(model, "classes_", [])}
if classes != {int(k) for k in LABELS}:
    raise RuntimeError("Model classes do not match metadata labels.")

app = FastAPI(
    title="ScamLens API",
    description="Experimental message and static URL risk screening.",
    version="1.2.0",
)

class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)

def _classify(message: str) -> dict[str, Any]:
    label = int(model.predict([message])[0])
    probabilities = model.predict_proba([message])[0]
    model_classes = [int(x) for x in model.classes_]
    score = float(1.0 - probabilities[model_classes.index(0)])
    return {
        "predicted_label": label,
        "category": LABELS[str(label)],
        "model_scam_score": round(score, 4),
        "model_scam_score_percent": round(score * 100, 2),
        "model_score_is_calibrated": False,
    }

def _combine_risk(model_result, rule_result, url_result):
    rule_flags = set(rule_result.get("flags", []))
    url_flags = {
        flag for item in url_result.get("urls", [])
        for flag in item.get("flags", [])
    }

    reasons = list(rule_result.get("reasons", []))
    for item in url_result.get("urls", []):
        for reason in item.get("reasons", []):
            if reason not in reasons:
                reasons.append(reason)

    strong_rules = {
        "credential_request", "payment_demand",
        "threat_or_consequence", "authority_plus_action",
    }
    strong_urls = {
        "userinfo_present", "ip_host", "punycode_hostname",
        "brand_in_subdomain",
    }

    # Do not elevate a message solely because an uncalibrated model score
    # crosses a numerical threshold. Model output remains a separate signal.
    strong_rule = bool(rule_flags & strong_rules)
    strong_url = bool(url_flags & strong_urls)
    shortener_only = bool(url_flags) and url_flags <= {"url_shortener"}
    multiple_signals = (
        len(rule_flags) >= 2
        or (bool(rule_flags) and bool(url_flags))
        or len(url_flags - {"url_shortener"}) >= 2
    )

    if strong_rule or strong_url or multiple_signals:
        risk = "Suspicious"
    elif rule_flags or url_flags:
        risk = "Review carefully"
    else:
        risk = "No strong indicators found"

    if not rule_flags and not url_flags:
        score = model_result["model_scam_score"]
        reasons.append(
            "The text model's experimental score is "
            f"{score:.2f} and is not calibrated; it is shown for context "
            "but does not independently determine this risk band."
        )

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
    message = request.message.strip()
    if not message:
        raise HTTPException(status_code=422, detail="Please provide a non-empty message.")
    try:
        result = _classify(message)
        score = result["model_scam_score"]
        label = result["predicted_label"]
        risk = (
            "No scam detected" if label == 0 else
            "High risk" if score >= 0.70 else
            "Potential risk" if score >= 0.30 else
            "Uncertain - review carefully"
        )
        return {
            "project": "ScamLens",
            **result,
            "scam_probability": result["model_scam_score"],
            "scam_probability_percent": result["model_scam_score_percent"],
            "risk_level": risk,
            "warning": (
                "Experimental, uncalibrated AI output. It is not a guarantee. "
                "Never share OTPs, PINs, passwords, or banking credentials."
            ),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {type(exc).__name__}")

@app.post("/check")
def check(request: MessageRequest):
    message = request.message.strip()
    if not message:
        raise HTTPException(status_code=422, detail="Please provide a non-empty message.")
    try:
        model_result = _classify(message)
        rule_result = check_message_rules(message)
        url_result = check_message_urls(message)
        risk, reasons = _combine_risk(model_result, rule_result, url_result)
        return {
            "project": "ScamLens",
            "version": app.version,
            **model_result,
            "rule_analysis": rule_result,
            "url_analysis": url_result,
            "overall_risk": risk,
            "reasons": reasons,
            "warning": (
                "Experimental screening can miss scams or flag legitimate messages. "
                "'No strong indicators found' does not mean safe. Verify via official "
                "channels and never share OTPs, PINs, passwords, or banking credentials."
            ),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Combined check failed: {type(exc).__name__}")
