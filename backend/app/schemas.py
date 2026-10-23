"""Pydantic request/response models (also drive the OpenAPI docs at /docs)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10_000, description="Message text to screen.")

    @field_validator("message")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Please provide a non-empty message.")
        return stripped


class Driver(BaseModel):
    source: str = Field(description="'rule' or 'url'")
    id: str
    strength: str = Field(description="'strong' or 'supporting'")


class CheckResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    project: str
    version: str
    endpoint_version: str
    model_available: bool
    predicted_label: Optional[int] = None
    category: Optional[str] = None
    model_scam_score: Optional[float] = None
    model_scam_score_percent: Optional[float] = None
    model_score_is_calibrated: bool = False
    rule_analysis: Dict[str, Any]
    url_analysis: Dict[str, Any]
    overall_risk: str
    reasons: List[str]
    drivers: List[Driver]
    advice: List[str]
    warning: str


class PredictResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=(), extra="allow")

    project: str
    predicted_label: int
    category: str
    model_scam_score: float
    model_scam_score_percent: float
    model_score_is_calibrated: bool
    scam_probability: float
    scam_probability_percent: float
    risk_level: str
    warning: str
