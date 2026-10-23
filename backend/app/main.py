"""ScamLens FastAPI application.

Run:  uvicorn app.main:app --host 0.0.0.0 --port 8000      (from the backend/ directory)

Routes: GET /, GET /health, POST /predict (legacy, model only), POST /check (combined).
Privacy: message bodies and URLs are never logged; errors never expose paths or stack traces.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from . import ENDPOINT_VERSION, __version__
from .config import Settings
from .model_service import ModelService, ModelUnavailable
from .ratelimit import SlidingWindowLimiter
from .schemas import CheckResponse, MessageRequest, PredictResponse
from .service import analyze, predict_only

logger = logging.getLogger("scamlens.api")


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limiter: SlidingWindowLimiter, trust_proxy_headers: bool):
        super().__init__(app)
        self.limiter = limiter
        self.trust_proxy_headers = trust_proxy_headers

    def _client_key(self, request: Request) -> str:
        if self.trust_proxy_headers:
            forwarded = request.headers.get("x-forwarded-for", "")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        if request.method == "POST" and not self.limiter.allow(self._client_key(request)):
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please wait a moment and try again."},
                headers={"Retry-After": "60"},
            )
        return await call_next(request)


class RequestLogMiddleware(BaseHTTPMiddleware):
    """Logs method, path, status and duration only. Never the body or query string."""

    async def dispatch(self, request: Request, call_next):
        request_id = uuid.uuid4().hex[:12]
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        logger.info("%s %s -> %s in %.0fms [%s]", request.method, request.url.path,
                    response.status_code, elapsed_ms, request_id)
        return response


def create_app(settings: Optional[Settings] = None, model_service: Optional[ModelService] = None) -> FastAPI:
    settings = settings or Settings.from_env()
    logging.basicConfig(level=getattr(logging, settings.log_level, logging.INFO))
    service = model_service or ModelService(
        settings.resolved_model_path, settings.resolved_metadata_path, settings.require_model
    )
    if model_service is None:
        service.load()  # raises only when SCAMLENS_REQUIRE_MODEL=true

    app = FastAPI(
        title="ScamLens API",
        description=(
            "Experimental scam screening combining message-pattern rules, static URL inspection "
            "and an optional text classifier. Results are indicators, not proof of fraud, and "
            "'No strong indicators found' never means safe."
        ),
        version=__version__,
    )
    app.state.model_service = service
    app.state.settings = settings

    app.add_middleware(RateLimitMiddleware, limiter=SlidingWindowLimiter(settings.rate_limit_per_minute),
                       trust_proxy_headers=settings.trust_proxy_headers)
    app.add_middleware(RequestLogMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Accept"],
    )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError):
        # Do not echo the submitted input back to the client.
        problems = exc.errors()
        detail = "Invalid request."
        if problems:
            first = problems[0]
            if first.get("type") == "string_too_long":
                detail = f"Messages must be {settings.max_message_chars:,} characters or fewer."
            elif first.get("type") in {"string_too_short", "missing"} or "non-empty" in str(first.get("msg", "")):
                detail = "Please provide a non-empty message."
        return JSONResponse(status_code=422, content={"detail": detail})

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        logger.error("Unhandled error: %s", type(exc).__name__)
        return JSONResponse(status_code=500, content={"detail": "Internal error. Please try again."})

    def _check_length(message: str) -> None:
        if len(message) > settings.max_message_chars:
            raise HTTPException(
                status_code=422,
                detail=f"Messages must be {settings.max_message_chars:,} characters or fewer.",
            )

    @app.get("/")
    def home():
        return {"project": "ScamLens", "status": "running", "documentation": "/docs", "version": __version__}

    @app.get("/health")
    def health():
        return {
            "status": "healthy",
            "version": __version__,
            "endpoint_version": ENDPOINT_VERSION,
            "checks": {"rules": True, "url_checker": True},
            **service.health(),
        }

    @app.post("/predict", response_model=PredictResponse)
    def predict(request: MessageRequest):
        """Legacy text-model-only endpoint, kept for existing clients."""
        _check_length(request.message)
        try:
            return predict_only(request.message, service)
        except ModelUnavailable:
            raise HTTPException(status_code=503, detail="The text model is not available on this server.")
        except Exception as exc:  # noqa: BLE001
            logger.error("Prediction failed: %s", type(exc).__name__)
            raise HTTPException(status_code=500, detail=f"Prediction failed: {type(exc).__name__}")

    @app.post("/check", response_model=CheckResponse)
    def check(request: MessageRequest):
        """Combined model (if loaded) + message rules + static URL checks + risk policy."""
        _check_length(request.message)
        try:
            return analyze(request.message, service, settings.model_review_threshold)
        except Exception as exc:  # noqa: BLE001
            logger.error("Combined check failed: %s", type(exc).__name__)
            raise HTTPException(status_code=500, detail=f"Combined check failed: {type(exc).__name__}")

    return app


app = create_app()
