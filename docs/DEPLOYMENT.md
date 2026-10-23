# Deployment checklist

Mapped from planner Phase 7. Tick these before exposing the API publicly.

**Configuration**
- [ ] Copy `backend/.env.example` into your platform's secret/config store. No `/content/...` Colab paths: set `SCAMLENS_MODEL_DIR` (or the explicit path vars).
- [ ] Mount the model directory read-only (`-v ./backend/models:/models:ro`); do not bake artifacts into the image.
- [ ] Once a model is deployed, set `SCAMLENS_REQUIRE_MODEL=true` so a missing/invalid artifact fails at startup instead of silently degrading to rules-only.
- [ ] Install the same scikit-learn version the model was trained with (`sklearn_version` in the metadata). The API warns on drift.
- [ ] `SCAMLENS_CORS_ORIGINS` = the exact frontend origin(s) only.

**Network and abuse controls**
- [ ] Serve over HTTPS (terminate at the proxy/platform).
- [ ] Keep `SCAMLENS_RATE_LIMIT_PER_MINUTE` on. The built-in limiter is per process. Behind several workers/instances, enforce limits at the gateway too.
- [ ] Set `SCAMLENS_TRUST_PROXY_HEADERS=true` only if a trusted proxy sets `X-Forwarded-For`; otherwise clients could spoof it.
- [ ] Set request-size and timeout limits at the proxy (the app caps `message` at 10,000 characters).

**Privacy**
- [ ] Keep logging at the default: method, path, status, duration, request id. Do not add request-body or URL logging.
- [ ] The frontend stylesheet imports Google Fonts, which makes a third-party request on page load (not containing message text). Self-host the fonts if that matters for your deployment.
- [ ] The frontend sends the pasted text only to your configured API, and only on **Analyze**.

**Release gate (from the planner)**
- [ ] `python -m pytest` passes in the runtime/Python version you deploy (including `tests/test_api.py`).
- [ ] `npm test && npm run build` passes.
- [ ] Manual pass: ordinary legitimate message; OTP-request scam; payment-pressure message; suspicious URL; legitimate message with a benign URL; blank input; API down (UI shows an error, not a verdict).
- [ ] The UI never shows "safe" or "guaranteed".

**Docker**: `docker compose up --build` builds both images. Set `VITE_SCAMLENS_API_URL` as a build arg for the real API URL (Vite variables are public and baked into the bundle, so never put secrets in them).
