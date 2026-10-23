# API

Interactive docs: `GET /docs` (OpenAPI). Base URL in development: `http://localhost:8000`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | service info |
| GET | `/health` | liveness + model state (reason code only, no paths) |
| POST | `/predict` | legacy: text model only. `503` when no model is loaded |
| POST | `/check` | combined rules + URLs + optional model, with risk band |

## Request

```json
{ "message": "Your bank account will be blocked. Share your OTP now: https://bit.ly/example." }
```

`message`: 1 to 10,000 characters after trimming. Whitespace-only is rejected.

## `POST /check` response

```json
{
  "project": "ScamLens",
  "version": "1.3.0",
  "endpoint_version": "1.2",
  "model_available": false,
  "predicted_label": null,
  "category": null,
  "model_scam_score": null,
  "model_scam_score_percent": null,
  "model_score_is_calibrated": false,
  "rule_analysis": {
    "flags": ["credential_request", "threat_or_consequence"],
    "reasons": ["The message may be asking the recipient to disclose a sensitive credential.", "..."],
    "flag_count": 2,
    "disclaimer": "Rule flags are heuristic indicators, not proof of fraud. ..."
  },
  "url_analysis": {
    "url_count": 1,
    "urls": [{ "url": "https://bit.ly/example", "valid": true, "hostname": "bit.ly",
               "registrable_domain": "bit.ly", "flags": ["url_shortener"], "reasons": ["..."] }],
    "has_suspicious_url": true,
    "reasons": ["1 of 1 URL(s) have review indicators."],
    "disclaimer": "Indicators are heuristic, not proof of fraud. An unflagged URL is not guaranteed safe."
  },
  "overall_risk": "Suspicious",
  "reasons": ["..."],
  "drivers": [{ "source": "rule", "id": "credential_request", "strength": "strong" }],
  "advice": ["Banks, police and government offices never ask for your OTP, PIN or password by message or call.", "..."],
  "warning": "Experimental screening can miss scams or flag legitimate messages. ..."
}
```

- `overall_risk` ∈ `Suspicious` | `Review carefully` | `No strong indicators found`.
- With a model loaded, `predicted_label` (0 Legitimate, 1 Government impersonation, 2 Financial fraud, 3 Bank phishing, 4 Romance/parcel/sextortion), `category`, `model_scam_score` (= 1 − P(class 0)) are populated. `model_score_is_calibrated` is always `false`.
- `drivers[].source` is `rule`, `url` (or `model` when the opt-in review threshold lifted the band).
- URL flags: `url_shortener`, `ip_host`, `userinfo_present`, `punycode_hostname`, `invalid_idn`, `brand_in_subdomain`, `brand_in_domain_label`, `uncommon_tld`, `many_subdomains`, `long_hostname`, `not_https`, `malformed_url`.

## `POST /predict` (legacy)

Returns `predicted_label`, `category`, `model_scam_score(_percent)`, `model_score_is_calibrated`, compatibility aliases
`scam_probability(_percent)`, `risk_level`, `warning`. The "probability" aliases are the same uncalibrated score.

## `GET /health`

```json
{ "status": "healthy", "version": "1.3.0", "endpoint_version": "1.2",
  "checks": { "rules": true, "url_checker": true },
  "model_loaded": false, "model_artifact": null, "model_candidate": null,
  "model_artifact_sha256": null, "model_unavailable_reason": "artifact_missing",
  "model_score_is_calibrated": false }
```

Reason codes: `artifact_missing`, `metadata_missing`, `metadata_invalid`, `class_mismatch`, `no_legitimate_class`, `load_failed`.

## Errors

All errors are `{"detail": "<string>"}`. `422` invalid message, `429` rate limited (with `Retry-After`), `503` model required but absent (`/predict`), `500` generic.
