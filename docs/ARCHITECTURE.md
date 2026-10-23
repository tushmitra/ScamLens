# Architecture

```
Browser (React)  --POST /check-->  FastAPI (app/main.py)
                                      |
                                      v
                              app/service.analyze()
        +---------------+------------+--------------+
        v               v                           v
  scam_rules.py   link_checker.py            model_service.py (optional)
  flags+reasons   per-URL flags+reasons      label, uncalibrated score
        \_______________|___________________________/
                        v
                 risk_engine.combine_risk()
        band + reasons + drivers + advice
```

## Modules

| Module | Responsibility | Notes |
|---|---|---|
| `app/scam_rules.py` | Regex indicators; strong flags `credential_request`, `payment_demand`, `threat_or_consequence`, `authority_plus_action`; contextual `urgent_action`, `remote_access_request`, `money_mule_request`, `advance_fee_scam`, `investment_claim` | The "master" version. Protective advice ("never share your OTP") suppresses only `credential_request`, not other signals. No network, no dependencies |
| `app/link_checker.py` | Extract and inspect URLs, statically | Never resolves DNS or fetches. Registrable-domain aware (`www.sbi.co.in` is not flagged), token-based brand matching, obfuscated IPs, scheme-less shortener links, 20-URL cap |
| `app/model_service.py` | Load/verify the joblib artifact, score | Optional. Verifies model classes against metadata, records SHA-256, warns on scikit-learn version drift. Client output never includes paths |
| `app/risk_engine.py` | The combination policy | Pure functions; testable without a model |
| `app/service.py` | Orchestration, response assembly | Framework-free |
| `app/main.py` | HTTP layer: routes, CORS, rate limit, headers, error shaping | App factory `create_app()` for tests |
| `app/config.py` | Env-only configuration | See `backend/.env.example` |

## Risk policy (default)

| Band | When |
|---|---|
| **Suspicious** | any strong rule flag, any strong URL flag (`userinfo_present`, `ip_host`, `punycode_hostname`, `brand_in_subdomain`), or multiple independent signals (≥2 rule flags; a rule flag plus any URL flag; ≥2 non-shortener URL flags) |
| **Review carefully** | at least one weaker rule or URL signal (e.g. a shortener alone, `not_https`, `urgent_action` alone, `remote_access_request` alone) |
| **No strong indicators found** | nothing triggered. Explicitly not "safe" |

The model score does **not** change the band by default: it is uncalibrated and on a different scale from boolean
flags. An opt-in `SCAMLENS_MODEL_REVIEW_THRESHOLD` lifts an otherwise-empty result to *Review carefully* (never
*Suspicious*) when the model predicts a scam class at or above the threshold. See [STATUS.md](STATUS.md) for why this matters.

Every response includes `drivers` (which signals set the band, strong vs supporting) so the UI can explain itself.

## Safety properties (each covered by a test)

- URL checks perform no network access (a test blocks `socket.connect` while running them).
- Empty/oversized/malformed bodies get clean 422s that do not echo the input.
- Unexpected errors return a generic 500 (no stack trace, no paths); model-load failures expose only a reason code.
- Message bodies, URLs and query strings are never logged: method, path, status, duration and a request id only.
- CORS is limited to configured origins; responses carry `nosniff` and `no-store`.

## Compatibility with earlier versions

`GET /`, `GET /health`, `POST /predict` keep their previous shapes (`/predict` returns 503 instead of failing at
startup when no model is present). `/check` is a superset of the v3 response: the old keys are unchanged and
`endpoint_version`, `model_available`, `drivers`, `advice` are added; model fields are `null` without a model.
Superseded rule/API versions are kept in `research/legacy/` for lineage only.
