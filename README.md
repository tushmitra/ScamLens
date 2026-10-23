# ScamLens

Experimental screening for suspicious SMS, chat and email messages. Paste a message and ScamLens returns:

- **message-rule indicators** (credential requests, payment demands, threats, authority + action, remote-access, money-mule, advance-fee, investment claims; English and Romanized Hinglish),
- **static URL indicators** (shorteners, raw/obfuscated IPs, `user@host` tricks, punycode, misleading subdomains, odd TLDs). Links are never opened,
- an optional **text-model signal** (word + character TF-IDF, 5 classes), clearly marked uncalibrated,
- an **overall review band** with reasons and next-step advice. It never says "safe".

> ScamLens is a prototype. It can miss scams and flag legitimate messages. See [docs/STATUS.md](docs/STATUS.md) for what has and has not been verified.

## Quick start

```bash
# Backend (Python 3.11+)
cd backend
pip install -r requirements-dev.txt
python -m pytest
uvicorn app.main:app --reload --port 8000      # http://localhost:8000/docs

# Frontend (Node 20+)
cd frontend
npm install && cp .env.example .env
npm test && npm run dev                          # http://localhost:5173
```

Or `docker compose up --build` (UI on :8080, API on :8000). Shortcuts are in the `Makefile`.

The API runs **without a model** (rules + URL only, `model_available: false`). To add the model, put the artifact in
`backend/models/`; see [backend/models/README.md](backend/models/README.md).

## Layout

```
backend/
  app/            link_checker, scam_rules, risk_engine, model_service, service, schemas, main (FastAPI)
  scripts/        train_model.py, evaluate.py, model_manifest.py
  tests/          unit + API tests
  models/         model artifacts (not committed) + README
frontend/         React + TypeScript + Vite UI (from scamlens-frontend-modern)
data/
  eval/           FROZEN 60-message AI-authored pilot (never train or tune on it)
  templates/      empty human-authored holdout template (+ empty 100-row template)
docs/             planner, architecture, API, evaluation protocol, deployment, status, history
research/         original Colab export, model comparison scripts, superseded rules/API versions
```

## How the pieces fit

```
message -> rules ----\
        -> URLs ------+-> risk policy -> band + reasons + drivers + advice
        -> model* ---/        (* optional; context only unless opted in)
```

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Endpoints: [docs/API.md](docs/API.md).

## Responsible use

- Not proof of fraud and not a guarantee of safety. "No strong indicators found" ≠ safe.
- Never enter OTPs, PINs, passwords or card details into ScamLens or anywhere a message links to.
- The model score is **uncalibrated**; do not present it as a probability.
- The 60-message pilot is AI-authored and synthetic. Do not quote it as real-world accuracy. See [docs/EVALUATION_PROTOCOL.md](docs/EVALUATION_PROTOCOL.md).
- Message bodies and URLs are not logged by default.
