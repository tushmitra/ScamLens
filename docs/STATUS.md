# Project status and open decisions

_Assembled 23 Oct 2026 from the supplied planner, notebook export, rule/API versions, pilot files and frontend._

## Verified in the build environment

| Item | How verified |
|---|---|
| `link_checker`, `scam_rules`, `risk_engine`, `service`, `model_service`, rate limiter, config, train/evaluate/manifest scripts | 74 unit tests pass (run with a stand-in runner, since pytest could not be installed there) |
| Model path end-to-end | A tiny throwaway model was trained with `scripts/train_model.py`, loaded, scored, and rejected on class mismatch |
| Evaluation harness | Per-language report, Wilson intervals, ledger refusing a second holdout run, rejection of an unfilled template |
| `app/main.py`, `app/schemas.py` | Compile only |

## NOT verified. Please run these first

1. **`backend/tests/test_api.py` (HTTP layer)** needs `fastapi` + `httpx`, which could not be installed in the build sandbox (PyPI blocked). `cd backend && pip install -r requirements-dev.txt && python -m pytest` should run everything; fix anything it surfaces in `main.py` first.
2. **Frontend** (`npm test`, `npm run build`): npm was unreachable, so the TypeScript/React changes were not type-checked or run. Changes: nullable model fields, "What to do next" advice section, no-model message, 3 new test files/cases, one test fixed (`App.test.tsx` looked for the label "Message to check" while the UI label is "Message content"). No `package-lock.json` was supplied; run `npm install` once and commit it.
3. **Docker builds** were not run.

## Done vs the planner's definition of done

| Planner item | State |
|---|---|
| Pilot labelled "60 synthetic, AI-authored" | Done (`data/eval/…FROZEN.csv`, protocol, README) |
| No model tuned on the pilot | Respected; `train_model.py` refuses eval/pilot/holdout paths |
| word+char artifact saved separately and verified | **Open.** The artifact was not in the upload. `scripts/train_model.py` reproduces the pipeline; `models/README.md` has the export steps |
| Original `targeted_model.joblib` untouched | Cannot be checked here. Script refuses to write that name; `model_manifest.py` records hashes |
| `link_checker.py` static-only with tests | Done (a test fails if it opens a socket) |
| Rule flags for credential/payment/threat/authority+action | Done (+ remote-access, money-mule, advance-fee, investment) |
| Combined risk with reasons, never "safe" | Done |
| `/predict` preserved, `/check` documented | Done (`docs/API.md`, OpenAPI) |
| API + app integration tests | Written; not executed (see above) |
| README, privacy, no secrets/logging of messages | Done |
| Independent human-authored evaluation planned, unused for tuning | Template + enforcing harness ready; **set not yet collected** |

## Changes to the supplied code (and why)

- `scam_rules.py` = your "master" file (the only one with `we are your bank`, which your v3 test requires). Unchanged.
- `link_checker.py` was embedded in the notebook; extracted and fixed:
  - Real bug: `www.sbi.co.in` raised `brand_in_subdomain` (a *strong* flag, so "Suspicious") because the registrable domain ignored `co.in`-style suffixes.
  - Real bug: brand match was by substring, so `responsibility.example.com` (contains "sbi") and `pineapple.example.com` (contains "apple") were flagged.
  - Added obfuscated numeric IPs, scheme-less shortener links (`bit.ly/x`), a weak `brand_in_domain_label` flag, a 20-URL cap.
- `/check` is a superset of v3; the API starts without a model instead of crashing.

## Decisions for you

1. **The model never changes the risk band (v3 policy), but rules + URL alone catch little on the pilot.** Exploratory, descriptive run of the frozen rules + URL system on the pilot: scam recall 13.3% English, 33.3% Hinglish (legit false alarms 0/15 and 2/15). The pilot messages are deliberately keyword-light; the word+char model alone scored 73.3% / 60.0% on the same set. So with the default policy the combined system will miss most scams that use no trigger phrases. An opt-in switch exists: `SCAMLENS_MODEL_REVIEW_THRESHOLD` (e.g. `0.5`) lifts an otherwise-empty result to *Review carefully* when the model predicts a scam class. It is off by default; choose it on general grounds, not by fitting the pilot, and record the choice before the holdout run. No rules were edited after seeing the pilot.
2. `remote_access_request` and `money_mule_request` are *supporting* flags under the v3 policy, so on their own they give "Review carefully". If you want them strong, add them to `STRONG_RULE_FLAGS` in `risk_engine.py` (a test pins the current behaviour and will need updating).
3. Model promotion stays on hold per the pilot report. word+char is the provisional default only.
4. Collect the 30-60 human-authored messages (template provided) and run the holdout once after freezing code, model and policy.
