# ScamLens — Detailed Project Planner

**Planning baseline:** 14 October 2026  
**Current stage:** Model pilot recorded; stop model tuning and move to link checker, API, and app engineering.  
**Primary objective:** Build a usable, testable ScamLens prototype that combines message classification, explainable rule flags, and URL-risk indicators without presenting experimental scores as proven real-world probabilities.

---

## 1. Project goal and boundaries

### Goal
A user submits a suspicious SMS, chat message, email excerpt, or message containing one or more URLs. ScamLens returns:
- an experimental text-model prediction and category;
- explicit rule flags, with reasons;
- URL-risk indicators for links found in the text;
- an overall review recommendation and practical safety advice.

### In scope for this iteration
1. Preserve the existing API behavior while adding a combined `/check` endpoint.
2. Provisionally use the word + character TF-IDF model for the app's text-model signal, once that pipeline is exported and verified.
3. Keep the existing `targeted_model.joblib` untouched as a backup.
4. Add general scam-pattern rules based on the planned scam types—not rules derived from the 60-message pilot's individual errors.
5. Add static URL inspection: extraction, normalization, shortener detection, hostname parsing, IP-host detection, suspicious URL endings, misleading subdomains, and basic lookalike-domain heuristics.
6. Integrate the API into the app and show reasons and uncertainty.
7. Test the system using repeatable unit and API tests.
8. Later, evaluate once on a genuinely independent, human-authored set of 30–60 messages, reporting English and Hinglish separately.

### Explicitly out of scope for this iteration
- Further model tuning or threshold tuning against the 60-message synthetic pilot.
- Claims that the pilot establishes real-world accuracy or proves one model is superior.
- Treating an uncalibrated model output as a reliable real-world probability.
- Automatically opening, crawling, or executing content from submitted URLs.
- Guaranteeing that any message or URL is safe.
- Adding a third-party URL reputation provider before the local checker and API are stable.

---

## 2. Current baseline and constraints

### Existing API file
The supplied `scamlens_api.py` currently:
- loads `/content/scamlens_model/targeted_model.joblib`;
- loads `/content/scamlens_model/metadata.json`;
- exposes `GET /`, `GET /health`, and `POST /predict`;
- accepts a `message` field up to 10,000 characters;
- calls `predict()` and `predict_proba()`;
- treats label `0` as legitimate and calculates `1 - P(label 0)` as a scam score;
- returns a category, score, risk label, and warning.

### Required compatibility
- Keep `/predict` working for existing callers.
- Add `/check` for the combined experience rather than silently changing the old response contract.
- Preserve the existing label mapping from metadata.
- Do not overwrite `targeted_model.joblib`; retain it as the rollback artifact.
- The API currently expects Colab paths. Move model and metadata paths to environment variables or a small configuration section before deployment, with clear startup errors if files are missing.
- Verify that the selected word + character pipeline is exported from the notebook and that its class labels match the metadata before making it the default.

### Model-evaluation decision
The recorded 60-message set is a **pilot, 60 synthetic messages**; the messages were AI-authored. The set contains 30 English and 30 Hinglish examples, balanced between legitimate and scam messages within each language. It is useful for a small exploratory comparison, but it is not a human-authored independent benchmark.

The pilot is frozen:
- do not train on it;
- do not use it to design new individual rules;
- do not adjust thresholds or features based on its individual errors;
- keep the report and CSV as recorded;
- describe results as pilot observations only.

The word + character model is a provisional engineering default, not a proven winner. The existing model remains the backup.

---

## 3. Recommended architecture

```text
User message
    |
    v
Input validation and normalization
    |
    +--------------------------+
    |                          |
    v                          v
Text classifier           URL extractor
    |                          |
    v                          v
Model label/score          Static URL checks
    |                          |
    +------------+-------------+
                 |
                 v
          Scam-pattern rules
                 |
                 v
       Signal combination layer
                 |
                 v
      Overall risk + explanations
                 |
                 v
          API response / app UI
```

### Suggested modules
- `scamlens_api.py`: FastAPI routes, request/response validation, orchestration.
- `link_checker.py`: URL extraction, parsing, and static URL indicators; no network requests in the MVP.
- `scam_rules.py`: message-pattern rules and rule explanations.
- `risk_engine.py`: combines model, rules, and URL indicators using documented, configurable logic.
- `tests/test_link_checker.py`: URL parsing and indicator tests.
- `tests/test_scam_rules.py`: rule tests.
- `tests/test_api.py`: request validation, endpoints, output schema, and error handling.
- `requirements.txt`: pinned or bounded runtime dependencies.
- `.env.example`: configuration names only, no secrets.
- `README.md`: setup, endpoints, limitations, and responsible-use warning.

Keep the first implementation simple: if introducing all modules at once makes integration difficult, begin with `link_checker.py` and `scam_rules.py`, then extract `risk_engine.py` when the behavior is tested.

---

## 4. Phase-by-phase implementation plan

## Phase 0 — Freeze the pilot and establish a clean baseline

**Tasks**
1. Keep `ScamLens_Detailed_Project_Planner.md`, the pilot report, and pilot CSV together in project documentation.
2. Label the dataset and report clearly: **pilot, 60 synthetic messages — AI-authored**.
3. Make a separate copy of the current model artifact before any model-path change.
4. Export the word + character pipeline from the notebook to a new artifact filename. Do not replace the backup.
5. Confirm model classes, feature pipeline, and metadata label mapping.
6. Record the exact artifact filenames and hashes in a local manifest or README.

**Acceptance criteria**
- The old model file is unchanged and can still be loaded.
- The new word + character artifact loads in a fresh runtime.
- A smoke test predicts all required output fields without exceptions.
- No code or training process uses the pilot file as training input.

**Stop condition:** If the word + character artifact cannot be exported and verified, do not point the API at a guessed path. Resolve the artifact first or temporarily keep the current model while link/API engineering continues.

## Phase 1 — Implement `link_checker.py`

**MVP behavior**
1. Extract multiple `http://` and `https://` URLs from a message.
2. Handle common trailing punctuation without corrupting valid URL characters.
3. Parse hostnames with a standard URL parser; normalize hostname casing and internationalized domain names carefully.
4. Identify:
   - known URL-shortener hostnames from a small, documented list;
   - raw IPv4/IPv6 hosts;
   - suspicious or uncommon top-level-domain endings using a configurable heuristic list;
   - misleading hostname structure, such as a trusted brand appearing only in a subdomain of an unrelated registrable domain;
   - `@` user-info tricks and other parsing ambiguities;
   - punycode/IDN hostnames for extra review;
   - non-HTTPS schemes or malformed URLs where relevant.
5. Return structured indicators, not a simple “safe/unsafe” assertion.
6. Support messages with no URLs and messages with several URLs.
7. Keep all checks static: **do not fetch the URL, follow redirects, load a webpage, or execute remote content** in this MVP.

**Suggested result shape**
```json
{
  "url_count": 1,
  "urls": [
    {
      "url": "https://example.test/path",
      "hostname": "example.test",
      "flags": ["shortener", "idn_hostname"],
      "reasons": ["The link uses a URL-shortening service."]
    }
  ],
  "has_suspicious_url": true,
  "reasons": ["One URL has indicators that warrant checking."]
}
```

This is an illustrative schema; finalize field names once API response models are implemented.

**Important safety details**
- Do not assume every shortener or unusual TLD is malicious.
- Do not flag a brand merely because its name appears anywhere in the URL; parse the hostname and registrable-domain boundary.
- Do not use substring checks as the only defense against deceptive subdomains.
- Do not resolve DNS or contact hosts in the first version.
- Avoid logging full user messages or full URLs by default; they may contain private tokens or personal data.

**Acceptance criteria**
- Correctly extracts zero, one, and multiple URLs.
- Trailing commas/periods are handled without stripping valid path content.
- Host parsing is deterministic for malformed input.
- Each flag has a human-readable explanation.
- No network access is performed by the checker.

## Phase 2 — Implement `scam_rules.py`

Rules must reflect broad scam patterns in the project plan, not the specific mistakes made on the frozen pilot.

### Rule families
1. **Credential request:** asks for OTP, one-time password, PIN, password, CVV, or banking credentials.
2. **Payment demand:** asks for a fee, deposit, advance payment, processing charge, release fee, or urgent transfer.
3. **Threat or consequence:** arrest, account blocking/freezing, SIM disconnection, service suspension, legal action, or a deadline-driven penalty.
4. **Authority impersonation plus action:** claims to be from a bank, police, government agency, courier, or official service **and** includes a link, request to call immediately, credential request, or payment demand.
5. **Urgency/manipulation:** “act now,” “immediately,” “within minutes,” or similar urgency. This should generally be a supporting indicator rather than sufficient evidence alone.

**Implementation guidance**
- Normalize case and whitespace; do not destroy the original message used for display.
- Use conservative phrase lists and word-boundary-aware patterns where possible.
- Support English and Romanized Hinglish phrases, including common variants such as “OTP bhejo,” “account block ho jayega,” “abhi pay karo,” and “KYC update karo.” Treat these as patterns, not a complete language model.
- Return rule IDs, matched category, and a short reason. Avoid exposing a large raw matched substring if it may contain sensitive information.
- Add explicit legitimate counterexamples to test false-positive behavior, such as warning someone not to share an OTP or a person discussing a scam academically.
- Never let a single vague word such as “bank,” “urgent,” or “payment” automatically label a message as a scam.

**Acceptance criteria**
- Each rule family has positive and negative unit tests.
- Authority claims alone do not automatically produce a high-risk result.
- The combined authority rule requires the planned action/link/urgency condition.
- Rules are not created by inspecting the pilot's individual false negatives.

## Phase 3 — Build the risk-combination layer

The result should combine three independent signal groups:
- text-model output;
- scam-pattern rule flags;
- URL indicators.

### Recommended decision design
1. Preserve the raw model score as `model_scam_score` or equivalent.
2. Keep rule and URL indicators separately visible.
3. Calculate a separate `overall_risk` or `review_score` using documented configurable weights/floors.
4. Make explicit rules and severe URL indicators capable of escalating a result even when the text model score is low.
5. Choose a recall-oriented “Suspicious” policy for the prototype, but document that this will increase false alarms.
6. Do not label the combined score as a calibrated probability unless a proper calibration study is done.
7. Avoid a blind numerical maximum between scores with different meanings. A boolean rule flag is not inherently on the same scale as an uncalibrated model score. Use an explicit escalation policy or map signal types to documented risk bands.

### Suggested risk bands
- **Suspicious:** a strong credential/payment/threat rule, a high-concern URL signal, or multiple independent supporting signals.
- **Review carefully:** one weaker signal or uncertain model result.
- **No strong indicators found:** no signals crossed the configured threshold. This must not say “safe.”

Exact thresholds should be configurable and selected using general policy considerations, not tuned on the frozen synthetic pilot. Keep the initial policy transparent and conservative.

**Acceptance criteria**
- Output explains which signals drove the final recommendation.
- A strong rule or URL indicator can raise the risk band.
- The model score remains available for debugging and evaluation.
- No response promises that a message is safe.
- The risk combination can be unit-tested without loading the model.

## Phase 4 — Extend FastAPI without breaking `/predict`

### Existing routes
- `GET /`: basic service information.
- `GET /health`: basic health information.
- `POST /predict`: existing text-only model response.

### Add
- `POST /check`: message classification + rule flags + URL checks + combined risk + safety advice.
- Optionally add `GET /version` or include model/artifact version in `/health` if useful for debugging.

### Request validation
- Keep a reasonable maximum message length (currently 10,000 characters).
- Reject empty/whitespace-only messages.
- Handle invalid input and model failures with clear HTTP status codes.
- Do not return stack traces or local filesystem details to clients.
- Avoid storing request contents unless explicitly required and disclosed.

### Example combined response
```json
{
  "project": "ScamLens",
  "endpoint_version": "1.1",
  "predicted_label": 3,
  "category": "Bank phishing",
  "model_scam_score": 0.64,
  "model_score_is_calibrated": false,
  "rule_flags": [
    {
      "rule_id": "credential_request",
      "reason": "The message appears to request a sensitive credential."
    }
  ],
  "url_analysis": {
    "url_count": 1,
    "has_suspicious_url": true,
    "reasons": ["The URL has indicators that warrant checking."]
  },
  "overall_risk": "Suspicious",
  "reasons": [
    "Credential-request pattern detected.",
    "The URL has indicators that warrant checking."
  ],
  "warning": "Experimental checks can miss scams and can flag legitimate messages. Do not share OTPs, PINs, passwords, or banking credentials."
}
```

This is an example contract, not an assertion about the current API's output. Finalize it in code and document it in `/docs`.

**Acceptance criteria**
- Existing `/predict` callers continue to work.
- `/check` returns a stable, documented schema.
- `/health` checks required dependencies and model load state accurately.
- Missing artifacts produce a useful startup message.
- No secrets, stack traces, or local paths leak in client-facing errors.

## Phase 5 — Testing and quality gates

### Unit tests: link checker
- no URL;
- one ordinary URL;
- multiple URLs in one message;
- trailing punctuation;
- URL shortener;
- raw IP host;
- deceptive subdomain;
- `@` user-info trick;
- punycode/IDN hostname;
- suspicious TLD heuristic;
- malformed URL;
- unsupported scheme;
- benign unusual URL to check false positives.

### Unit tests: rules
- OTP/PIN/password request;
- legitimate security advice mentioning OTP;
- fee/deposit demand;
- ordinary bill/payment discussion;
- account-blocking threat;
- neutral explanation of a bank account being blocked;
- authority claim with link/action;
- authority name without a suspicious action;
- English and Romanized Hinglish variants.

### API tests
- root and health endpoints;
- valid `/predict`;
- valid `/check` with no URL;
- `/check` with multiple URLs;
- blank message;
- oversized message;
- malformed request body;
- model exception;
- stable response fields and types.

### Manual integration checklist
- run API in a fresh runtime;
- open `/docs`;
- test an ordinary legitimate message;
- test an obvious credential-request scam;
- test a payment-pressure message;
- test a message with a suspicious URL;
- test a legitimate message containing a benign URL;
- verify reasons are understandable and not contradictory;
- verify the app handles API timeouts and errors.

**Release gate:** all tests pass, model artifact loads cleanly, and the app never displays “guaranteed safe.”

## Phase 6 — App integration

**UI flow**
1. Large text input with a clear example placeholder.
2. “Check message” action and loading state.
3. Overall risk band with a short explanation.
4. Separate sections for:
   - AI text prediction;
   - message rule flags;
   - each detected URL and its flags;
   - recommended next steps.
5. Visible note: “ScamLens is experimental. No detected warning signs does not guarantee safety.”
6. Error state for API unavailable, invalid input, or timeout.
7. Responsive layout and accessible labels.

**User-safety copy**
- Never ask users to paste passwords, OTPs, full card details, or other secrets.
- Do not encourage users to click a suspicious URL to “test” it.
- Advise users to verify through an official app, known phone number, or manually entered official website—not through the suspicious message's link or number.

**Acceptance criteria**
- App shows the difference between model prediction and deterministic indicators.
- Each warning has a reason.
- The UI never promises certainty.
- It remains usable on desktop and mobile.
- API errors are handled without exposing internals.

## Phase 7 — Deployment readiness

Before deployment:
- move paths and settings to environment variables;
- pin or constrain dependencies;
- add a reproducible startup command;
- add `.env.example` without secrets;
- confirm model and metadata files are included in the deployment strategy;
- verify the platform can host the model artifact and has sufficient memory;
- configure CORS narrowly for the real app origin;
- avoid logging message bodies and query-string tokens;
- set request-size and timeout limits;
- add a basic rate limit if publicly accessible;
- use HTTPS;
- add a README section explaining experimental limitations;
- run the test suite in the same Python/runtime version used for deployment.

Do not deploy the API with hard-coded `/content/...` paths unless the hosting environment truly uses that path. Do not commit API keys or private datasets.

## Phase 8 — Independent human-authored evaluation

This happens after the product flow is stable; it is not a reason to delay link checker and app work.

### Collection
- Aim for 30–60 messages written or contributed by people, with permission to use them for evaluation.
- Include English and Romanized Hinglish.
- Include legitimate and scam-like messages, plus borderline cases.
- Remove names, phone numbers, account numbers, addresses, OTPs, tracking IDs, and other personal details.
- Do not ask contributors to send real credentials or click links.
- Record whether examples are paraphrased or fictionalized; do not claim a real-world origin if they are synthetic.
- Keep this set out of training and rule-writing.

### Pre-agreed evaluation protocol
1. Freeze the code, model artifact, and risk policy before running the set.
2. Define labels and the scam/legitimate grouping before scoring.
3. Run the evaluation once.
4. Report English and Hinglish separately.
5. Report scam recall, scams missed, legitimate false alarms, sample counts, and uncertainty/limitations.
6. Include the model-only and combined-system outputs separately where possible.
7. Do not change the model, rules, or threshold based on the test results and then report the same set as independent. Any subsequent version needs a new holdout set.

### Interpretation
Thirty to sixty messages are still a small sample. Treat the results as an initial human-authored evaluation, not proof of broad real-world effectiveness. If contributors provide only fictional examples, label them as human-authored synthetic examples, not naturally occurring messages.

---

## 5. Timeline and milestones

The original planning constraint was to finish model comparison by 17 October and stop model work around 20 October. The model comparison is now recorded, so the remaining time should prioritize product engineering rather than more experiments.

| Window | Focus | Deliverable |
|---|---|---|
| 14 Oct | Freeze pilot; inspect API baseline; export and verify word + character candidate without replacing backup | Pilot report/CSV retained; model artifacts identified |
| 15 Oct | Build and unit-test `link_checker.py` | Static URL analysis module |
| 16 Oct | Add `scam_rules.py` and transparent risk combination | Rule flags and documented escalation policy |
| 17 Oct | Add `/check`; preserve `/predict`; API tests | Stable combined API |
| 18 Oct | Integrate app UI and error states | End-to-end message check flow |
| 19 Oct | Run regression, safety, and deployment checks; write README | Release-candidate prototype |
| 20 Oct | Buffer for integration defects; freeze model work | Stable build; no more pilot-driven tuning |
| After 20 Oct | Collect/prepare independent human-authored messages in parallel with product hardening; evaluate once after code/model/policy freeze | Separate English/Hinglish report |

Dates are targets, not a reason to skip tests. If a phase slips, prioritize a safe, working vertical slice over adding untested features.

---

## 6. Definition of done

ScamLens is ready for a limited prototype demonstration when:
- [ ] pilot report clearly says “pilot, 60 synthetic messages” and identifies AI authorship;
- [ ] no model has been tuned against the pilot;
- [ ] word + character artifact is saved separately and verified;
- [ ] original `targeted_model.joblib` remains unchanged as backup;
- [ ] `link_checker.py` is static-only and has unit tests;
- [ ] rule flags cover credential requests, payment demands, threats, and authority-plus-action patterns;
- [ ] combined risk returns understandable reasons and does not call a result “safe”;
- [ ] `/predict` still works and `/check` is documented;
- [ ] API and app integration tests pass;
- [ ] README documents setup, artifact paths, endpoint schemas, privacy, and limitations;
- [ ] no secrets or full message contents are logged by default;
- [ ] independent human-authored evaluation is planned separately and has not been used for tuning.

---

## 7. Immediate next actions

1. Confirm the word + character model artifact exists in the current Colab runtime and export it under a new filename; keep the backup untouched.
2. Implement `link_checker.py` first, with tests, and no network access.
3. Implement general-purpose scam rules from the project plan.
4. Add the signal-combination layer and `/check` endpoint.
5. Run the API tests, then connect the app.
6. Keep the 60-message synthetic pilot frozen.
7. Only after the app and policy are frozen, run the independent human-authored evaluation once.

**Current limitation:** the supplied file shows the API but not the main app, repository layout, or the actual saved word + character artifact path. Those need to be verified during implementation rather than assumed.
