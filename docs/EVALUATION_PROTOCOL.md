# Evaluation protocol

This turns Phase 8 of the planner into something the tooling enforces (`backend/scripts/evaluate.py`).

## Data rules

| Set | Status | Rule |
|---|---|---|
| `data/eval/pilot_ai_authored_60_FROZEN.csv` | Frozen. 60 AI-authored synthetic messages (30 English, 30 Hinglish; 15 legitimate + 15 scam each) | Never train, tune thresholds/rules/features on it. Describe as "pilot, synthetic, AI-authored". Exploratory runs only |
| `data/templates/human_authored_holdout_template.csv` | Empty template: 15 legit + 15 scam per language | Fill with 30-60 human-written messages (sanitised: no names, numbers, account IDs, OTPs). Keep out of training and rule-writing |
| `data/templates/independent_test_100_template_EMPTY.csv` | Empty `text,is_scam` template from the notebook | Different schema; convert to `text,language,label` before using with the harness |

Label `0` = legitimate; any other label = scam. If contributors write fictional examples, record them as
*human-authored synthetic*, not "real-world".

## Procedure (holdout)

1. Freeze code, model artifact (record SHA-256 with `scripts/model_manifest.py`) and risk policy, including `SCAMLENS_MODEL_REVIEW_THRESHOLD` if used.
2. Run once:
   `python scripts/evaluate.py --data <set>.csv --mode holdout --provenance human_authored_synthetic --system combined`
   and, for the breakdown, `--system rules` and `--system model` (each is a separate run, so use `--mode exploratory` for the extra breakdowns, or evaluate them on the same freeze before looking at any result).
3. The harness records the dataset hash in `reports/eval_ledger.jsonl` and **refuses a second holdout run on the same file**. A new version needs a new set.
4. Report, per language (English and Hinglish separately): scam recall, scams missed, legitimate false alarms, sample sizes, 95% interval, and model-only vs combined system.
5. Do not change the model, rules or thresholds in response, then report the same set as independent.

## Alert definitions (fixed in advance)

- **flagged**: band is `Suspicious` or `Review carefully` (model-only system: predicted label ≠ 0).
- **suspicious**: band is `Suspicious` only.

Both are reported. Neither is "accuracy". With 15 scam messages per language, each miss moves recall by 6.67 points and the
95% interval is roughly ±25 points; treat results as an initial signal.

## What has been run so far

| Run | Mode | Notes |
|---|---|---|
| Model comparison on the pilot (see `docs/history/pilot_evaluation_report.md`) | exploratory (pre-existing) | word+char best on English recall; no promotion |
| Rules + URL system on the pilot (`docs/history/pilot_runs/`) | exploratory, run once after the rules were frozen, no changes made afterwards | Scam recall (flagged): English 13.3% (2/15), Hinglish 33.3% (5/15); legitimate false alarms: English 0/15, Hinglish 2/15. Descriptive only |
| Any human-authored holdout | **not yet run** | |

The notebook's 100-message "independent" set was authored in the same notebook session and used to compare models,
so it is not an independent benchmark either (see `research/README.md`).
