# Data

| Path | What it is | Rule |
|---|---|---|
| `eval/pilot_ai_authored_60_FROZEN.csv` | 60 AI-authored synthetic messages, `text,language,label` | **Frozen.** No training, tuning or rule-writing. Exploratory evaluation only |
| `templates/human_authored_holdout_template.csv` | Empty: 15 legit + 15 scam per language | Fill with sanitised human-written messages; evaluate once (`docs/EVALUATION_PROTOCOL.md`) |
| `templates/independent_test_100_template_EMPTY.csv` | Empty `text,is_scam` template from the notebook | Different schema. Convert before use |

Training data (the Hugging Face multiclass set and the Hinglish additions) is **not** included here: the base set is
downloaded in the notebook, and the Hinglish set was generated inside it. `backend/scripts/train_model.py` takes any CSV with
`text,label` (labels 0-4) and refuses paths that look like evaluation data.

Never put real OTPs, account numbers, names or phone numbers in any file in this directory.
