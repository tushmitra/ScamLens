# Model artifacts

Artifacts are **not committed** (see `.gitignore`); they are large, version-sensitive and may be re-exported.

Expected files (names are configurable via env vars):

| File | Role |
|---|---|
| `word_char_candidate.joblib` + `word_char_candidate_metadata.json` | Provisional app model (word + char TF-IDF, Logistic Regression) |
| `targeted_model.joblib` + `metadata.json` | **Rollback backup. Never overwrite.** `scripts/train_model.py` refuses to write these names |

Without an artifact the API still runs and reports `model_available: false` (rules + URL signals only).
Set `SCAMLENS_REQUIRE_MODEL=true` to make a missing/invalid model a startup error instead.

## Getting the artifact in place
1. In the Colab runtime, locate `/content/scamlens_model/word_char_candidate.joblib` and its `_metadata.json`
   (the notebook export saves both; `research/model_inventory.py` lists them) and download both here.
2. Check the metadata labels are `0..4` and the model's classes match (the API verifies this at startup).
3. Install the same scikit-learn version used in Colab (`python -c "import sklearn; print(sklearn.__version__)"` there).
4. `python scripts/model_manifest.py` to record sizes and SHA-256 hashes in `MANIFEST.json`.

Or retrain reproducibly: `python scripts/train_model.py --help`.
