# Research and history (not part of the running app)

| File | Notes |
|---|---|
| `colab_notebook_export.py` | The original Colab export (`ScamLens.ipynb`): dataset inspection, TF-IDF baselines, Hinglish data creation, error-driven iterations, artifact export, link-checker prototype. Uses `/content/...` paths and `display()`; it is a record, not a runnable script |
| `exploratory_model_comparison.py` | Compares the four candidate artifacts on a 100-row candidate set (itself labelled non-independent) |
| `model_inventory.py` | Lists files/metadata in `/content/scamlens_model` |
| `legacy/` | Superseded `scam_rules` v2/v3 and `scamlens_api` v2/v3, kept for lineage. The current implementations live in `backend/app/` |

Caveats recorded in the notebook itself:

- The notebook's 100-message "independent" set was authored in the same session and used to compare models, so it is **not** independent.
- Several iterations were driven by development-set errors; scores from those iterations are not generalisation results.
- The Hinglish training set was template-expanded from a small number of seeds (300 rows, de-duplicated), so models may memorise phrasing.
