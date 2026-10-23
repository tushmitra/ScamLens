# ScamLens — Pilot Evaluation Report

**Evaluation type:** AI-authored synthetic challenge pilot  
**Date recorded:** 14 October 2026  
**Test set size:** 60 messages  
**Languages:** 30 English, 30 Hinglish  
**Balance:** In each language, 15 legitimate messages and 15 scam messages  
**Overlap check:** 0 exact normalized overlaps and 0 rows flagged by the configured similarity-review heuristic. This does not prove semantic independence.

## Purpose and limitations

This is a small, AI-authored synthetic pilot intended to compare model behavior on borderline-style examples. It is **not** a genuinely independent, human-authored benchmark and must not be presented as real-world performance. With only 15 scam examples per language, each missed scam changes recall by approximately 6.67 percentage points. Similarity screening is heuristic and cannot rule out semantic leakage or author/model-style bias.

The pilot has now been evaluated. Do not use these 60 examples to tune features, labels, thresholds, training data, or model parameters. Keep the results as recorded and move model development forward without further fitting to this test set.

## Results

| Model | Language | Scam recall | Scams missed | Legitimate false alarms | Legitimate messages |
|---|---|---:|---:|---:|---:|
| Baseline — original data | English | 53.33% | 7 | 4 | 15 |
| Baseline — original data | Hinglish | 40.00% | 9 | 1 | 15 |
| Word-only — + Hinglish | English | 60.00% | 6 | 2 | 15 |
| Word-only — + Hinglish | Hinglish | 53.33% | 7 | 0 | 15 |
| Word + character — + Hinglish | English | 73.33% | 4 | 1 | 15 |
| Word + character — + Hinglish | Hinglish | 60.00% | 6 | 1 | 15 |
| V2 — development-error tuned | English | 60.00% | 6 | 1 | 15 |
| V2 — development-error tuned | Hinglish | 60.00% | 6 | 0 | 15 |

## Interpretation

- The word + character model had the highest English scam recall in this pilot (73.33%) and 60.00% Hinglish scam recall.
- The v2 development-error-tuned model had 60.00% recall in both languages and fewer legitimate false alarms than the word + character model on this pilot.
- The word-only model with Hinglish examples improved on the baseline in scam recall for both languages and produced no Hinglish legitimate false alarms in this sample.
- These results are descriptive of this synthetic pilot only. Do not use the v2 development-set scores previously observed during error-focused iteration as generalization results.

## Decision

**Do not replace the current API model based on this pilot alone.** Keep the currently deployed/saved API model unchanged until an independent evaluation and a deliberate promotion decision are completed. Treat word + character as a candidate for future evaluation, not as a validated production winner.

## Guardrails

1. Do not tune any model against this pilot set.
2. Do not describe these results as a human-authored or independent benchmark.
3. Do not put these pilot numbers in marketing or claim real-world accuracy.
4. If a genuinely independent, human-authored test set becomes available, apply the same pre-agreed comparison rules once and report scam recall and legitimate false alarms separately for English and Hinglish.
5. Continue with the ScamLens link-checker and API/app work while keeping model promotion on hold.

## Next engineering phase: link checker and API/app

Recommended order:
1. Add URL extraction and normalization to the API.
2. Add safe URL inspection: parse hostnames, handle IDNs and redirects cautiously, and identify obvious URL red flags without visiting arbitrary URLs or executing page content.
3. Return structured results with separate fields for message classification and URL signals; make clear that URL indicators are heuristics, not proof of fraud.
4. Add tests for shortened URLs, Unicode/IDN lookalikes, misleading subdomains, URL punctuation, multiple links, and messages with no URL.
5. Wire the endpoint into the app and show reasons plus uncertainty, rather than a definitive “safe” guarantee.
6. Keep the current model artifact unchanged during this phase.
