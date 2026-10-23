# ScamLens evaluation: pilot_ai_authored_60_FROZEN.csv

- Mode: **exploratory**  (NOT A HOLDOUT RESULT; repeats allowed)
- System: `rules`; model loaded: False; model review threshold: None
- Provenance: ai_authored_synthetic
- Dataset sha256: `dec55cfd9c540702a4d75018662378affba243f8322252163b127997a53d8701`; rows: 60
- Run (UTC): 2026-10-23T07:29:50+00:00

| Language | Policy | Scam recall | 95% CI | Missed | Legit false alarms | Scam n | Legit n |
|---|---|---:|---|---:|---:|---:|---:|
| English | flagged | 13.33% | 3.7-37.9% | 13 | 0 | 15 | 15 |
| English | suspicious | 0.0% | 0.0-20.4% | 15 | 0 | 15 | 15 |
| Hinglish | flagged | 33.33% | 15.2-58.3% | 10 | 2 | 15 | 15 |
| Hinglish | suspicious | 20.0% | 7.0-45.2% | 12 | 1 | 15 | 15 |

Small samples: each missed scam moves recall by 100/n points. Report English and Hinglish separately, do not describe synthetic sets as real-world performance, and do not tune on this set.
