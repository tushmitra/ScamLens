#!/usr/bin/env python3
"""Evaluation harness implementing docs/EVALUATION_PROTOCOL.md.

Usage (from backend/):
    python scripts/evaluate.py --data ../data/eval/<set>.csv --mode holdout \
        --provenance human_authored_synthetic --system combined

CSV columns: text,language,label  (label 0 = legitimate, any other label = scam).

Systems:
  rules     message rules + static URL checks, combined by the risk policy (no model)
  combined  rules + URL + model (if a model artifact is available) -- reported by risk band
  model     text model only: predicted_label != 0 counts as an alert

Alert definitions (fixed before scoring):
  flagged     risk band is "Suspicious" or "Review carefully"   (model system: label != 0)
  suspicious  risk band is "Suspicious" only                    (model system: same as flagged)

Modes:
  holdout      the dataset hash is recorded in reports/eval_ledger.jsonl; a second run on the
               same file is refused (a holdout is scored once; later versions need a new set)
  exploratory  repeats allowed; the report is stamped NOT A HOLDOUT RESULT

Reports are written per language, with Wilson 95% intervals; small samples are labelled as such.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.config import Settings  # noqa: E402
from app.model_service import ModelService  # noqa: E402
from app.service import analyze  # noqa: E402

RISK_NONE = "No strong indicators found"
RISK_SUSPICIOUS = "Suspicious"


def wilson(successes: int, n: int, z: float = 1.96):
    if n == 0:
        return (None, None)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (round(max(0.0, centre - half) * 100, 1), round(min(1.0, centre + half) * 100, 1))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_dataset(path: Path) -> List[Dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = {"text", "language", "label"} - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"{path}: missing columns {sorted(missing)}")
        rows = []
        for line_no, row in enumerate(reader, start=2):
            if not (row.get("text") or "").strip():
                raise SystemExit(f"{path}:{line_no}: empty text. Fill the template before evaluating.")
            try:
                label = int(row["label"])
            except (TypeError, ValueError):
                raise SystemExit(f"{path}:{line_no}: label must be an integer")
            rows.append({"text": row["text"].strip(), "language": row["language"].strip(), "label": label})
    if not rows:
        raise SystemExit(f"{path}: no rows")
    return rows


def predict_alerts(system: str, text: str, model: Optional[ModelService],
                   threshold: Optional[float] = None) -> Dict[str, bool]:
    if system == "model":
        if model is None or not model.available:
            raise SystemExit("--system model requires a loaded model artifact.")
        flagged = model.classify(text)["predicted_label"] != 0
        return {"flagged": flagged, "suspicious": flagged}
    result = analyze(text, model if system == "combined" else None, threshold if system == "combined" else None)
    risk = result["overall_risk"]
    return {"flagged": risk != RISK_NONE, "suspicious": risk == RISK_SUSPICIOUS}


def score(rows: List[Dict[str, Any]], system: str, model: Optional[ModelService],
          threshold: Optional[float] = None) -> Dict[str, Any]:
    by_language: Dict[str, Dict[str, int]] = {}
    for row in rows:
        stats = by_language.setdefault(row["language"], {
            "scam_n": 0, "legit_n": 0, "missed_flagged": 0, "missed_suspicious": 0,
            "false_alarms_flagged": 0, "false_alarms_suspicious": 0,
        })
        alerts = predict_alerts(system, row["text"], model, threshold)
        if row["label"] == 0:
            stats["legit_n"] += 1
            stats["false_alarms_flagged"] += alerts["flagged"]
            stats["false_alarms_suspicious"] += alerts["suspicious"]
        else:
            stats["scam_n"] += 1
            stats["missed_flagged"] += not alerts["flagged"]
            stats["missed_suspicious"] += not alerts["suspicious"]

    report: Dict[str, Any] = {}
    for language, s in sorted(by_language.items()):
        entry: Dict[str, Any] = {"scam_n": s["scam_n"], "legit_n": s["legit_n"]}
        for policy in ("flagged", "suspicious"):
            missed = s[f"missed_{policy}"]
            caught = s["scam_n"] - missed
            entry[policy] = {
                "scam_recall_pct": round(100 * caught / s["scam_n"], 2) if s["scam_n"] else None,
                "recall_95ci_pct": wilson(caught, s["scam_n"]),
                "scams_missed": missed,
                "legit_false_alarms": s[f"false_alarms_{policy}"],
            }
        report[language] = entry
    return report


def render_markdown(meta: Dict[str, Any], report: Dict[str, Any]) -> str:
    lines = [
        f"# ScamLens evaluation: {meta['dataset']}",
        "",
        f"- Mode: **{meta['mode']}**" + ("  (NOT A HOLDOUT RESULT; repeats allowed)" if meta["mode"] == "exploratory" else ""),
        f"- System: `{meta['system']}`; model loaded: {meta['model_loaded']}; model review threshold: {meta['model_review_threshold']}",
        f"- Provenance: {meta['provenance']}",
        f"- Dataset sha256: `{meta['dataset_sha256']}`; rows: {meta['rows']}",
        f"- Run (UTC): {meta['run_utc']}",
        "",
        "| Language | Policy | Scam recall | 95% CI | Missed | Legit false alarms | Scam n | Legit n |",
        "|---|---|---:|---|---:|---:|---:|---:|",
    ]
    for language, entry in report.items():
        for policy in ("flagged", "suspicious"):
            p = entry[policy]
            lines.append(
                f"| {language} | {policy} | {p['scam_recall_pct']}% | {p['recall_95ci_pct'][0]}-{p['recall_95ci_pct'][1]}% | "
                f"{p['scams_missed']} | {p['legit_false_alarms']} | {entry['scam_n']} | {entry['legit_n']} |"
            )
    lines += [
        "",
        "Small samples: each missed scam moves recall by 100/n points. Report English and Hinglish separately, "
        "do not describe synthetic sets as real-world performance, and do not tune on this set.",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", required=True)
    parser.add_argument("--mode", choices=["holdout", "exploratory"], required=True)
    parser.add_argument("--provenance", required=True,
                        help="e.g. human_authored_synthetic, ai_authored_synthetic, real_world_sanitized")
    parser.add_argument("--system", choices=["rules", "combined", "model"], default="combined")
    parser.add_argument("--reports-dir", default=str(BACKEND.parent / "reports"))
    args = parser.parse_args(argv)

    data_path = Path(args.data)
    rows = read_dataset(data_path)
    digest = sha256_file(data_path)
    reports_dir = Path(args.reports_dir)
    ledger = reports_dir / "eval_ledger.jsonl"

    if args.mode == "holdout" and ledger.is_file():
        for line in ledger.read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            if entry.get("dataset_sha256") == digest and entry.get("mode") == "holdout":
                raise SystemExit(
                    f"This exact dataset was already scored as a holdout on {entry['run_utc']}. "
                    "A holdout is scored once. Create a new human-authored set for the next version."
                )

    settings = Settings.from_env()
    model = ModelService(settings.resolved_model_path, settings.resolved_metadata_path).load()
    system = args.system
    if system == "combined" and not model.available:
        print("Note: no model artifact found; 'combined' runs rules + URL only.", file=sys.stderr)

    report = score(rows, system, model if model.available else None, settings.model_review_threshold)
    meta = {
        "dataset": data_path.name,
        "dataset_sha256": digest,
        "rows": len(rows),
        "mode": args.mode,
        "system": system,
        "model_loaded": model.available,
        "model_artifact_sha256": model.artifact_sha256,
        "model_review_threshold": settings.model_review_threshold if system == "combined" else None,
        "provenance": args.provenance,
        "run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    reports_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{data_path.stem}__{system}__{args.mode}"
    (reports_dir / f"{stem}.json").write_text(json.dumps({"meta": meta, "results": report}, indent=2), encoding="utf-8")
    markdown = render_markdown(meta, report)
    (reports_dir / f"{stem}.md").write_text(markdown, encoding="utf-8")
    with ledger.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(meta) + "\n")
    print(markdown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
