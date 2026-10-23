#!/usr/bin/env python3
"""Reproducible training for the word + character TF-IDF / Logistic Regression candidate.

Mirrors the notebook pipeline: word 1-2-grams + char_wb 3-5-grams (sublinear TF),
LogisticRegression(max_iter=1000), group-aware dev split on normalized text, and
optional extra (e.g. Hinglish) data with a higher sample weight (notebook used 4.0).

Usage (from backend/):
    python scripts/train_model.py --base-data path/to/base.csv \
        --extra-data path/to/hinglish_training_clean.csv --extra-weight 4.0 \
        --out-dir models --name word_char_candidate

CSV format: columns `text,label` with integer labels 0-4
(0 Legitimate, 1 Government impersonation, 2 Financial fraud, 3 Bank phishing,
 4 Romance/parcel/sextortion).

Guardrails:
  * refuses inputs that look like evaluation/pilot/holdout files (frozen sets are never training data);
  * never overwrites an existing artifact without --overwrite, and never touches
    `targeted_model.joblib` / `metadata.json` (the rollback backup);
  * writes a metadata file with hashes, versions and row counts, for the artifact manifest.
The dev split reported here is NOT an independent evaluation.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

LABELS: Dict[str, str] = {
    "0": "Legitimate",
    "1": "Government impersonation",
    "2": "Financial fraud",
    "3": "Bank phishing",
    "4": "Romance/parcel/sextortion",
}
PROTECTED_NAMES = {"targeted_model.joblib", "metadata.json"}
FORBIDDEN_INPUT_HINTS = ("eval", "pilot", "frozen", "locked", "holdout", "independent")


def normalize_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r"\d+", "<NUM>", text)
    return re.sub(r"\s+", " ", text).strip()


def check_input_allowed(path: Path) -> None:
    lowered = "/".join(part.lower() for part in path.parts[-3:])
    for hint in FORBIDDEN_INPUT_HINTS:
        if hint in lowered:
            raise SystemExit(
                f"Refusing to train on '{path}': the path contains '{hint}'. Evaluation, pilot and "
                "holdout files must never be used as training data."
            )


def read_rows(path: Path) -> Tuple[List[str], List[int]]:
    texts: List[str] = []
    labels: List[int] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not {"text", "label"} <= set(reader.fieldnames):
            raise SystemExit(f"{path}: expected columns text,label")
        for line_no, row in enumerate(reader, start=2):
            text = (row.get("text") or "").strip()
            if not text:
                continue
            try:
                label = int(row["label"])
            except (TypeError, ValueError):
                raise SystemExit(f"{path}:{line_no}: label must be an integer 0-4")
            if str(label) not in LABELS:
                raise SystemExit(f"{path}:{line_no}: unexpected label {label}")
            texts.append(text)
            labels.append(label)
    if not texts:
        raise SystemExit(f"{path}: no usable rows")
    return texts, labels


def build_pipeline(min_df: int = 2):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline

    return Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=min_df, sublinear_tf=True)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=min_df, sublinear_tf=True)),
        ])),
        ("classifier", LogisticRegression(max_iter=1000)),
    ])


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def train(args: argparse.Namespace) -> Dict[str, object]:
    import joblib
    import numpy as np
    import sklearn
    from sklearn.metrics import classification_report
    from sklearn.model_selection import GroupShuffleSplit

    out_dir = Path(args.out_dir)
    artifact = out_dir / f"{args.name}.joblib"
    metadata_path = out_dir / f"{args.name}_metadata.json"
    for target in (artifact, metadata_path):
        if target.name in PROTECTED_NAMES:
            raise SystemExit(f"Refusing to write protected backup name: {target.name}")
        if target.exists() and not args.overwrite:
            raise SystemExit(f"{target} exists. Choose a new --name or pass --overwrite.")

    data_files = [Path(args.base_data)] + ([Path(args.extra_data)] if args.extra_data else [])
    for path in data_files:
        check_input_allowed(path)
        if not path.is_file():
            raise SystemExit(f"Data file not found: {path}")

    base_texts, base_labels = read_rows(data_files[0])
    # Dev split on the base data only; extra data (if any) is always training-side, as in the notebook.
    groups = [normalize_text(t) for t in base_texts]
    splitter = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=args.seed)
    train_idx, dev_idx = next(splitter.split(base_texts, base_labels, groups=groups))

    x_train = [base_texts[i] for i in train_idx]
    y_train = [base_labels[i] for i in train_idx]
    weights = [1.0] * len(x_train)
    if args.extra_data:
        extra_texts, extra_labels = read_rows(data_files[1])
        x_train += extra_texts
        y_train += extra_labels
        weights += [args.extra_weight] * len(extra_texts)

    model = build_pipeline(args.min_df)
    model.fit(x_train, y_train, classifier__sample_weight=np.asarray(weights, dtype=float))
    if sorted(int(c) for c in model.classes_) != [0, 1, 2, 3, 4]:
        raise SystemExit(f"Training data must contain all classes 0-4; got {list(model.classes_)}")

    dev_x = [base_texts[i] for i in dev_idx]
    dev_y = [base_labels[i] for i in dev_idx]
    print("Development split report (NOT an independent evaluation):")
    print(classification_report(dev_y, model.predict(dev_x), zero_division=0))

    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, artifact)

    metadata = {
        "project": "ScamLens",
        "selected_model": args.name,
        "model_type": "Word and character TF-IDF with Logistic Regression",
        "artifact": artifact.name,
        "labels": LABELS,
        "binary_rule": "Any predicted label other than 0 is treated as a scam",
        "development_note": (
            "Provisional candidate. Not independently validated for production. "
            "Frozen pilot/holdout sets were not used for training or tuning."
        ),
        "sklearn_version": sklearn.__version__,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "artifact_sha256": sha256_file(artifact),
        "training": {
            "rows": len(x_train),
            "dev_rows": len(dev_x),
            "extra_weight": args.extra_weight if args.extra_data else None,
            "seed": args.seed,
            "min_df": args.min_df,
            "data_sha256": {p.name: sha256_file(p) for p in data_files},
        },
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Saved {artifact} and {metadata_path}")
    return metadata


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-data", required=True)
    parser.add_argument("--extra-data")
    parser.add_argument("--extra-weight", type=float, default=4.0)
    parser.add_argument("--out-dir", default="models")
    parser.add_argument("--name", default="word_char_candidate")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--min-df", type=int, default=2)
    parser.add_argument("--overwrite", action="store_true")
    train(parser.parse_args(argv))
    return 0


if __name__ == "__main__":
    sys.exit(main())
