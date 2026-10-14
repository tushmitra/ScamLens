from pathlib import Path
import json
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)

BASE = Path("/content")
MODEL_DIR = BASE / "scamlens_model"
DATASET = BASE / "scamlens_fresh_eval_100.csv"

CANDIDATES = [
    ("targeted_model", "targeted_model.joblib", "metadata.json"),
    ("word_char_candidate", "word_char_candidate.joblib",
     "word_char_candidate_metadata.json"),
    ("error_focused_candidate", "error_focused_candidate.joblib",
     "error_focused_candidate_metadata.json"),
    ("error_focused_v2_candidate", "error_focused_v2_candidate.joblib",
     "error_focused_v2_metadata.json"),
]

if not DATASET.is_file():
    raise FileNotFoundError(f"Evaluation dataset not found: {DATASET}")

df = pd.read_csv(DATASET)
required = {"text", "label"}
if not required.issubset(df.columns):
    raise ValueError(f"Dataset must contain columns {sorted(required)}")

df = df.dropna(subset=["text", "label"]).copy()
df["text"] = df["text"].astype(str)
df["label"] = df["label"].astype(int)

if df.empty:
    raise ValueError("No labeled, non-empty evaluation rows.")
if not set(df["label"].unique()).issubset({0, 1, 2, 3, 4}):
    raise ValueError("Unexpected labels; expected class IDs 0 through 4.")

labels = [0, 1, 2, 3, 4]
label_names = [
    "Legitimate",
    "Government impersonation",
    "Financial fraud",
    "Bank phishing",
    "Romance/parcel/sextortion",
]

print("EXPLORATORY MODEL COMPARISON")
print("Dataset:", DATASET)
print("Rows:", len(df))
print("Class distribution:")
print(df["label"].value_counts().sort_index().to_string())
print(
    "\nCaveat: this dataset is only a candidate evaluation set. "
    "Its filename and lack of exact text overlap do not prove it was "
    "independent of model development. Do not use these results as "
    "a production-performance claim."
)

results = []

for name, artifact_name, metadata_name in CANDIDATES:
    artifact = MODEL_DIR / artifact_name
    metadata_path = MODEL_DIR / metadata_name
    print("\n" + "=" * 78)
    print("MODEL:", name)

    if not artifact.is_file():
        print("SKIPPED: artifact missing")
        continue

    try:
        model = joblib.load(artifact)
        metadata = (
            json.loads(metadata_path.read_text(encoding="utf-8"))
            if metadata_path.is_file()
            else {}
        )
        model_classes = [int(x) for x in getattr(model, "classes_", [])]
        if model_classes and set(model_classes) != set(labels):
            print("SKIPPED: model class IDs do not match 0..4")
            print("Model classes:", model_classes)
            continue

        predictions = np.asarray(model.predict(df["text"].tolist())).astype(int)
        if len(predictions) != len(df):
            print("SKIPPED: prediction count mismatch")
            continue

        five_class_accuracy = accuracy_score(df["label"], predictions)
        y_true_binary = (df["label"].to_numpy() != 0).astype(int)
        y_pred_binary = (predictions != 0).astype(int)

        binary_accuracy = accuracy_score(y_true_binary, y_pred_binary)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true_binary,
            y_pred_binary,
            average="binary",
            zero_division=0,
        )

        print("Artifact:", artifact_name)
        print("Metadata:", metadata_name)
        print("Five-class accuracy:", round(five_class_accuracy, 4))
        print("Binary accuracy:", round(binary_accuracy, 4))
        print("Scam precision:", round(precision, 4))
        print("Scam recall:", round(recall, 4))
        print("Scam F1:", round(f1, 4))
        print("\nFive-class report:")
        print(classification_report(
            df["label"],
            predictions,
            labels=labels,
            target_names=label_names,
            zero_division=0,
        ))
        print("Five-class confusion matrix (rows=true, columns=predicted):")
        print(confusion_matrix(df["label"], predictions, labels=labels))
        print("Binary confusion matrix [[TN, FP], [FN, TP]]:")
        print(confusion_matrix(y_true_binary, y_pred_binary, labels=[0, 1]))

        results.append({
            "model": name,
            "n": len(df),
            "five_class_accuracy": five_class_accuracy,
            "binary_accuracy": binary_accuracy,
            "scam_precision": precision,
            "scam_recall": recall,
            "scam_f1": f1,
        })

    except Exception as exc:
        print("SKIPPED due to inspection/prediction error:",
              type(exc).__name__, str(exc))

if results:
    summary = pd.DataFrame(results).sort_values("scam_f1", ascending=False)
    summary_path = BASE / "scamlens_exploratory_model_comparison.csv"
    summary.to_csv(summary_path, index=False)
    print("\n" + "=" * 78)
    print("SUMMARY")
    print(summary.to_string(index=False))
    print("Saved summary:", summary_path)
else:
    print("\nNo model produced a valid comparison.")
