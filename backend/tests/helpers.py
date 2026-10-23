"""Shared test helpers: a tiny, fast model artifact so the model path can be tested offline."""
from __future__ import annotations

import csv
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "scripts"))

PHRASES = {
    0: "your parcel is arriving tomorrow thank you for shopping",
    1: "police arrest warrant digital custody cooperate immediately",
    2: "guaranteed profit double your money registration fee prize",
    3: "bank account blocked verify password otp kyc link",
    4: "private video customs fee gift parcel love emergency money",
}
FILLERS = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
           "india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa"]


def write_training_csv(path: Path) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["text", "label"])
        for label, phrase in PHRASES.items():
            for filler in FILLERS:
                writer.writerow([f"{phrase} {filler}", label])
    return path


def make_tiny_model(directory: Path, name: str = "word_char_candidate") -> Path:
    """Train a throwaway model with the real training script; returns the directory."""
    import train_model

    data = write_training_csv(directory / "tiny_training.csv")
    train_model.main([
        "--base-data", str(data), "--out-dir", str(directory), "--name", name,
        "--min-df", "1", "--seed", "1",
    ])
    return directory
