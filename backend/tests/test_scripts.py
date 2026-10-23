import csv
import json
import tempfile
from pathlib import Path

from helpers import BACKEND, make_tiny_model, write_training_csv  # noqa: F401

import evaluate
import train_model


def expect_exit(func, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except SystemExit as exc:
        return str(exc)
    raise AssertionError("expected SystemExit")


def test_training_writes_artifact_metadata_and_hashes():
    with tempfile.TemporaryDirectory() as tmp:
        directory = make_tiny_model(Path(tmp))
        meta = json.loads((directory / "word_char_candidate_metadata.json").read_text())
        assert meta["labels"]["0"] == "Legitimate"
        assert len(meta["artifact_sha256"]) == 64
        assert meta["sklearn_version"]
        assert "tiny_training.csv" in meta["training"]["data_sha256"]


def test_training_refuses_to_overwrite_and_protects_backup_name():
    with tempfile.TemporaryDirectory() as tmp:
        directory = make_tiny_model(Path(tmp))
        data = directory / "tiny_training.csv"
        msg = expect_exit(train_model.main, ["--base-data", str(data), "--out-dir", str(directory),
                                             "--name", "word_char_candidate", "--min-df", "1"])
        assert "exists" in msg
        # 'targeted_model.joblib' is the rollback backup and can never be written by this script
        msg = expect_exit(train_model.main, ["--base-data", str(data), "--out-dir", str(directory),
                                             "--name", "targeted_model", "--min-df", "1", "--overwrite"])
        assert "protected" in msg


def test_training_refuses_evaluation_and_pilot_files():
    with tempfile.TemporaryDirectory() as tmp:
        for name in ("pilot_ai_authored_60_FROZEN.csv", "locked_test.csv", "holdout_set.csv"):
            path = write_training_csv(Path(tmp) / name)
            msg = expect_exit(train_model.main, ["--base-data", str(path), "--out-dir", tmp, "--name", "x"])
            assert "Refusing to train" in msg


def test_training_rejects_bad_labels():
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "bad.csv"
        bad.write_text("text,label\nhello,9\n", encoding="utf-8")
        assert "unexpected label" in expect_exit(train_model.read_rows, bad)


def _write_eval_csv(path: Path):
    rows = [
        ("Please share your OTP to verify your bank account.", "English", 3),
        ("Your appointment is confirmed for Monday at 10 AM.", "English", 0),
        ("Pay the processing fee to claim your prize", "English", 2),
        ("Your exam form was submitted successfully.", "English", 0),
        ("OTP bhejo abhi", "Hinglish", 3),
        ("Aapka mobile recharge successfully ho gaya hai.", "Hinglish", 0),
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["text", "language", "label"])
        writer.writerows(rows)


def test_evaluation_reports_per_language_and_ledger_blocks_holdout_reuse():
    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp) / "set.csv"
        _write_eval_csv(data)
        reports = Path(tmp) / "reports"
        args = ["--data", str(data), "--mode", "holdout", "--provenance", "test_fixture",
                "--system", "rules", "--reports-dir", str(reports)]
        assert evaluate.main(args) == 0
        result = json.loads(next(reports.glob("*.json")).read_text())["results"]
        assert set(result) == {"English", "Hinglish"}
        assert result["English"]["scam_n"] == 2 and result["English"]["legit_n"] == 2
        assert result["English"]["flagged"]["legit_false_alarms"] == 0
        assert result["Hinglish"]["flagged"]["scams_missed"] == 0
        assert "already scored as a holdout" in expect_exit(evaluate.main, args)
        # exploratory runs may repeat and are stamped
        exploratory = args.copy()
        exploratory[3] = "exploratory"
        assert evaluate.main(exploratory) == 0
        assert evaluate.main(exploratory) == 0
        assert "NOT A HOLDOUT RESULT" in next(reports.glob("*exploratory.md")).read_text()


def test_evaluation_rejects_unfilled_template():
    with tempfile.TemporaryDirectory() as tmp:
        template = BACKEND.parent / "data" / "templates" / "human_authored_holdout_template.csv"
        msg = expect_exit(evaluate.main, ["--data", str(template), "--mode", "exploratory",
                                          "--provenance", "x", "--reports-dir", tmp])
        assert "empty text" in msg


def test_wilson_interval_sanity():
    low, high = evaluate.wilson(11, 15)
    assert 0 < low < 73.3 < high < 100
    assert evaluate.wilson(0, 0) == (None, None)
