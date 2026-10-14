from pathlib import Path
import json

model_dir = Path("/content/scamlens_model")

print("Model directory exists:", model_dir.exists())
if not model_dir.exists():
    print("Create or upload /content/scamlens_model before continuing.")
else:
    print("\nFiles:")
    for path in sorted(model_dir.iterdir()):
        if path.is_file():
            print(f"- {path.name} ({path.stat().st_size:,} bytes)")

    print("\nMetadata summaries:")
    for path in sorted(model_dir.glob("*metadata*.json")):
        print(f"\n--- {path.name} ---")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for key, value in data.items():
                # Keep the output concise and avoid printing model internals.
                print(f"{key}: {value}")
        except Exception as exc:
            print("Could not read metadata:", type(exc).__name__, str(exc))
