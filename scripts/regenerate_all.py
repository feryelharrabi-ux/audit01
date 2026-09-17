"""Run the reproducibility pipeline in a controlled order."""
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    required = [ROOT / "config" / "config.yaml", ROOT / "data" / "README.md"]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError(f"Missing required project files: {missing}")

    manifest_dir = ROOT / "results" / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "scaffold_ready",
        "note": "Connect migrated preprocessing, attack, AI and blockchain commands here.",
    }
    (manifest_dir / "pipeline_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print("Project scaffold validated; pipeline manifest written.")


if __name__ == "__main__":
    main()
