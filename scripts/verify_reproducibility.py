"""Validate that required output and manifest locations exist."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    required = [ROOT / "results" / "manifests", ROOT / "results" / "tables", ROOT / "results" / "figures"]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_dir()]
    if missing:
        raise SystemExit(f"Missing result directories: {missing}")
    print("Reproducibility layout verified.")


if __name__ == "__main__":
    main()
