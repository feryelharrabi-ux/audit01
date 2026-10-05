"""Validate that required output and manifest locations exist."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    required = [
        ROOT / "results" / "manifests" / "pipeline_manifest.json",
        ROOT / "results" / "tables" / "metrics_report.json",
        ROOT / "results" / "tables" / "metrics_summary.csv",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
    if missing:
        raise SystemExit(f"Missing generated results: {missing}. Run scripts/regenerate_all.py first.")
    manifest = __import__("json").loads(required[0].read_text(encoding="utf-8"))
    absent_outputs = [name for name in manifest["outputs"] if not (ROOT / name).is_file()]
    if absent_outputs:
        raise SystemExit(f"Manifest references missing outputs: {absent_outputs}")
    print(f"Reproducibility verified: {len(manifest['outputs'])} result files are present.")


if __name__ == "__main__":
    main()
