"""Recalculate evaluation tables, figures, and a provenance manifest."""
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    processed = ROOT / "data" / "processed"
    required = [
        ROOT / "config" / "config.yaml",
        processed / "sample_logs.csv",
        processed / "cost_report_summary.csv",
        processed / "ai_results.xlsx",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError(f"Missing required project files: {missing}")

    results = ROOT / "results"
    tables = results / "tables"
    figures = results / "figures"
    tables.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        sys.executable, str(ROOT / "scripts" / "evaluate_metrics.py"),
        "--logs-csv", str(processed / "sample_logs.csv"),
        "--blockchain-csv", str(processed / "cost_report_summary.csv"),
        "--ai-xlsx", str(processed / "ai_results.xlsx"),
        "--model", "pred_TF-IDF+LR", "--threshold", "0.5",
        "--output-dir", str(tables),
    ], check=True, cwd=ROOT)
    subprocess.run([
        sys.executable, str(ROOT / "scripts" / "generate_result_figures.py"),
        "--report", str(tables / "metrics_report.json"),
        "--output-dir", str(figures),
    ], check=True, cwd=ROOT)

    manifest_dir = ROOT / "results" / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    inputs = required[1:]
    outputs = sorted([*tables.glob("metrics_*.json"), *tables.glob("metrics_*.csv"), *figures.glob("I*.png")])
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "complete",
        "ai_model": "pred_TF-IDF+LR",
        "threshold": 0.5,
        "inputs": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs},
        "outputs": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in outputs},
    }
    (manifest_dir / "pipeline_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Evaluation regenerated: {len(outputs)} outputs recorded in the manifest.")


if __name__ == "__main__":
    main()
