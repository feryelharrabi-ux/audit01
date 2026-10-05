#!/usr/bin/env python3
"""Build a falsification workbook from generated CSVs and immutable truth."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import pandas as pd

ATTACKS = {
    "delete_isolated", "delete_contiguous", "delete_critical",
    "inject_normal", "inject_anomalous", "inject_plausible_timestamp",
    "modify_content", "modify_level", "modify_timestamp", "modify_source_id",
    "modify_event_id", "permute_two_logs", "reverse_window",
    "move_critical_event", "replay", "rollback",
}
BASE_COLUMNS = [
    "log_id", "source_id", "timestamp", "seq_no", "raw_log", "event_id",
    "event_template", "parameters", "session_id", "block_id", "severity",
    "batch_id", "origin_log_id",
]
TRUTH_COLUMNS = [
    "log_id", "batch_id", "original_position", "position_after", "attack_type",
    "intensity", "modified_fields", "is_deleted", "tampered",
]


def read(path: Path) -> pd.DataFrame:
    return pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig")


def rate_and_attack(path: Path) -> tuple[str, float]:
    prefix = "tampered_"
    name = path.stem[len(prefix):] if path.stem.startswith(prefix) else path.stem
    attack, rate = name.rsplit("_", 1)
    return attack, float(rate.replace("p", "."))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True, help="Clean canonical CSV")
    parser.add_argument("--tampering-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    clean = read(args.input)
    if "source_id" not in clean.columns:
        raise SystemExit("Clean input must contain source_id")
    files = sorted(args.tampering_dir.glob("tampered_*.csv"))
    records, truths, manifests = [], [], []
    for path in files:
        attack, rate = rate_and_attack(path)
        if attack not in ATTACKS:
            raise SystemExit(f"Unexpected attack: {attack}")
        truth_path = args.tampering_dir / f"ground_truth_logs_{attack}_{str(rate).replace('.', 'p')}.csv"
        if not truth_path.exists():
            raise SystemExit(f"Missing immutable truth: {truth_path}")
        logs = read(path)
        truth = read(truth_path)
        missing = [column for column in TRUTH_COLUMNS if column not in truth.columns]
        if missing:
            raise SystemExit(f"Truth file {truth_path} lacks: {missing}")
        logs["attack_type"] = attack
        logs["intensity"] = rate
        logs["dataset"] = "BGL"
        truth["dataset"] = "BGL"
        truth["intensity"] = rate
        records.append(logs)
        truths.append(truth)
        manifests.append({"attack_type": attack, "intensity": rate,
                          "output_rows": len(logs), "truth_rows": len(truth)})

    if {item["attack_type"] for item in manifests} != ATTACKS:
        raise SystemExit(f"Expected exactly {len(ATTACKS)} attack types")
    if sorted({item["intensity"] for item in manifests}) != [0.1, 0.5, 1.0, 5.0, 10.0]:
        raise SystemExit("Expected intensities: 0.1, 0.5, 1, 5, 10")

    falsifications = pd.concat(records, ignore_index=True)
    ground_truth = pd.concat(truths, ignore_index=True)
    output_columns = [column for column in BASE_COLUMNS + ["attack_type", "intensity", "dataset"] if column in falsifications]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(args.output, engine="openpyxl") as writer:
        falsifications[output_columns].to_excel(writer, index=False, sheet_name="Falsifications")
        ground_truth.to_excel(writer, index=False, sheet_name="ground_truth")
        pd.DataFrame(manifests).to_excel(writer, index=False, sheet_name="manifest")
    print(json.dumps({"rows": len(falsifications), "truth_rows": len(ground_truth),
                      "attacks": len(ATTACKS), "intensities": 5}, indent=2))


if __name__ == "__main__":
    main()
