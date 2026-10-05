"""Recalculate binary metrics and enforce basic prediction-table invariants."""

import csv
import math
import sys
from pathlib import Path


def metric(value):
    return value / 100 if value else 0.0


def scores(rows, column):
    tn = fp = fn = tp = 0
    for row in rows:
        actual = int(row["y"])
        predicted = int(row[column])
        if actual == 0 and predicted == 0:
            tn += 1
        elif actual == 0 and predicted == 1:
            fp += 1
        elif actual == 1 and predicted == 0:
            fn += 1
        elif actual == 1 and predicted == 1:
            tp += 1
        else:
            raise ValueError(f"Labels binaires attendus: {actual}, {predicted}")
    total = tn + fp + fn + tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "model": column,
        "n": total,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "accuracy": (tn + tp) / total if total else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def main(path):
    with Path(path).open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    required = {"log_id", "y", "pred_LSTM"}
    missing = required.difference(rows[0] if rows else {})
    if missing:
        raise ValueError(f"Colonnes manquantes: {sorted(missing)}")
    log_ids = [row["log_id"] for row in rows]
    if len(log_ids) != len(set(log_ids)):
        raise ValueError("Fuite potentielle: log_id dupliques dans la table")
    columns = [name for name in rows[0] if name.startswith("pred_")]
    for column in columns:
        result = scores(rows, column)
        print(
            f"{column}: CM=({result['tn']},{result['fp']},{result['fn']},{result['tp']}) "
            f"accuracy={result['accuracy']:.6f} precision={result['precision']:.6f} "
            f"recall={result['recall']:.6f} f1={result['f1']:.6f}"
        )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: py -3 audit_predictions.py predictions_test.csv")
    main(sys.argv[1])