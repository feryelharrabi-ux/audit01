r"""Evaluation reproductible des metriques des parties D, G et E.

Usage depuis le dossier ``partie I``:
    py evaluate_metrics.py
    py evaluate_metrics.py --ai-csv ..\partie G\predictions.csv

Le fichier IA attendu contient au minimum ``y_true`` et ``y_score``. Les
colonnes facultatives sont ``attack_type``, ``timestamp`` et ``detected_at``.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
import time
from pathlib import Path
from statistics import mean
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
PARTIE_D = ROOT / "data" / "processed"
PARTIE_E = ROOT / "data" / "processed"
sys.path.insert(0, str(ROOT / "src"))

from crypto.hash_chain import LogRecord, build_chain, verify_chain  # noqa: E402
from crypto.merkle import (  # noqa: E402
    build_merkle_tree,
    generate_inclusion_proof,
    verify_inclusion_proof,
)


def load_records(path: Path, limit: int = 300) -> List[LogRecord]:
    records = []
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for row in list(csv.DictReader(stream))[:limit]:
            records.append(LogRecord(
                source_id=str(row["source_id"]),
                seq_no=int(row["seq_no"]),
                timestamp=row["timestamp"],
                event_id=str(row["event_id"]),
                event_template=str(row["event_template"]),
                raw_log=str(row["raw_log"]),
            ))
    records.sort(key=lambda record: record.seq_no)
    return records


def timed(callable_, *args):
    started = time.perf_counter()
    result = callable_(*args)
    return result, time.perf_counter() - started


def crypto_metrics(records: Sequence[LogRecord]) -> Dict[str, object]:
    chained, hash_seconds = timed(build_chain, list(records))
    tree, merkle_seconds = timed(build_merkle_tree, [entry.leaf for entry in chained])
    proof, proof_seconds = timed(generate_inclusion_proof, tree, len(tree.leaves) // 2, "evaluation")
    _, verify_seconds = timed(verify_inclusion_proof, proof)
    proof_sizes = [
        len(json.dumps(
            generate_inclusion_proof(tree, index, "evaluation").to_dict(),
            separators=(",", ":"),
        ).encode("utf-8"))
        for index in range(len(tree.leaves))
    ]

    def detection(mutator) -> bool:
        candidate = list(chained)
        mutator(candidate)
        return not verify_chain(candidate)

    def modify(items):
        items[len(items) // 2].record.raw_log += " tampered"

    def delete(items):
        del items[len(items) // 2]

    def inject(items):
        items.insert(len(items) // 2, items[0])

    def reorder(items):
        index = len(items) // 2
        items[index - 1], items[index] = items[index], items[index - 1]

    detections = {
        "modification": detection(modify),
        "suppression": detection(delete),
        "injection": detection(inject),
        "reordering": detection(reorder),
    }
    return {
        "detection_rate_modification": float(detections["modification"]),
        "detection_rate_suppression": float(detections["suppression"]),
        "detection_rate_injection": float(detections["injection"]),
        "detection_rate_reordering": float(detections["reordering"]),
        "hash_generation_ms": hash_seconds * 1000,
        "merkle_construction_ms": merkle_seconds * 1000,
        "proof_generation_ms": proof_seconds * 1000,
        "proof_verification_ms": verify_seconds * 1000,
        "average_merkle_proof_bytes": mean(proof_sizes),
    }


def confusion(y_true: Sequence[int], scores: Sequence[float], threshold: float) -> Tuple[int, int, int, int]:
    predicted = [int(score >= threshold) for score in scores]
    tp = sum(actual == predicted_value == 1 for actual, predicted_value in zip(y_true, predicted))
    tn = sum(actual == predicted_value == 0 for actual, predicted_value in zip(y_true, predicted))
    fp = sum(actual == 0 and predicted_value == 1 for actual, predicted_value in zip(y_true, predicted))
    fn = sum(actual == 1 and predicted_value == 0 for actual, predicted_value in zip(y_true, predicted))
    return tp, tn, fp, fn


def safe_div(numerator: float, denominator: float) -> Optional[float]:
    return numerator / denominator if denominator else None


def roc_auc(y_true: Sequence[int], scores: Sequence[float]) -> Optional[float]:
    positives = sum(y_true)
    negatives = len(y_true) - positives
    if not positives or not negatives:
        return None
    ranks = sorted(range(len(scores)), key=lambda index: scores[index])
    rank_sum = sum(position + 1 for position, index in enumerate(ranks) if y_true[index])
    return (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def pr_auc(y_true: Sequence[int], scores: Sequence[float]) -> Optional[float]:
    positives = sum(y_true)
    if not positives:
        return None
    order = sorted(range(len(scores)), key=lambda index: scores[index], reverse=True)
    seen = 0
    area = 0.0
    previous_recall = 0.0
    for position, index in enumerate(order, 1):
        seen += y_true[index]
        if y_true[index]:
            recall = seen / positives
            area += (recall - previous_recall) * (seen / position)
            previous_recall = recall
    return area


def parse_timestamp(value: str) -> float:
    from datetime import datetime
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def ai_metrics(path: Optional[Path], threshold: float, xlsx_path: Optional[Path] = None,
               model: str = "pred_TF-IDF+LR") -> Dict[str, object]:
    if xlsx_path is not None:
        try:
            import pandas as pd
        except ImportError as exc:
            raise RuntimeError("pandas est requis pour lire --ai-xlsx") from exc
        frame = pd.read_excel(xlsx_path, sheet_name="predictions_test")
        prediction_column = model if model.startswith("pred_") else f"pred_{model}"
        if "y" not in frame or prediction_column not in frame:
            raise ValueError(f"Colonnes attendues dans predictions_test: y et {prediction_column}")
        rows = []
        for _, row in frame.iterrows():
            attack_type = row.get("attack_type", "unknown")
            if pd.isna(attack_type):
                attack_type = "unknown"
            rows.append({
                "y_true": row["y"],
                "y_score": row[prediction_column],
                "attack_type": str(attack_type),
            })
    elif path is None:
        return {"status": "NA - fournir --ai-csv avec y_true et y_score"}
    else:
        with path.open(encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.DictReader(stream))
    required = {"y_true", "y_score"}
    missing = required - set(rows[0]) if rows else required
    if missing:
        raise ValueError(f"Colonnes IA manquantes: {', '.join(sorted(missing))}")
    y_true = [int(float(row["y_true"])) for row in rows]
    scores = [float(row["y_score"]) for row in rows]
    if any(label not in (0, 1) for label in y_true):
        raise ValueError("y_true doit contenir uniquement 0 ou 1")
    tp, tn, fp, fn = confusion(y_true, scores, threshold)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    accuracy = safe_div(tp + tn, len(y_true))
    fpr = safe_div(fp, fp + tn)
    fnr = safe_div(fn, fn + tp)
    result = {
        "status": "OK",
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": safe_div(2 * tp, 2 * tp + fp + fn),
        "auroc": roc_auc(y_true, scores),
        "auprc": pr_auc(y_true, scores),
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "threshold": threshold,
        "n_samples": len(y_true),
    }
    attack_types = sorted({row.get("attack_type", "unknown") for row in rows})
    result["recall_by_attack_type"] = {
        attack: safe_div(sum(y_true[i] and scores[i] >= threshold for i, row in enumerate(rows) if row.get("attack_type", "unknown") == attack),
                         sum(y_true[i] for i, row in enumerate(rows) if row.get("attack_type", "unknown") == attack))
        for attack in attack_types
    }
    delays = []
    for row, actual, score in zip(rows, y_true, scores):
        if actual and score >= threshold and row.get("timestamp") and row.get("detected_at"):
            delays.append(parse_timestamp(row["detected_at"]) - parse_timestamp(row["timestamp"]))
    result["detection_delay_seconds_mean"] = mean(delays) if delays else None
    result["detection_delay_samples"] = len(delays)
    return result


def blockchain_metrics(path: Path) -> Dict[str, object]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    numeric = lambda row, key: float(row[key])
    result = {"status": "OK", "scenarios": []}
    for row in rows:
        transactions = int(float(row["n_transactions"]))
        logs_per_second = safe_div(float(row["logs_par_batch_moyen"]) * transactions,
                                   float(row["temps_total_ancrage_s"]))
        result["scenarios"].append({
            "batch_size_or_delta_minutes": int(row["delta_t_minutes"]),
            "gas_per_anchor": numeric(row, "gas_moyen_par_tx"),
            "gas_total": numeric(row, "gas_total"),
            "anchoring_latency_seconds_mean": numeric(row, "temps_moyen_ancrage_s"),
            "logs_per_second": logs_per_second,
            "offchain_storage_bytes": None,
            "onchain_storage_bytes_total": numeric(row, "taille_onchain_totale_octets"),
            "transaction_count": transactions,
            "average_logs_per_batch": numeric(row, "logs_par_batch_moyen"),
        })
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Calcule les metriques attendues de la partie I.")
    parser.add_argument("--logs-csv", type=Path, default=PARTIE_D / "sample_logs.csv")
    parser.add_argument("--blockchain-csv", type=Path, default=PARTIE_E / "cost_report_summary.csv")
    parser.add_argument("--ai-csv", type=Path, help="Predictions avec y_true,y_score et colonnes optionnelles")
    parser.add_argument("--ai-xlsx", type=Path, help="Classeur G avec la feuille predictions_test")
    parser.add_argument("--model", default="pred_TF-IDF+LR", help="Colonne pred_* a evaluer dans le classeur")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).parent / "results")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "cryptographic": crypto_metrics(load_records(args.logs_csv)),
        "ai": ai_metrics(args.ai_csv, args.threshold, args.ai_xlsx, args.model),
        "blockchain_performance": blockchain_metrics(args.blockchain_csv),
    }
    with (args.output_dir / "metrics_report.json").open("w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=True)
    with (args.output_dir / "metrics_summary.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["family", "metric", "value"])
        for family, metrics in report.items():
            for metric, value in metrics.items():
                if metric != "scenarios" and not isinstance(value, dict):
                    writer.writerow([family, metric, value])
    print(json.dumps(report, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()