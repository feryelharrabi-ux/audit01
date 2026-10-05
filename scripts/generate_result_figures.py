"""Generate the Part I result figures from the JSON evaluation report."""
import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter


def save_bar(labels: list[str], values: list[float], title: str, ylabel: str, output: Path,
             percent: bool = False) -> None:
    figure, axis = plt.subplots(figsize=(8, 4.5))
    bars = axis.bar(labels, values, color="#168b83")
    axis.set_title(title)
    axis.set_ylabel(ylabel)
    if percent:
        axis.set_ylim(0, 1.05)
        axis.yaxis.set_major_formatter(PercentFormatter(1.0))
    axis.grid(axis="y", alpha=0.22)
    axis.bar_label(bars, fmt="%.3f" if not percent else "%.1%", padding=3, fontsize=8)
    figure.tight_layout()
    figure.savefig(output, dpi=160)
    plt.close(figure)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    args.output_dir.mkdir(parents=True, exist_ok=True)

    crypto = report["cryptographic"]
    detection_keys = [
        "detection_rate_modification", "detection_rate_suppression",
        "detection_rate_injection", "detection_rate_reordering",
    ]
    save_bar(["Modification", "Suppression", "Injection", "Réordonnancement"],
             [crypto[key] for key in detection_keys], "Détection des mutations cryptographiques",
             "Taux de détection", args.output_dir / "I1_detection_crypto.png", percent=True)

    ai = report["ai"]
    ai_keys = ["accuracy", "precision", "recall", "f1_score", "auroc", "auprc"]
    save_bar(["Accuracy", "Precision", "Recall", "F1", "AUROC", "AUPRC"],
             [ai[key] for key in ai_keys], "Métriques IA - pred_TF-IDF+LR, seuil 0,5",
             "Score", args.output_dir / "I2_metriques_ia.png", percent=True)
    save_bar(["FPR", "FNR"], [ai["false_positive_rate"], ai["false_negative_rate"]],
             "Taux de faux positifs et faux négatifs", "Taux", args.output_dir / "I3_fpr_fnr.png",
             percent=True)

    timing_keys = ["hash_generation_ms", "merkle_construction_ms", "proof_generation_ms", "proof_verification_ms"]
    save_bar(["Chaîne de hachage", "Arbre Merkle", "Génération preuve", "Vérification preuve"],
             [crypto[key] for key in timing_keys], "Temps cryptographiques mesurés", "Temps (ms)",
             args.output_dir / "I4_timing_crypto.png")

    scenarios = report["blockchain_performance"]["scenarios"]
    save_bar([f"{item['batch_size_or_delta_minutes']} min" for item in scenarios],
             [item["gas_total"] for item in scenarios], "Gas total selon l'intervalle d'ancrage",
             "Gas total", args.output_dir / "I5_gas_strategies.png")
    print(f"Generated 5 figures in {args.output_dir}")


if __name__ == "__main__":
    main()