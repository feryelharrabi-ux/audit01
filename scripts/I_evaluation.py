"""Regenerate Part I only from artefacts produced by Parts D through H.

The script has no fallback metrics. It discovers source files relative to the
repository root, validates their contracts, computes summaries from them, and
records provenance in the workbook.
"""
from __future__ import annotations

import argparse
import hashlib
import platform
import subprocess
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import numpy as np
import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_ROOT = SCRIPT_DIR.parent
OUTPUT_NAME = "I_evaluation_complete.xlsx"


def find_one(root: Path, names: tuple[str, ...], patterns: tuple[str, ...]) -> Path:
    candidates = [root / name for name in names]
    candidates += [p for pattern in patterns for p in root.rglob(pattern)]
    candidates = sorted({p.resolve() for p in candidates if p.is_file()})
    if not candidates:
        raise FileNotFoundError(
            f"Artefact manquant sous {root}: noms={names}, motifs={patterns}. "
            "Placez les sorties D-H dans le dépôt ou utilisez --root."
        )
    return candidates[0]


def load_sources(root: Path) -> dict[str, Path]:
    return {
        "ai": find_one(root, ("ai_results.xlsx",), ("**/G_IA/ai_results.xlsx", "**/*ai_results*.xlsx")),
        "verification": find_one(root, ("verification_report_BGL.xlsx",), ("**/F_verification/*verification*.xlsx", "**/*verification_report*.xlsx")),
        "cost": find_one(root, ("cost_report_summary.csv",), ("**/eth_project/cost_report_summary.csv", "**/*cost_report_summary*.csv")),
        "anchoring": find_one(root, ("H_couplage_ia_ancrage.xlsx",), ("**/H_couplage/*ancrage*.xlsx", "**/*couplage*ancrage*.xlsx")),
        "crypto_timing": find_one(root, ("crypto_timing.csv",), ("**/*crypto*timing*.csv", "**/*timing*merkle*.csv")),
        "detection": find_one(root, ("detection_rates.csv",), ("**/*detection*rate*.csv", "**/*detection*rates*.csv")),
    }


def read_required_sheet(path: Path, sheet: str, columns: list[str]) -> pd.DataFrame:
    df = pd.read_excel(path, sheet_name=sheet)
    missing = sorted(set(columns) - set(df.columns))
    if missing:
        raise ValueError(f"{path.name}/{sheet}: colonnes manquantes: {missing}")
    return df


def metadata(root: Path, sources: dict[str, Path]) -> pd.DataFrame:
    try:
        version = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True,
            stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        version = "git-inconnu"
    rows = []
    for key, path in sources.items():
        rows.append({
            "artefact": key,
            "chemin_relatif": str(path.relative_to(root)) if path.is_relative_to(root) else str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "taille_octets": path.stat().st_size,
            "code_version": version,
            "python": platform.python_version(),
            "graine": "voir artefact source",
        })
    return pd.DataFrame(rows)


def load_verification(path: Path) -> dict[str, pd.DataFrame]:
    workbook = pd.ExcelFile(path)
    return {sheet: pd.read_excel(path, sheet_name=sheet) for sheet in workbook.sheet_names}


def crypto_metrics(sources: dict[str, Path]) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    detection = pd.read_csv(sources["detection"])
    required = {"attack_type", "total", "detected", "not_detected"}
    if not required.issubset(detection.columns):
        raise ValueError(f"detection_rates.csv: colonnes manquantes: {sorted(required - set(detection.columns))}")
    if (detection[["total", "detected", "not_detected"]] < 0).any().any():
        raise AssertionError("Les comptages cryptographiques doivent être positifs")
    if not (detection["detected"] + detection["not_detected"] == detection["total"]).all():
        raise AssertionError("detected + not_detected doit égaler total pour chaque attaque")

    def family(value: str) -> str:
        names = (("injection", "Injection"), ("modification", "Modification"),
                 ("reord", "Réordonnancement"), ("replay", "Replay"),
                 ("rollback", "Rollback"), ("suppression", "Suppression"))
        return next((label for token, label in names if token in value.lower()), "Autre")

    detection["famille"] = detection["attack_type"].map(family)
    detection["detection_rate_calcule"] = detection["detected"] / detection["total"]
    by_family = detection.groupby("famille", as_index=False)[["total", "detected", "not_detected"]].sum()
    by_family["taux_detection"] = by_family["detected"] / by_family["total"]
    timing = pd.read_csv(sources["crypto_timing"])
    timing_columns = ["N logs", "Temps chaîne (ms)", "Temps Merkle (ms)",
                      "Temps génération preuve (ms)", "Temps vérification preuve (ms)",
                      "Taille preuve (octets)", "Nb siblings"]
    if not set(timing_columns).issubset(timing.columns):
        if len(timing.columns) == len(timing_columns):
            timing.columns = timing_columns
        else:
            raise ValueError("crypto_timing.csv ne respecte pas le contrat de colonnes attendu")
    summary = by_family.rename(columns={"famille": "Métrique", "taux_detection": "Valeur"})[["Métrique", "Valeur"]]
    summary["Valeur"] = summary["Valeur"].map(lambda value: f"{value:.4%}")
    return summary, detection, timing


def ia_metrics(sources: dict[str, Path]) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    path = sources["ai"]
    models = read_required_sheet(path, "comparaison_modeles", ["model"])
    predictions = read_required_sheet(path, "predictions_test", ["y"])
    attacks = read_required_sheet(path, "metriques_par_attaque", [])
    y_true = predictions["y"].to_numpy()
    prediction_columns = [column for column in predictions if column.startswith("pred_")]
    if not prediction_columns:
        raise ValueError("predictions_test ne contient aucune colonne pred_*")
    rows = []
    for column in prediction_columns:
        y_pred = predictions[column].to_numpy()
        if len(y_pred) != len(y_true) or not set(np.unique(y_pred)).issubset({0, 1}):
            raise AssertionError(f"Prédictions invalides pour {column}")
        tp = int(((y_true == 1) & (y_pred == 1)).sum())
        tn = int(((y_true == 0) & (y_pred == 0)).sum())
        fp = int(((y_true == 0) & (y_pred == 1)).sum())
        fn = int(((y_true == 1) & (y_pred == 0)).sum())
        name = column.removeprefix("pred_")
        aliases = {"TF-IDF+LR": "TF-IDF + LR", "TF-IDF+SVM": "TF-IDF + SVM",
                   "IForest": "Isolation Forest", "OCSVM": "One-Class SVM"}
        name = aliases.get(name, name)
        source = models[models["model"] == name]
        row = source.iloc[0].to_dict() if not source.empty else {"model": name}
        row.update({"Modèle": name, "TP": tp, "TN": tn, "FP": fp, "FN": fn,
                    "FPR": fp / (fp + tn) if fp + tn else np.nan,
                    "FNR": fn / (fn + tp) if fn + tp else np.nan})
        rows.append(row)
    raw = pd.DataFrame(rows)
    expected = ["accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc"]
    missing = sorted(set(expected) - set(raw.columns))
    if missing:
        raise ValueError(f"comparaison_modeles: métriques manquantes: {missing}")
    summary = raw.loc[:, ["Modèle", *expected, "FPR", "FNR"]].copy()
    summary.columns = ["Modèle", "Accuracy", "Precision", "Recall", "F1-score", "AUROC", "AUPRC", "FPR", "FNR"]
    return summary, raw, attacks


def blockchain_metrics(sources: dict[str, Path]) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    cost = pd.read_csv(sources["cost"])
    anchoring = read_required_sheet(sources["anchoring"], "cout_securite", ["strategie", "gas_total", "latence_moy_logs"])
    required = {"logs_par_batch_moyen", "temps_moyen_ancrage_s"}
    if not required.issubset(cost.columns):
        raise ValueError(f"cost_report_summary.csv: colonnes manquantes: {sorted(required - set(cost.columns))}")
    cost["debit_blockchain_logs_s"] = cost["logs_par_batch_moyen"] / cost["temps_moyen_ancrage_s"]
    for stage, column in {"crypto": "temps_crypto_s", "ia": "temps_ia_s", "blockchain": "temps_moyen_ancrage_s"}.items():
        if column in cost:
            cost[f"debit_{stage}_logs_s"] = cost["logs_par_batch_moyen"] / cost[column]
    stage_columns = ["temps_crypto_s", "temps_ia_s", "temps_moyen_ancrage_s"]
    if set(stage_columns).issubset(cost.columns):
        cost["debit_bout_en_bout_logs_s"] = cost["logs_par_batch_moyen"] / cost[stage_columns].sum(axis=1)
    end_to_end = cost.get("debit_bout_en_bout_logs_s", pd.Series([np.nan])).mean()
    summary = pd.DataFrame({"Métrique": ["Débit blockchain (logs/s)", "Débit bout en bout (logs/s)"],
                            "Valeur": [cost["debit_blockchain_logs_s"].mean(), end_to_end]})
    return summary, cost, anchoring


def serialized_storage(root: Path) -> pd.DataFrame:
    candidates = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in {".json", ".jsonl", ".csv", ".parquet", ".pkl"}]
    return pd.DataFrame([{"fichier": str(p.relative_to(root)), "taille_octets": p.stat().st_size} for p in candidates],
                        columns=["fichier", "taille_octets"])


def plot_figures(output_dir: Path, detection: pd.DataFrame, ia: pd.DataFrame,
                 timing: pd.DataFrame, cost: pd.DataFrame) -> None:
    figures = output_dir / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    grouped = detection.groupby("famille", as_index=False)[["total", "detected"]].sum()
    grouped["taux"] = grouped["detected"] / grouped["total"]
    grouped.sort_values("taux").plot.barh(x="famille", y="taux", legend=False, xlim=(0, 1),
                                           title="Taux de détection calculé par famille")
    plt.tight_layout(); plt.savefig(figures / "I1_detection_crypto.png", dpi=150); plt.close()
    metrics = [column for column in ["F1-score", "AUROC", "AUPRC", "Recall", "Precision"] if column in ia]
    ia.set_index("Modèle")[metrics].plot.bar(figsize=(11, 5), ylim=(0, 1.05), title="Métriques IA calculées")
    plt.tight_layout(); plt.savefig(figures / "I2_metriques_ia.png", dpi=150); plt.close()
    if {"FPR", "FNR"}.issubset(ia.columns):
        ia.set_index("Modèle")[["FPR", "FNR"]].plot.bar(figsize=(9, 5), ylim=(0, 1), title="FPR / FNR calculés")
        plt.tight_layout(); plt.savefig(figures / "I3_fpr_fnr.png", dpi=150); plt.close()
    timing.plot(x="N logs", y=["Temps chaîne (ms)", "Temps Merkle (ms)"], marker="o",
                title="Temps cryptographiques mesurés")
    plt.tight_layout(); plt.savefig(figures / "I4_timing_crypto.png", dpi=150); plt.close()
    if "gas_total" in cost:
        cost.plot(x=cost.columns[0], y="gas_total", kind="bar", legend=False, title="Gas mesuré par configuration")
        plt.tight_layout(); plt.savefig(figures / "I5_gas_strategies.png", dpi=150); plt.close()


def write_report(output: Path, sheets: dict[str, pd.DataFrame]) -> None:
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        for name, frame in sheets.items():
            frame.to_excel(writer, sheet_name=name[:31], index=False)
            writer.sheets[name[:31]].freeze_panes(1, 0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="Racine du dépôt contenant les sorties D-H")
    parser.add_argument("--output-dir", type=Path, default=SCRIPT_DIR)
    args = parser.parse_args()
    root = args.root.resolve()
    sources = load_sources(root)
    crypto_summary, detection, timing = crypto_metrics(sources)
    ia_summary, ia_models, attacks = ia_metrics(sources)
    bc_summary, cost, anchoring = blockchain_metrics(sources)
    verification = load_verification(sources["verification"])
    provenance = metadata(root, sources)
    storage = serialized_storage(root)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir.resolve() / OUTPUT_NAME
    plot_figures(args.output_dir.resolve(), detection, ia_summary, timing, cost)
    global_summary = pd.concat([
        crypto_summary.assign(famille="crypto"), ia_summary.assign(famille="IA"),
        bc_summary.assign(famille="blockchain")], ignore_index=True)
    sheets = {"synthese_globale": global_summary, "detection_par_attaque": detection,
        "timing_crypto": timing, "metriques_ia": ia_summary, "metriques_ia_brutes": ia_models,
        "recall_par_attaque": attacks, "cout_ancrage": cost, "cout_strategies": anchoring,
        "stockage_mesure": storage, "provenance": provenance}
    sheets.update({"verification_" + name: frame for name, frame in verification.items()})
    write_report(output, sheets)
    print(f"Rapport régénéré depuis {len(sources)} artefacts: {output}")


if __name__ == "__main__":
    main()
