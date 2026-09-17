# Audit Reproducibility Project

Projet reorganise pour rendre les composants d'audit decouvrables, testables et reproductibles.

## Installation Python

```bash
python -m venv .venv
python -m pip install -r requirements-lock.txt
```

## Installation Node

```bash
cd contracts
npm ci
```

## Reproduction

Depuis la racine du projet:

```bash
python scripts/regenerate_all.py
python scripts/verify_reproducibility.py
pytest -q
```

Les donnees brutes doivent etre placees dans `data/raw/BGL/` et `data/raw/HDFS/`. Les sorties generees vont dans `data/processed/`, `data/attacks/` et `results/`.

## Contrats

```bash
cd contracts
npx hardhat test
```

Voir `docs/` pour le modele de menace, la methodologie, les limites et les corrections de l'audit.
