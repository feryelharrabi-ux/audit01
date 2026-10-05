# Données du projet

## Contenu fourni

- `processed/` contient les logs d'exemple du volet cryptographique, les deux
	exports structurés BGL/HDFS, les coûts blockchain et le classeur de
	prédictions IA utilisé pour l'évaluation.
- `attacks/` contient les jeux de falsifications BGL et HDFS livrés avec le
	projet.
- `raw/` est réservé aux fichiers bruts BGL et HDFS. Les fichiers bruts
	originaux n'étaient pas présents dans le dossier de livraison local et ne
	sont donc pas inclus dans ce dépôt.

Les sorties tabulaires d'évaluation se trouvent dans `../results/tables/` et
les figures dans `../results/figures/`. Les gros fichiers de données sont
fournis pour permettre l'inspection; les rapports peuvent être recalculés avec
`python scripts/regenerate_all.py` depuis la racine du projet.
# Donnees

Placez les sources brutes BGL dans `raw/BGL/` et HDFS dans `raw/HDFS/`.

Les fichiers bruts ne sont pas inclus automatiquement dans l'archive. Documentez leur provenance, leur version et leur SHA-256 dans `results/manifests/`.

Les donnees generees sont ecrites dans `processed/` et les falsifications dans `attacks/`.
