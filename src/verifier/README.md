# Vérificateur des journaux

Le dossier local de la partie F ne contenait aucun script source de
vérification, seulement un cache Python compilé (`__pycache__`), qui n'est pas
une source réutilisable. Aucun code n'a été inventé pour le remplacer. Les
tests du chaînage, des preuves Merkle et des signatures disponibles sont dans
`tests/verifier/` et les implémentations correspondantes dans `src/crypto/`.
Ajouter ici le vérificateur F original lorsqu'il sera récupéré.