# Scripts de QA manuels

Scripts de contrôle **manuels**, déplacés hors de `tests/` car ce ne sont pas
des tests unitaires pytest : ils lancent un navigateur (Playwright) ou exécutent
du code au niveau module (contexte Flask, requêtes vers un serveur live), ce qui
cassait la collecte de `pytest tests/`.

Ils restent utiles pour vérifier manuellement le rendu, le responsive ou des
comportements de bout en bout.

## Prérequis
- Une instance de l'application en cours d'exécution (souvent `http://localhost:5000`).
- Pour les scripts Playwright : `pip install playwright && playwright install chromium`.
- Certains scripts s'appuient sur des cookies de session sauvegardés localement.

## Usage
Lancer un script directement, l'application étant démarrée :

```bash
python tools/manual-qa/test_visual.py
```

> Les vrais tests unitaires (exécutés par `pytest tests/`) restent dans `tests/`.
