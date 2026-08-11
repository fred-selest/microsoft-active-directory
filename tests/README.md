# 🧪 Tests — Suite de Tests Automatisés

**Répertoire :** `tests/`

---

## 🎯 Rôle

Ce répertoire contient la suite de tests automatisés de l'application AD Web
Interface. Elle est exécutée par la CI (`.github/workflows/ci.yml`, job
`test`) sur chaque push et pull request vers `main`.

**Framework :** `pytest`

Ce fichier décrit les fichiers **réellement présents** dans `tests/` (13
fichiers). Les versions précédentes de ce document faisaient référence à des
dizaines de fichiers (`test_users.py`, `test_groups.py`, `test_mobile.py`,
`test_page_structure.py`…) qui n'ont jamais existé dans ce dépôt : ce
document les remplace.

---

## 📁 Contenu réel

### Tests unitaires / d'intégration (exécutés sous pytest en CI)

| Fichier | Couvre |
|---|---|
| `test_security.py` | `core/security.py` : échappement LDAP, rate limiting, validation de mot de passe, headers de sécurité, CSRF |
| `test_scripts_manager.py` | `core/scripts_manager.py` et les routes `/api/scripts/*` : liste, prérequis, exécution, téléchargement, historique |
| `test_server_session.py` | Sessions côté serveur (constat C4) : le cookie ne porte qu'un identifiant opaque, le fichier de session est créé côté serveur |
| `test_connection_order.py` | Ordre des méthodes de connexion AD (constat É2 : LDAPS/STARTTLS avant le LDAP en clair) |
| `test_csrf_global.py` | Protection CSRF globale (constat É3) : jeton dans le `<meta>`, en-tête, formulaire, corps JSON |
| `test_fix_protocol.py` | Route `/api/fix-protocol` (durcissement des protocoles hérités) |
| `test_hardening_147.py` | Durcissements v1.47.0 (validation TLS opt-in, etc.) |
| `test_permissions_c1.py` | Non-régression du contrôle d'accès granulaire (constat C1) |
| `test_qa_pages.py` | Non-régression du passage QA des pages (crashes 500, interactivité) |

Ces fichiers utilisent `unittest`/`pytest` (classes `TestCase`-like, fixtures
`pytest.fixture`, assertions) et s'exécutent avec un simple `pytest`, sans
serveur ni contrôleur de domaine réel — les appels LDAP/AD sont mockés.

### Scripts autonomes (exclus de la collecte pytest en CI)

| Fichier | Nature |
|---|---|
| `test_api_diagnostic.py` | Script `requests` qui interroge un serveur **déjà démarré** (`/api/diagnostic`). Pas de `def test_*`, ne s'exécute pas sous pytest. |
| `test_api_full.py` | Idem, contre `/api/diagnostic` en réponse complète. |
| `test_connections.py` | Script de diagnostic autonome qui vérifie des imports/fonctions. **Chemins d'import obsolètes** (`security`, `session_crypto`, `audit`, `audit_history` à la racine — ces modules ont depuis été déplacés dans `core/`). À corriger ou supprimer séparément ; en l'état, lancer `python tests/test_connections.py` rapporte des échecs qui ne reflètent pas l'état réel du code (voir `core/security.py`, `core/session_crypto.py`, `core/audit.py`). |

`.github/workflows/ci.yml` exclut ces trois fichiers de la collecte pytest
(`--ignore`) : ce ne sont pas des tests au sens pytest, et `test_connections.py`
ferait échouer la CI sur des faux positifs sans corriger la vraie régression
sous-jacente.

---

## 🚀 Exécution des tests

```bash
# Suite complète, comme en CI
pytest tests/ \
  --ignore=tests/test_api_diagnostic.py \
  --ignore=tests/test_api_full.py \
  --ignore=tests/test_connections.py \
  -v

# Un fichier spécifique
pytest tests/test_security.py -v

# Avec couverture
pytest tests/ --ignore=tests/test_api_diagnostic.py --ignore=tests/test_api_full.py \
  --ignore=tests/test_connections.py --cov=core --cov=routes --cov-report=term-missing
```

Certains tests importent l'application Flask (`from app import app`), ce qui
exige une `SECRET_KEY` en environnement (sinon `config.py` lève une erreur en
mode non-DEBUG) :

```bash
SECRET_KEY=test-secret-key pytest tests/ --ignore=tests/test_api_diagnostic.py \
  --ignore=tests/test_api_full.py --ignore=tests/test_connections.py
```

### Point d'attention : `unittest.mock.patch` sur `request`

Plusieurs tests de `test_security.py` font `@patch('core.security.request')`
pour mocker l'objet `request` de Flask. Hors contexte de requête actif,
`unittest.mock` doit introspecter l'objet réel avant de le remplacer, et
`core.security.request` (LocalProxy Werkzeug) lève `RuntimeError` dès cette
introspection. La fixture `autouse` `_app_request_context` (en tête de
`test_security.py`) pousse un `app.test_request_context('/')` pour toute la
durée du module — ne pas la supprimer sans comprendre pourquoi elle est là.

---

## 📌 État connu (voir aussi `AUDIT_2026-07-20.md`)

- Pas de fichier `CHANGELOG.md` séparé (voir `CHANGELOG.md` à la racine,
  ajouté pour que le lien du `README.md` pointe vers un fichier réel).
- Aucun test ne couvre encore `core/updater.py`, `core/log_analyzer.py`,
  `core/security_audit.py`, `routes/admin_tools.py`, `routes/groups/`,
  `routes/ous/` : chantier à part, non traité dans cette itération.
- `test_connections.py` (voir ci-dessus) nécessite une correction de ses
  chemins d'import avant de pouvoir rejoindre la collecte pytest en CI.
