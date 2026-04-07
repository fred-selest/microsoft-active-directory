# 🧪 Tests — Suite de Tests Automatisés

**Répertoire :** `tests/`

---

## 🎯 Rôle

Le répertoire `tests/` contient la **suite de tests automatisés** pour valider le bon fonctionnement de l'application AD Web Interface.

**Framework :** `pytest`  
**Couverture :** Tests unitaires, tests d'intégration, tests de pages HTML, tests responsive

---

## 📁 Structure

```
tests/
├── __init__.py               # Package tests
│
├── Tests Fonctionnels
│   ├── test_connections.py   # Tests de connexion LDAP
│   ├── test_users.py         # CRUD utilisateurs
│   ├── test_groups.py        # CRUD groupes
│   ├── test_computers.py     # CRUD ordinateurs
│   ├── test_admin_accounts.py # Comptes admin
│   └── ...
│
├── Tests d'API
│   ├── test_api_admin.py     # API administration
│   ├── test_api_diagnostic.py # API diagnostic
│   ├── test_api_full.py      # API complète
│   └── ...
│
├── Tests de Pages HTML
│   ├── test_page_structure.py # Structure HTML
│   ├── test_html_check.py    # Validation HTML
│   ├── test_table_structure.py # Tableaux HTML
│   ├── test_header.py        # En-têtes de page
│   └── ...
│
├── Tests Responsive / Mobile
│   ├── test_responsive.py    # Tests responsive desktop
│   ├── test_mobile.py        # Tests mobile
│   ├── test_all_mobile.py    # Tous tests mobile
│   ├── test_password_policy_mobile.py # MDP policy mobile
│   └── ...
│
├── Tests Spécifiques
│   ├── test_alerts.py        # Système d'alertes
│   ├── test_alerts_impl.py   # Implémentation alertes
│   ├── test_alerts_links.py  # Liens alertes
│   ├── test_alerts_menu.py   # Menu alertes
│   ├── test_alerts_overflow.py # Overflow alertes
│   ├── test_alerts_perms.py  # Permissions alertes
│   ├── test_password_audit.py # Audit mots de passe
│   ├── test_diagnostic.py    # Diagnostic LDAP
│   └── ...
│
├── Tests de Debug
│   ├── test_debug.py         # Routes de debug
│   ├── test_main_debug.py    # Debug page principale
│   ├── test_context_debug.py # Debug context
│   ├── test_display.py       # Affichage
│   └── ...
│
├── Tests de Performance / Layout
│   ├── test_spacing.py       # Espacements CSS
│   ├── test_sidebar.py       # Barre latérale
│   ├── test_container_overflow.py # Overflow containers
│   └── ...
│
├── Tests Spéciaux
│   ├── test_sticky.py        # Éléments sticky
│   ├── test_sticky_final.py  # Sticky final
│   ├── test_sticky_reload.py # Sticky + reload
│   ├── test_sticky_check.py  # Vérification sticky
│   ├── test_sticky_debug.py  # Debug sticky
│   ├── test_chromium.py      # Tests Chromium
│   └── test_full.py          # Test complet
│
└── Tests Utilitaires
    ├── test_is_connected.py  # Fonction is_connected()
    ├── test_css_loaded.py    # CSS chargé
    ├── test_dashboard_css.py # CSS dashboard
    └── ...
```

---

## 🚀 Exécution des Tests

### Commande de Base

```bash
# Tous les tests
pytest

# Avec verbose
pytest -v

# Avec couverture de code
pytest --cov=. --cov-report=html

# Un fichier spécifique
pytest tests/test_connections.py

# Une fonction spécifique
pytest tests/test_users.py::test_create_user

# Arrêter au premier échec
pytest -x

# Réexécuter les échecs
pytest --lf
```

---

## 📝 Structure d'un Test

### Exemple : Test de Connexion

```python
# tests/test_connections.py
import pytest
from app import app
from routes.core import get_ad_connection

@pytest.fixture
def client():
    """Fixture pour le client de test Flask."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_connection_ldap(client):
    """Test de connexion LDAP standard."""
    response = client.post('/connect', data={
        'server': 'dc01.corp.local',
        'port': '389',
        'username': 'admin',
        'password': 'P@ssw0rd',
        'base_dn': 'DC=corp,DC=local'
    })
    assert response.status_code == 302  # Redirection après succès
    assert '/dashboard' in response.location

def test_connection_ldaps(client):
    """Test de connexion LDAPS (SSL)."""
    response = client.post('/connect', data={
        'server': 'dc01.corp.local',
        'port': '636',
        'username': 'admin',
        'password': 'P@ssw0rd',
        'base_dn': 'DC=corp,DC=local',
        'use_ssl': True
    })
    assert response.status_code == 302
```

---

## 🧩 Fixtures Courantes

### Client Flask

```python
@pytest.fixture
def client():
    """Client de test Flask."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Désactiver CSRF pour tests
    with app.test_client() as client:
        yield client
```

### Session Authentifiée

```python
@pytest.fixture
def authenticated_client(client):
    """Client avec session authentifiée."""
    with client.session_transaction() as sess:
        sess['ad_server'] = 'dc01.corp.local'
        sess['ad_base_dn'] = 'DC=corp,DC=local'
        sess['ad_username'] = 'admin'
        sess['ad_permissions'] = ['users:read', 'users:write']
    yield client
```

### Connexion LDAP Mock

```python
@pytest.fixture
def mock_ldap(mocker):
    """Mock de la connexion LDAP."""
    mock_conn = mocker.Mock()
    mock_conn.search.return_value = True
    mock_conn.entries = []
    mock_conn.result = {'result': 0, 'description': 'Success'}
    mocker.patch('routes.core.get_ad_connection', return_value=(mock_conn, None))
    yield mock_conn
```

---

## 📊 Catégories de Tests

### 1. Tests Fonctionnels

**Objectif :** Valider les fonctionnalités métier.

**Exemples :**
- `test_connections.py` — Connexions LDAP, STARTTLS, LDAPS
- `test_users.py` — CRUD utilisateurs
- `test_groups.py` — CRUD groupes
- `test_admin_accounts.py` — Gestion des comptes admin

---

### 2. Tests d'API

**Objectif :** Valider les endpoints JSON.

**Exemples :**
```python
# tests/test_api_admin.py
def test_api_save_settings(client):
    response = client.post('/api/admin/save', json={
        'site_title': 'Test AD'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] == True
```

---

### 3. Tests de Pages HTML

**Objectif :** Valider la structure HTML des pages.

**Exemples :**
```python
# tests/test_page_structure.py
def test_dashboard_structure(client):
    response = client.get('/dashboard')
    assert response.status_code == 200
    
    html = response.data.decode('utf-8')
    assert '<nav' in html  # Navbar présente
    assert '<aside' in html  # Sidebar présente
    assert '<main' in html  # Contenu principal présent
```

---

### 4. Tests Responsive / Mobile

**Objectif :** Valider l'affichage sur mobile.

**Exemples :**
```python
# tests/test_mobile.py
def test_users_mobile_view(client):
    response = client.get('/users', headers={
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)'
    })
    assert response.status_code == 200
    
    html = response.data.decode('utf-8')
    assert 'mobile' in html or 'responsive' in html
```

---

### 5. Tests d'Alertes

**Objectif :** Valider le système d'alertes AD.

**Exemples :**
```python
# tests/test_alerts.py
def test_expiring_accounts_alert(client):
    response = client.get('/alerts/expiring')
    assert response.status_code == 200
    
    data = response.get_json()
    assert 'accounts' in data
    assert isinstance(data['accounts'], list)
```

---

### 6. Tests de Debug

**Objectif :** Valider les routes de debug.

**Exemples :**
```python
# tests/test_debug.py
def test_debug_dashboard(client):
    response = client.get('/_debug/')
    assert response.status_code == 200
    
    data = response.get_json()
    assert 'routes_count' in data
    assert 'templates_count' in data
```

---

## 🔧 Outils de Test

### pytest-mock

Permet de mocker des fonctions :

```bash
pip install pytest-mock
```

```python
def test_with_mock(mocker):
    mock_func = mocker.patch('module.function_to_mock')
    mock_func.return_value = 'mocked'
    
    # Tester
    result = module.function_under_test()
    
    # Vérifier
    mock_func.assert_called_once()
```

---

### pytest-cov (Couverture)

```bash
pip install pytest-cov
pytest --cov=. --cov-report=html
```

Ouvre `htmlcov/index.html` pour voir la couverture.

---

### pytest-html (Rapports HTML)

```bash
pip install pytest-html
pytest --html=report.html
```

---

## 📈 Couverture de Code

### Objectif de Couverture

| Module | Objectif | Actuel |
|--------|----------|--------|
| `routes/` | 80% | ~75% |
| `core/` | 70% | ~65% |
| `templates/` | N/A | N/A |

### Générer un Rapport

```bash
pytest --cov=routes --cov=core --cov-report=term-missing
```

---

## 🐛 Dépannage

### 1. Tests Échouent à Cause de CSRF

**Erreur :** `403 Forbidden`

**Solution :** Désactiver CSRF dans les tests :

```python
@app.before_request
def disable_csrf_for_tests():
    if app.config['TESTING']:
        app.config['WTF_CSRF_ENABLED'] = False
```

---

### 2. Fuites de Mémoire

**Symptôme :** Tests lents après plusieurs exécutions

**Solution :** Nettoyer les fixtures :

```python
@pytest.fixture
def cleanup():
    yield
    # Nettoyage après le test
    remove_test_data()
```

---

### 3. Tests Dépendants

**Problème :** Un test dépend du résultat d'un autre

**Solution :** Rendre les tests indépendants :

```python
# ❌ FAUX
def test_create_user():
    global user_id
    user_id = create_user()

def test_update_user():
    update_user(user_id)  # Dépend de test_create_user

# ✅ CORRECT
def test_update_user():
    user_id = create_test_user()  # Crée son propre utilisateur
    update_user(user_id)
    cleanup_test_user(user_id)
```

---

## 📝 Bonnes Pratiques

### 1. Nommage des Tests

```python
def test_<module>_<function>_<case>():
    # Exemples :
    def test_users_create_valid():
    def test_users_create_invalid_email():
    def test_users_delete_nonexistent():
```

---

### 2. Arrange-Act-Assert

```python
def test_something():
    # Arrange (préparation)
    user_data = {'username': 'test', 'email': 'test@example.com'}
    
    # Act (action)
    result = create_user(user_data)
    
    # Assert (vérification)
    assert result is not None
    assert result.username == 'test'
```

---

### 3. Tests Rapides

- Un test = une vérification
- Pas d'attente inutile
- Mock des appels externes (LDAP, SMTP, API)

---

### 4. Documentation

```python
def test_connection_ldaps():
    """
    Test de connexion LDAPS (port 636, SSL).
    
    Vérifie :
    - La connexion SSL s'établit correctement
    - Le certificat est validé
    - La redirection vers dashboard fonctionne
    
    Prérequis :
    - Serveur LDAP avec SSL activé
    - Certificat valide
    """
```

---

## 🔄 Intégration Continue

### GitHub Actions

```yaml
# .github/workflows/tests.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.10
    
    - name: Install dependencies
      run: pip install -r requirements.txt
    
    - name: Run tests
      run: pytest -v --cov=.
```

---

## 📊 Statistiques de Tests

### Nombre de Tests par Catégorie

| Catégorie | Nombre de tests |
|-----------|-----------------|
| Fonctionnels | ~20 |
| API | ~10 |
| HTML | ~15 |
| Responsive | ~10 |
| Alertes | ~10 |
| Debug | ~5 |
| **Total** | **~70** |

---

## 🎯 Roadmap des Tests

### À Ajouter

- [ ] Tests de performance (charge)
- [ ] Tests de sécurité (injection LDAP, XSS)
- [ ] Tests E2E avec Selenium
- [ ] Tests des templates Jinja2
- [ ] Tests des scripts PowerShell

---

**Version :** 1.35.0  
**Mainteneur :** Équipe AD Web Interface
