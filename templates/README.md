# 🎨 Templates — Vues Jinja2

**Répertoire :** `templates/`

---

## 🎯 Rôle

Le répertoire `templates/` contient tous les **templates HTML** utilisant le moteur **Jinja2**. Ils génèrent les pages web de l'interface AD Web Interface.

---

## 📁 Structure

```
templates/
├── base.html                 # Layout principal (navbar, sidebar, footer)
├── index.html                # Page d'accueil (landing page)
├── connect.html              # Formulaire de connexion AD
├── dashboard.html            # Tableau de bord
├── error.html                # Page d'erreur générique
├── 404.html                  # Erreur 404
├── 500.html                  # Erreur 500
│
├── users.html                # Liste des utilisateurs
├── create_user.html          # Création utilisateur
├── edit_user.html            # Édition utilisateur
├── reset_password.html       # Réinitialisation MDP
├── user_form.html            # Formulaire utilisateur générique
├── user_templates.html       # Modèles de création
├── import_users.html         # Import en masse
├── duplicate_user.html       # Duplication utilisateur
├── compare_users.html        # Comparaison utilisateurs
├── compare_users_form.html   # Formulaire comparaison
│
├── groups.html               # Liste des groupes
├── group_details.html        # Détails d'un groupe
├── group_form.html           # Formulaire groupe
├── create_group.html         # Création groupe
├── nested_groups.html        # Groupes imbriqués
│
├── computers.html            # Liste des ordinateurs
├── laps.html                 # Dashboard LAPS
├── laps_create_admin.html    # Création admin LAPS
├── laps_gpo.html             # Configuration GPO LAPS
├── laps_install.html         # Installation LAPS
├── laps_extend_schema.html   # Extension schéma LAPS
├── laps_read_permissions.html # Permissions lecture LAPS
├── laps_computer_permissions.html # Permissions par ordinateur
│
├── bitlocker.html            # Clés BitLocker
│
├── ous.html                  # Liste des OUs
├── ou_form.html              # Formulaire OU
├── tree.html                 # Arborescence AD
│
├── tools/                    # Outils divers
│   ├── accounts.py           # Comptes bloqués/expirés
│   ├── backups.py            # Sauvegardes
│   └── ...
│
├── admin.html                # Administration
├── settings.html             # Paramètres
├── permissions.html          # Permissions granulaires
├── theme_designer.html       # Créateur de thème
│
├── audit.html                # Logs d'audit
├── audit_history.html        # Historique complet
├── password_audit.html       # Audit mots de passe
├── password_audit_history.html # Historique audit MDP
├── password_auditor_report.html # Rapport audit
├── password_policy.html      # Politique MDP
│
├── alerts.html               # Alertes AD
├── alerts_page.html          # Page complète alertes
├── expiring_accounts.html    # Comptes expirés
├── locked_accounts.html      # Comptes verrouillés
├── recycle_bin.html          # Corbeille AD
│
├── diagnostic.html           # Diagnostic réseau/LDAP
├── security_audit.html       # Audit de sécurité
│
├── backups.html              # Liste des sauvegardes
├── backup_detail.html        # Détail sauvegarde
│
├── search.html               # Recherche globale
├── global_search.html        # Formulaire recherche
├── advanced_search.html      # Recherche avancée
│
├── login_history.html        # Historique connexions
├── login_success.html        # Page après connexion
├── logged_out.html           # Page après déconnexion
│
├── favorites_page.html       # Favoris
├── bulk_operations.html      # Opérations en masse
│
├── reports.html              # Rapports
├── maintenance.html          # Maintenance
├── history.html              # Historique actions
│
├── api_docs.html             # Documentation API
│
├── feature_disabled.html     # Fonctionnalité désactivée
├── rate_limited.html         # Rate limiting
│
├── update.html               # Page de mise à jour
│
├── partials/                 # Composants réutilisables
│   ├── _navbar.html          # Barre de navigation
│   ├── _sidebar.html         # Barre latérale
│   ├── _footer.html          # Pied de page
│   ├── _alerts.html          # Flash messages
│   ├── _pagination.html      # Pagination
│   └── ...
│
└── debug/                    # Templates de debug
    └── dashboard.html        # Dashboard debug
```

---

## 🏗️ Architecture des Templates

### 1. Template de Base (`base.html`)

Tous les templates étendent `base.html` qui fournit :

```html
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}AD Web Interface{% endblock %}</title>
    
    <!-- CSS -->
    <link rel="stylesheet" href="{{ url_for('static', filename='css/styles.css') }}">
    {% block extra_css %}{% endblock %}
    
    <!-- Favicon, PWA manifest, etc. -->
</head>
<body class="{% if dark_mode %}dark-mode{% endif %}">
    <!-- Navbar -->
    {% include 'partials/_navbar.html' %}
    
    <!-- Sidebar -->
    {% include 'partials/_sidebar.html' %}
    
    <!-- Contenu principal -->
    <main class="content">
        <!-- Flash messages -->
        {% include 'partials/_alerts.html' %}
        
        {% block content %}{% endblock %}
    </main>
    
    <!-- Scripts -->
    <script src="{{ url_for('static', filename='js/main.js') }}"></script>
    {% block extra_js %}{% endblock %}
</body>
</html>
```

---

### 2. Blocs Jinja2 à Définir

| Bloc | Obligatoire | Description |
|------|-------------|-------------|
| `{% block title %}` | ✅ | Titre de la page |
| `{% block content %}` | ✅ | Contenu principal |
| `{% block extra_css %}` | ❌ | CSS spécifique à la page |
| `{% block extra_js %}` | ❌ | JavaScript spécifique |

**Exemple :**

```html
{% extends 'base.html' %}

{% block title %}Créer un utilisateur{% endblock %}

{% block content %}
<div class="form-container">
    <h1>Créer un utilisateur</h1>
    <form method="POST">
        <!-- Formulaire -->
    </form>
</div>
{% endblock %}

{% block extra_js %}
<script>
    // Script spécifique
</script>
{% endblock %}
```

---

## 🎯 Variables Globales (Context Processor)

Le module `core/context_processor.py` injecte automatiquement ces variables :

| Variable | Type | Description |
|----------|------|-------------|
| `version` | str | Version de l'application (fichier `VERSION`) |
| `dark_mode` | bool | État du mode sombre |
| `connected` | bool | Utilisateur connecté ou non |
| `settings` | dict | Paramètres depuis `settings.json` |
| `config` | object | Configuration Flask |

**Utilisation :**

```html
<!-- Dans n'importe quel template -->
<footer>
    <p>AD Web Interface v{{ version }}</p>
    {% if connected %}
        <a href="{{ url_for('main.disconnect') }}">Déconnexion</a>
    {% else %}
        <a href="{{ url_for('main.connect') }}">Connexion</a>
    {% endif %}
</footer>
```

---

## 🔒 Sécurité dans les Templates

### 1. Token CSRF

```html
<form method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <!-- Autres champs -->
</form>
```

### 2. Échappement Automatique

Jinja2 échappe automatiquement les variables :

```html
<!-- ✅ SÉCURISÉ --}}
<p>{{ user_input }}</p>  <!-- HTML échappé -->

<!-- ❌ DANGEREUX --}}
<p>{{ user_input|safe }}</p>  <!-- N'utiliser que si confiance absolue -->
```

---

## 🎨 Classes CSS Disponibles

Le fichier `static/css/styles.css` fournit ces classes utilitaires :

### Badges

```html
<span class="badge">Normal</span>
<span class="badge badge-success">Succès</span>
<span class="badge badge-warning">Attention</span>
<span class="badge badge-danger">Danger</span>
<span class="badge badge-info">Info</span>
```

### Alertes

```html
<div class="alert alert-success">Opération réussie !</div>
<div class="alert alert-warning">Attention...</div>
<div class="alert alert-danger">Erreur critique !</div>
<div class="alert alert-info">Information</div>
```

### Formulaire

```html
<div class="form-container">
    <div class="form-section">
        <div class="form-row">
            <div class="form-group">
                <label>Nom</label>
                <input type="text" name="name">
            </div>
            <div class="form-check">
                <input type="checkbox" id="active">
                <label for="active">Actif</label>
            </div>
        </div>
    </div>
    <div class="form-actions">
        <button type="submit" class="btn btn-primary">Enregistrer</button>
    </div>
</div>
```

### En-têtes de Page

```html
<div class="page-header">
    <h1>Titre de la page</h1>
    <div class="page-header-actions">
        <a href="#" class="btn btn-primary">Action</a>
    </div>
</div>
```

### Couleurs de Texte

```html
<p class="text-success">Succès</p>
<p class="text-warning">Attention</p>
<p class="text-danger">Erreur</p>
<p class="text-info">Info</p>
```

---

## 📋 Flash Messages

Les messages flash sont affichés via `partials/_alerts.html` :

```python
# Dans une route Python
flash('Utilisateur créé avec succès !', 'success')
flash('Erreur de connexion', 'error')
flash('Attention : compte expiré', 'warning')
flash('Information utile', 'info')
```

**Catégories supportées :**
- `'success'` — Vert
- `'error'` — Rouge
- `'warning'` — Orange
- `'info'` — Bleu

---

## 🧩 Partials (Composants Réutilisables)

Le répertoire `partials/` contient des fragments HTML inclus dans les pages :

```html
<!-- Navbar -->
{% include 'partials/_navbar.html' %}

<!-- Sidebar -->
{% include 'partials/_sidebar.html' %}

<!-- Footer -->
{% include 'partials/_footer.html' %}

<!-- Alertes -->
{% include 'partials/_alerts.html' %}

<!-- Pagination -->
{% include 'partials/_pagination.html' %}
```

---

## 📱 Responsive Design

Tous les templates sont **responsive** grâce aux media queries dans `styles.css`.

**Points de rupture :**

```css
/* Mobile */
@media (max-width: 768px) { ... }

/* Tablet */
@media (min-width: 769px) and (max-width: 1024px) { ... }

/* Desktop */
@media (min-width: 1025px) { ... }
```

---

## 🎯 Templates Spéciaux

### 1. Pages d'Erreur

```python
# Dans app.py ou routes/
return render_template('error.html', 
    error_code=404,
    error_message="Page non trouvée",
    error_details=str(error),
    connected=is_connected()
), 404
```

### 2. Pages de Maintenance

```html
{% extends 'base.html' %}

{% block content %}
<div class="maintenance-container">
    <h1>Maintenance en cours</h1>
    <p>L'application sera bientôt de retour.</p>
</div>
{% endblock %}
```

---

## ⚠️ Bonnes Pratiques

### 1. Jamais de Couleurs Hex dans le HTML

```html
<!-- ❌ FAUX -->
<div style="color: #0078d4;">Texte</div>

<!-- ✅ CORRECT -->
<div style="color: var(--primary);">Texte</div>
```

### 2. CSS Spécifique dans `styles.css`

```html
<!-- ❌ ÉVITER -->
{% block extra_css %}
<style>
    .ma-page { background: red; }
</style>
{% endblock %}

<!-- ✅ PRÉFÉRER -->
<!-- Ajouter dans styles.css, section dédiée -->
```

### 3. `{% block extra_js %}` à la Racine

```html
<!-- ❌ FAUX --}}
{% block content %}
    {% block extra_js %}{% endblock %}
{% endblock %}

<!-- ✅ CORRECT --}}
{% block content %}{% endblock %}
{% block extra_js %}{% endblock %}
```

### 4. URLs Dynamiques avec `url_for()`

```html
<!-- ❌ ÉVITER -->
<a href="/users/create">Créer</a>

<!-- ✅ PRÉFÉRER -->
<a href="{{ url_for('users.create_user') }}">Créer</a>
```

---

## 🔧 Debug des Templates

### 1. Mode Debug Activé

```python
# Dans app.py (si DEBUG=True)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
```

### 2. Forcer le Rechargement

En production, les templates sont **mis en cache**. Après modification :

```powershell
# Redémarrer le service Windows
.\nssm\ADWebInterface.exe restart
```

---

## 🧪 Tests

Les templates sont testés via :

```bash
pytest tests/test_page_structure.py
pytest tests/test_responsive.py
pytest tests/test_html_check.py
```

---

**Version :** 1.35.0  
**Mainteneur :** Équipe AD Web Interface
