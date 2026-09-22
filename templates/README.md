# 🎨 Templates — Vues Jinja2

**Répertoire :** `templates/`

---

## 🎯 Rôle

Le répertoire `templates/` contient tous les **templates HTML** utilisant le moteur **Jinja2**. Ils génèrent les pages web de l'interface AD Web Interface.

---

## 📁 Structure

```
templates/
├── base.html                 # Layout principal (topbar, sidebar, messages flash)
├── index.html                # Page d'accueil (landing page)
├── connect.html              # Formulaire de connexion AD
├── change_password.html      # Changement d'un mot de passe expiré
├── login_success.html        # Page après connexion
├── logged_out.html           # Page après déconnexion
├── dashboard.html            # Tableau de bord
├── error.html                # Page d'erreur générique (404, 403, 500…)
├── feature_disabled.html     # Fonctionnalité désactivée
├── rate_limited.html         # Rate limiting
│
├── users.html                # Liste des utilisateurs
├── create_user.html          # Création utilisateur
├── edit_user.html            # Édition utilisateur
├── reset_password.html       # Réinitialisation MDP
├── user_templates.html       # Modèles de création
├── template_form.html        # Formulaire de modèle utilisateur
├── favorites_page.html       # Favoris
│
├── groups.html               # Liste des groupes
├── group_details.html        # Détails d'un groupe
├── group_form.html           # Formulaire groupe
├── create_group.html         # Création groupe
│
├── computers.html            # Liste des ordinateurs
├── laps.html                 # Mots de passe LAPS
├── bitlocker.html            # Clés BitLocker
│
├── ous.html                  # Liste des OUs
├── ou_form.html              # Formulaire OU
│
├── locked_accounts.html      # Comptes verrouillés
├── expiring_accounts.html    # Comptes expirés
├── recycle_bin.html          # Corbeille AD
├── password_policy.html      # Politique MDP
├── password_audit.html       # Audit mots de passe (assemble password_audit/)
├── password_audit_history.html # Historique audit MDP
├── password_auditor_report.html # Rapport audit
│
├── admin.html                # Administration (paramètres, menu, thème)
├── permissions.html          # Permissions granulaires
├── audit.html                # Logs d'audit
├── alerts.html               # Alertes AD
├── security_audit.html       # Audit de sécurité
├── diagnostic.html           # Diagnostic réseau/LDAP
├── errors.html               # Erreurs récentes de l'application
├── log_analysis.html         # Analyse automatique des logs
├── scripts.html              # Scripts PowerShell
├── backups.html              # Liste des sauvegardes
├── backup_detail.html        # Détail sauvegarde
├── update.html               # Page de mise à jour
├── api_docs.html             # Documentation API
│
├── partials/                 # Composants inclus par base.html
│   ├── _topbar.html          # Barre supérieure
│   ├── _sidebar.html         # Barre latérale (menus configurables)
│   └── _flash.html           # Messages flash
│
├── password_audit/           # Sections incluses par password_audit.html
│   ├── _intro.html, _progress.html, _dashboard.html, _styles.html, _scripts.html
│   └── _weak_accounts.html, _admin_accounts.html, _service_accounts.html,
│       _old_passwords.html, _security.html
│
└── debug/                    # Templates de debug (FLASK_ENV=development)
    └── dashboard.html        # Dashboard debug
```

> Cette arborescence reflète les fichiers réellement présents. Un test
> (`tests/test_qa_pages.py`) vérifie que chaque template est bien rendu ou
> inclus quelque part : un template orphelin fait échouer la CI.

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
    <!-- Barre supérieure -->
    {% include 'partials/_topbar.html' %}
    
    <!-- Sidebar -->
    {% include 'partials/_sidebar.html' %}
    
    <!-- Contenu principal -->
    <main class="content">
        <!-- Flash messages -->
        {% include 'partials/_flash.html' %}
        
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

Les messages flash sont affichés via `partials/_flash.html` :

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
<!-- Barre supérieure -->
{% include 'partials/_topbar.html' %}

<!-- Barre latérale -->
{% include 'partials/_sidebar.html' %}

<!-- Messages flash -->
{% include 'partials/_flash.html' %}
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
