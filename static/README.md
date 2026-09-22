# 🎨 Static — Ressources Statiques

**Répertoire :** `static/`

---

## 🎯 Rôle

Le répertoire `static/` contient toutes les **ressources statiques** servies par Flask : CSS, JavaScript, icônes, et fichiers PWA (Progressive Web App).

---

## 📁 Structure

```
static/
├── css/
│   └── styles.css              # Feuille de style principale (unique)
│
├── js/
│   ├── actions.js              # Délégation d'événements (CSP stricte)
│   ├── main.js                 # JavaScript principal
│   └── display-debugger.js     # Outil de débogage d'affichage (DEBUG)
│
├── vendor/                     # Bibliothèques tierces servies localement
│   ├── chart.umd.js            # Chart.js 4.4.4
│   └── chart.js.LICENSE.md     # Licence MIT
│
├── icons/
│   └── icon.svg                # Icône de l'application (favicon, PWA)
│
├── manifest.webmanifest        # Manifeste PWA
└── sw.js                       # Service Worker PWA
```

---

## 🎨 CSS — `styles.css`

### Structure du Fichier

Le fichier CSS principal est organisé en **17 sections numérotées** :

```css
/* ==========================================================================
   1. RESET & BASE
   ========================================================================== */

/* ==========================================================================
   2. VARIABLES CSS
   ========================================================================== */

/* ==========================================================================
   3. TYPOGRAPHIE
   ========================================================================== */

/* ... jusqu'à la section 17 ... */
```

### Variables CSS Principales (`:root`)

```css
:root {
    /* Couleurs */
    --primary:        #0078d4;   /* Bleu Microsoft */
    --primary-dark:   #005a9e;
    --white:          #ffffff;
    
    /* Arrière-plans */
    --bg-primary:     #f5f5f5;
    --bg-secondary:   #ffffff;
    
    /* Texte */
    --text-primary:   #1b1b1b;
    --text-secondary: #555555;
    
    /* Bordures */
    --border-color:   #e0e0e0;
    --border-radius:  6px;
    
    /* Ombres */
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
    --shadow-md: 0 4px 6px rgba(0,0,0,0.1);
    --shadow-lg: 0 10px 15px rgba(0,0,0,0.15);
    
    /* Espacements */
    --spacing-sm:  0.5rem;
    --spacing-md:  1rem;
    --spacing-lg:  1.5rem;
    --spacing-xl:  2rem;
    
    /* Transitions */
    --transition-fast:    0.15s ease;
    --transition-normal:  0.3s ease;
}
```

### Dark Mode (Section 17)

```css
/* Variables dark mode (alias par défaut) */
:root {
    --dark-bg-primary:    var(--bg-primary);
    --dark-bg-secondary:  var(--bg-secondary);
    --dark-border:        var(--border-color);
    --dark-text-primary:  var(--text-primary);
    --dark-text-secondary: var(--text-secondary);
}

/* Mode sombre activé */
body.dark-mode {
    --dark-bg-primary:    #0f0f1a;
    --dark-bg-secondary:  #1a1a2e;
    --dark-border:        #3a3a5a;
    --dark-text-primary:  #f0f0f5;
    --dark-text-secondary: #c0c0d0;
}
```

### Classes Utilitaires

**Badges :**
```css
.badge              /* Badge gris neutre */
.badge-success      /* Badge vert */
.badge-warning      /* Badge orange */
.badge-danger       /* Badge rouge */
.badge-info         /* Badge bleu */
```

**Alertes :**
```css
.alert              /* Conteneur d'alerte */
.alert-success      /* Alerte verte */
.alert-warning      /* Alerte orange */
.alert-danger       /* Alerte rouge */
.alert-info         /* Alerte bleue */
```

**Formulaire :**
```css
.form-container     /* Conteneur principal */
.form-section       /* Section de formulaire */
.form-row           /* Ligne de formulaire */
.form-group         /* Groupe de champ */
.form-check         /* Checkbox/radio */
.form-actions       /* Boutons d'action */
.input-group        /* Groupe d'input */
.btn-icon           /* Bouton avec icône */
```

**Layout :**
```css
.page-header        /* En-tête de page */
.page-header-actions /* Actions dans l'en-tête */
.content            /* Contenu principal */
.sidebar            /* Barre latérale */
.navbar             /* Barre de navigation */
```

**Couleurs de texte :**
```css
.text-success       /* Texte vert */
.text-warning       /* Texte orange */
.text-danger        /* Texte rouge */
.text-info          /* Texte bleu */
```

---

## 📜 JavaScript — `main.js`

### Fonctions Principales

```javascript
/**
 * Échapper les caractères HTML pour prévenir les XSS
 * @param {string} text - Texte à échapper
 * @returns {string} Texte échappé
 */
function escapeHtml(text) { ... }

/**
 * Afficher un message d'erreur
 * @param {HTMLElement} container - Conteneur
 * @param {string} message - Message
 */
function showError(container, message) { ... }

/**
 * Initialiser les formulaires de recherche
 */
function initSearchForms() { ... }

/**
 * Vérifier les informations système
 */
function fetchSystemInfo() { ... }
```

### Événements DOM

```javascript
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser les formulaires de recherche
    initSearchForms();
    
    // Vérifier les informations système
    fetchSystemInfo();
    
    // Autres initialisations...
});
```

---

## 🔧 display-debugger.js

Outil de débogage pour analyser l'affichage des pages.

**Fonctions :**
- Survol des éléments avec outline coloré
- Affichage des dimensions (width/height)
- Détection des problèmes de layout
- Inspection des overflow

**Utilisation :**
```javascript
// Dans la console navigateur
DisplayDebugger.enable();
DisplayDebugger.disable();
```

---

## 📱 PWA (Progressive Web App)

### `manifest.webmanifest`

Manifeste d'installation : nom « AD Web Interface », `start_url` `/`,
affichage `standalone`, couleur de thème `#0078d4`, et une seule icône
vectorielle (`/static/icons/icon.svg`, `sizes: any`) valable pour toutes les
tailles.

### `sw.js` — Service Worker

- **Stratégie « network first »** : la requête part toujours vers le serveur ;
  le cache ne sert qu'en cas d'erreur réseau.
- **Seuls les fichiers `/static/` sont mis en cache** au fil de l'eau (plus
  `/`, `styles.css`, `main.js` et l'icône à l'installation). Les pages
  dynamiques ne sont pas conservées, et les requêtes non-GET ou vers `/api/`
  ne passent jamais par le cache.
- `CACHE_NAME` est versionné : changer sa valeur purge les anciens caches à
  l'activation.
- Un gestionnaire de notifications push est présent mais n'est alimenté par
  aucun envoi côté serveur à ce jour.

---

## 🖼️ Icônes

`icons/icon.svg` est l'unique icône : favicon, icône « Apple touch » et
icône PWA (déclarée dans `base.html` et `manifest.webmanifest`). Le format
vectoriel évite de maintenir des déclinaisons PNG par taille.

---

## 🎯 Bonnes Pratiques

### 1. Utiliser les Variables CSS

```css
/* ❌ FAUX */
color: #0078d4;
background: #f5f5f5;

/* ✅ CORRECT */
color: var(--primary);
background: var(--bg-primary);
```

### 2. Responsive Design

```css
/* Mobile first */
.element {
    padding: var(--spacing-sm);
}

/* Tablet */
@media (min-width: 768px) {
    .element {
        padding: var(--spacing-md);
    }
}

/* Desktop */
@media (min-width: 1024px) {
    .element {
        padding: var(--spacing-lg);
    }
}
```

### 3. Chargement des Scripts

```html
<!-- En bas de page, avant </body> — le nonce est obligatoire (CSP stricte) -->
<script nonce="{{ csp_nonce() }}" src="{{ url_for('static', filename='js/main.js') }}"></script>

<!-- Avec module ES6 -->
<script nonce="{{ csp_nonce() }}" type="module" src="{{ url_for('static', filename='js/module.js') }}"></script>
```

- `js/actions.js` : délégation d'événements (`data-onclick`, `data-confirm`…)
  qui remplace les attributs `on*="…"` bloqués par la CSP. Voir
  `templates/README.md`, règle 5.
- `vendor/` : bibliothèques tierces servies localement (chart.js 4.4.4,
  licence MIT dans `vendor/chart.js.LICENSE.md`). Aucune dépendance CDN.

### 4. Cache Busting

Flask ajoute automatiquement un hash de version :

```html
<link rel="stylesheet" href="/static/css/styles.css?v=abc123">
```

---

## 🧪 Tests

```bash
pytest tests/test_css_loaded.py
pytest tests/test_responsive.py
pytest tests/test_dashboard_css.py
```

---

## 📊 Performance

### Optimisations Recommandées

1. **Minification CSS/JS** en production
2. **Gzip/Brotli** compression serveur
3. **Cache HTTP** avec versioning
4. **Lazy loading** des images
5. **Critical CSS** inline pour le above-the-fold

---

## 🔧 Personnalisation

### Changer la Couleur Principale

**Méthode 1 : Via settings.json**
```json
{
  "site": {
    "theme_color": "#005a9e"
  }
}
```

**Méthode 2 : Via CSS custom**
```css
:root {
    --primary: #votre-couleur;
    --primary-dark: #votre-couleur-foncée;
}
```

### Ajouter un Thème Personnalisé

1. Créer un fichier dans `data/themes/`
2. Définir les variables CSS
3. Charger via l'interface d'administration

---

## ⚠️ Pièges Connus

### 1. Chemins Relatifs vs Absolus

```html
<!-- ❌ FAUX (peut casser selon l'URL) -->
<link rel="stylesheet" href="css/styles.css">

<!-- ✅ CORRECT -->
<link rel="stylesheet" href="{{ url_for('static', filename='css/styles.css') }}">
```

### 2. Cache Navigateur

Après modification du CSS/JS :
- **Développement** : `TEMPLATES_AUTO_RELOAD = True`
- **Production** : Redémarrer le service + vider le cache

### 3. Conflits JavaScript

```javascript
// ✅ TOUJOURS encapsuler
document.addEventListener('DOMContentLoaded', function() {
    // Code ici
});

// ou utiliser des modules ES6
// type="module"
```

---

**Version :** 1.35.0  
**Mainteneur :** Équipe AD Web Interface
