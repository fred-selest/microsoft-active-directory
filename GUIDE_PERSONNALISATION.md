# 🎨 Guide de Personnalisation - AD Web Interface

## Sommaire

1. [Ajouter un logo personnalisé](#ajouter-un-logo-personnalis)
2. [Changer les couleurs](#changer-les-couleurs)
3. [Personnaliser la police](#personnaliser-la-police)
4. [CSS personnalisé](#css-personnalis)
5. [Exemples](#exemples)

---

## 📋 Ajouter un logo personnalisé

### Étape 1 : Préparer votre logo

- **Format** : PNG, SVG, ou JPG
- **Taille recommandée** : 200x40px (ratio 5:1)
- **Fond** : Transparent recommandé (PNG)
- **Nom** : `logo.png` ou `logo.svg`

### Étape 2 :Uploader le logo

1. Connectez-vous en **admin**
2. Allez dans **⚙️ Admin** → **Paramètres**
3. Section **Logo** :
   - Cliquez sur "Parcourir"
   - Sélectionnez votre fichier logo
   - Cliquez sur "Enregistrer"

### Étape 3 : Ajuster la taille

Dans **Admin** → **Paramètres** :
- **Hauteur du logo** : `40px` (défaut) à `60px` (max)
- **Position** : Gauche, Centre, Droite

---

## 🎨 Changer les couleurs

### Couleurs disponibles

| Variable | Défaut | Description |
|----------|--------|-------------|
| `primary_color` | `#0078d4` | Bleu Microsoft (boutons, liens) |
| `secondary_color` | `#107c10` | Vert (succès, validation) |
| `danger_color` | `#d13438` | Rouge (erreurs, suppression) |
| `warning_color` | `#ffb900` | Jaune (avertissements) |
| `info_color` | `#00b7c3` | Cyan (informations) |

### Comment changer

**Via l'interface Admin :**
1. **⚙️ Admin** → **Paramètres**
2. Section **Couleurs**
3. Cliquez sur les sélecteurs de couleur
4. **Enregistrer**

**Via fichier settings.json :**
```json
{
  "branding": {
    "primary_color": "#your-color",
    "secondary_color": "#your-color"
  }
}
```

---

## 🔤 Personnaliser la police

### Polices supportées

- **Segoe UI** (défaut - Windows)
- **Roboto** (Google Fonts)
- **Open Sans** (Google Fonts)
- **Lato** (Google Fonts)
- **Custom** (importe via CSS)

### Ajouter une police Google Fonts

1. **⚙️ Admin** → **Paramètres**
2. Section **CSS personnalisé**
3. Ajoutez :
```css
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap');

body {
    font-family: 'Roboto', sans-serif;
}
```
4. **Enregistrer**

---

## 🖌️ CSS personnalisé

### Où ajouter du CSS

**⚙️ Admin** → **Paramètres** → **CSS personnalisé**

### Exemples utiles

#### 1. Changer l'arrondi des boutons
```css
.btn {
    border-radius: 4px !important;
}

.card {
    border-radius: 12px !important;
}
```

#### 2. Augmenter la taille de la sidebar
```css
.sidebar {
    width: 320px !important;
}

.sidebar.open ~ .main-content {
    margin-left: 320px !important;
}
```

#### 3. Changer l'ombre des cartes
```css
.card {
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15) !important;
}

.card:hover {
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2) !important;
}
```

#### 4. Mode sombre personnalisé
```css
body.dark-mode {
    --dark-bg-primary: #1a1a2e;
    --dark-bg-secondary: #16213e;
    --dark-text-primary: #eaeaea;
    --dark-accent: #00d9ff;
}
```

---

## 📸 Exemples complets

### Thème "Entreprise Bleu"
```json
{
  "site": {
    "title": "Mon AD Entreprise",
    "logo": "logo_entreprise.png",
    "logo_height": "50px",
    "theme_color": "#003366"
  },
  "branding": {
    "primary_color": "#003366",
    "secondary_color": "#0066cc",
    "danger_color": "#cc0000",
    "border_radius": "4px",
    "font_family": "Segoe UI, sans-serif"
  }
}
```

### Thème "Moderne Vert"
```json
{
  "site": {
    "title": "AD Manager",
    "logo": "logo_vert.svg",
    "logo_height": "45px"
  },
  "branding": {
    "primary_color": "#2e7d32",
    "secondary_color": "#66bb6a",
    "danger_color": "#ef5350",
    "warning_color": "#ffa726",
    "info_color": "#42a5f5",
    "border_radius": "12px",
    "font_family": "Roboto, sans-serif"
  }
}
```

### Thème "Dark Tech"
```json
{
  "site": {
    "title": "AD Console",
    "theme_color": "#00ff88"
  },
  "branding": {
    "primary_color": "#00ff88",
    "secondary_color": "#00cc6a",
    "danger_color": "#ff4444",
    "warning_color": "#ffbb00",
    "info_color": "#00ccff",
    "border_radius": "0px",
    "font_family": "'Courier New', monospace"
  },
  "features": {
    "dark_mode": true
  }
}
```

---

## 📁 Structure des fichiers

```
C:\AD-WebInterface\
├── static/
│   └── images/
│       ├── logo.png          ← Votre logo
│       └── logo_entreprise.png
├── data/
│   └── settings.json         ← Paramètres personnalisés
└── templates/
    └── base.html             ← Template principal
```

---

## 🔄 Réinitialiser les paramètres

**Via interface :**
1. **⚙️ Admin** → **Paramètres**
2. Bouton **🔄 Réinitialiser**
3. Confirmer

**Via fichier :**
```bash
# Supprimer le fichier de paramètres
del data\settings.json
# Redémarrer le serveur
```

---

## 💡 Astuces

1. **Logo transparent** : Utilisez PNG avec fond transparent pour un meilleur rendu
2. **Couleurs contrastées** : Vérifiez le contraste pour l'accessibilité
3. **Test mobile** : Vérifiez l'affichage sur mobile après personnalisation
4. **Backup** : Sauvegardez `data/settings.json` avant modifications
5. **CSS minimal** : Commencez avec peu de CSS, testez, puis ajoutez

---

## 🆘 Dépannage

### Logo ne s'affiche pas
- Vérifiez le chemin : `static/images/logo.png`
- Redémarrez le serveur
- Videz le cache navigateur (Ctrl+Shift+Suppr)

### Couleurs ne changent pas
- Vérifiez le format hexadécimal : `#RRGGBB`
- Rechargez la page avec Ctrl+F5
- Vérifiez les erreurs CSS (F12 → Console)

### Police ne s'applique pas
- Vérifiez l'orthographe de la police
- Importez Google Fonts si nécessaire
- Testez avec une police système (Arial, Segoe UI)

---

**✅ Personnalisation terminée !**

Pour toute question, consultez la documentation complète ou contactez l'administrateur.
