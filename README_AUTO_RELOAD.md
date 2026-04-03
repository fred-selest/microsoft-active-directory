# 🔄 AUTO-RELOAD - Rechargement Automatique

## 📋 Description

Script de surveillance qui redémarre automatiquement le serveur Flask à chaque modification de fichier.

## 🚀 Utilisation

### Méthode 1 : Script auto-reload (Recommandé)

```bash
# Windows
.\run_auto_reload.bat

# Linux/Mac
python auto_reload.py
```

### Méthode 2 : Mode DEBUG Flask

Dans `.env` :
```ini
FLASK_DEBUG=true
```

Puis :
```bash
python run.py
```

→ Recharge les templates HTML automatiquement
→ **Ne recharge PAS** les fichiers Python (redémarrage requis)

## 📁 Fichiers surveillés

| Type | Extensions | Répertoires |
|------|-----------|-------------|
| Python | `.py` | `routes/`, `*.py` |
| Templates | `.html` | `templates/` |
| CSS | `.css` | `static/css/` |
| JavaScript | `.js` | `static/js/` |
| Config | `.env` | Racine |

## ⚙️ Fonctionnement

1. **Scan initial** : Calcule le hash de tous les fichiers
2. **Surveillance** : Vérifie chaque seconde
3. **Détection** : Compare les hashes
4. **Redémarrage** : Si changement détecté → restart serveur

## 🛑 Arrêter

Appuie sur **Ctrl+C** dans le terminal

## 📊 Logs

Exemple de sortie :
```
============================================================
 👁️  AUTO-RELOAD - Surveillance des fichiers
============================================================

📁 Répertoires surveillés: routes, templates, static/css, static/js
📄 Types de fichiers: *.py, *.html, *.css, *.js, .env
⚠️  Appuie sur Ctrl+C pour arrêter

📊 247 fichiers surveillés

============================================================
 🚀 Démarrage du serveur Flask...
============================================================

 ✅ Serveur démarré (PID: 12345)
 📡 Écoute sur http://localhost:5000
 👁️  Surveillance des modifications...

   ✏️  Modifié: templates/password_audit.html

============================================================
 📝 Modification détectée !
============================================================

 🛑 Arrêt du serveur (PID: 12345)...
 ============================================================
 🚀 Démarrage du serveur Flask...
 ============================================================

 ✅ Serveur redémarré !
```

## 🔧 Dépannage

### Le serveur ne redémarre pas

1. Vérifie que `auto_reload.py` est dans le bon répertoire
2. Lance en mode verbose : `python -u auto_reload.py`

### Faux positifs (redémarrages inutiles)

Modifie `EXCLUDE_PATTERNS` dans `auto_reload.py` :
```python
EXCLUDE_PATTERNS = [
    '*.pyc',
    '__pycache__',
    '.git',
    'logs',
    'data',
    'test_*.py',  # Exclure les tests
    '*.tmp',      # Exclure les temporaires
]
```

### Trop lent

Augmente l'intervalle de surveillance (ligne ~170) :
```python
time.sleep(2)  # Vérifier toutes les 2 secondes au lieu de 1
```

---

## 📝 Comparaison

| Méthode | Python | HTML | CSS | JS |
|---------|--------|------|-----|-----|
| **auto_reload.py** | ✅ Auto | ✅ Auto | ✅ Auto | ✅ Auto |
| **FLASK_DEBUG** | ❌ Manual | ✅ Auto | ❌ Manual | ❌ Manual |
| **Manual** | ❌ | ❌ | ❌ | ❌ |

**Recommandation :** Utilise `auto_reload.py` pour le développement !
