# 🎉 AD Web Interface v1.23.0 - Notes de Version

**Date:** 2 Avril 2026  
**Type:** Version majeure  
**Compatibilité:** Windows Server 2016+, Python 3.8+

---

## 📋 Sommaire

1. [Nouvelles fonctionnalités](#nouvelles-fonctionnalités)
2. [Corrections de bugs](#corrections-de-bugs)
3. [Améliorations de sécurité](#améliorations-de-sécurité)
4. [Guide de mise à jour](#guide-de-mise-à-jour)
5. [Documentation](#documentation)

---

## 🚀 Nouvelles fonctionnalités

### 🔔 Système d'alertes complet

**Page:** `/alerts` (accessible aux admins)

**Détection automatique:**
- ✅ Comptes expirants (30 jours)
- ✅ Mots de passe expirant (14 jours)
- ✅ Comptes inactifs (90 jours)

**Fonctionnalités:**
- 📊 Statistiques en temps réel (critiques, erreurs, avertissements, infos)
- 🔍 Filtres par type, sévérité et statut
- ✅ Acquittement des alertes
- 🗑️ Suppression des alertes
- 📥 Export JSON des alertes
- 🔄 Vérification manuelle ou automatique

**API:**
```
GET  /api/alerts              → Liste des alertes
POST /api/alerts/<id>/acknowledge → Acquitter une alerte
POST /api/alerts/<id>/delete      → Supprimer une alerte
POST /api/alerts/check            → Lancer une vérification
```

---

### 🔐 Case "Changer MDP à prochaine connexion"

**Page:** `/users/create`

**Fonctionnement:**
- Case à cocher dans le formulaire de création
- Cochée par défaut (sécurité maximale)
- Définit `pwdLastSet=0` dans Active Directory
- Force l'utilisateur à changer son mot de passe au prochain login

**Utilisation:**
```
1. Créez un nouvel utilisateur
2. Cochez "L'utilisateur doit changer son mot de passe..."
3. L'utilisateur devra changer son MDP à sa première connexion
```

---

### 🎨 Personnalisation avancée

**Accès:** `⚙️ Admin → Paramètres`

**Options disponibles:**

#### Logo personnalisé
- Upload de logo (PNG, SVG, JPG)
- Hauteur ajustable (40-60px)
- Position : gauche, centre, droite
- Dossier: `static/images/`

#### Couleurs thématiques
| Variable | Défaut | Description |
|----------|--------|-------------|
| `primary_color` | #0078d4 | Bleu Microsoft |
| `secondary_color` | #107c10 | Vert (succès) |
| `danger_color` | #d13438 | Rouge (erreurs) |
| `warning_color` | #ffb900 | Jaune (avertissements) |
| `info_color` | #00b7c3 | Cyan (infos) |

#### Police personnalisée
- Segoe UI (défaut)
- Google Fonts (Roboto, Open Sans, Lato)
- CSS personnalisé pour polices externes

#### CSS personnalisé
- Zone de texte libre dans Admin
- Injection dynamique dans `<head>`
- Persistance dans `data/settings.json`

**Guide complet:** `GUIDE_PERSONNALISATION.md`

---

### 🧰 Scripts PowerShell de correction

**Dossier:** `scripts/`

| Script | Fonction | Impact |
|--------|----------|--------|
| `fix_smbv1.ps1` | Désactive SMBv1 | 🔴 Redémarrage requis |
| `fix_ntlm.ps1` | Passe NTLM au niveau 5 | 🔴 Redémarrage requis |
| `fix_ldap_signing.ps1` | Active signing LDAP | 🟡 Recommandé |
| `fix_channel_binding.ps1` | Active Channel Binding | 🟡 Recommandé |

**Utilisation manuelle:**
```powershell
# En tant qu'administrateur
cd C:\AD-WebInterface\scripts
.\fix_smbv1.ps1
```

**Via l'interface:**
- Page `/password-audit` → Section "Protocoles Obsolètes"
- Bouton "🔧 Appliquer la correction"
- Confirmation → Exécution → Redémarrage si nécessaire

---

### 🔍 Détection automatique des protocoles

**Page:** `/password-audit` → Section "🔒 Protocoles Obsolètes"

**Protocoles vérifiés:**
- SMBv1 (via PowerShell)
- NTLM/LM (via Registry)
- LDAP Signing (via Registry)
- Channel Binding (via Registry)

**API:** `POST /api/fix-protocol`
```json
{
  "protocol": "smbv1"
}
```

---

### 📊 Tests visuels automatisés

**Scripts:**
- `test_full.py` → Test complet avec captures d'écran
- `test_debug.py` → Détection des bugs d'affichage
- `test_visual.py` → Navigation manuelle
- `test_responsive.py` → Test multi-résolutions

**Utilisation:**
```bash
python test_full.py
```

**Résultats:**
- Captures dans `logs/screenshots/`
- Rapport JSON dans `logs/test_results.json`
- Détection automatique des overflow, éléments coupés, erreurs JS

---

## 🐛 Corrections de bugs

### Overflow horizontal (+280px)
**Problème:** Toutes les pages avaient un scroll horizontal indésirable  
**Cause:** Sidebar non correctement gérée  
**Solution:** `overflow-x: hidden` sur sidebar et main-content  
**Fichiers:** `optimizations.css`, `responsive.css`

### Boutons empilés verticalement
**Problème:** Boutons dans header empilés au lieu d'être alignés  
**Cause:** Flexbox mal configuré  
**Solution:** Header-actions en flexbox avec wrap  
**Fichier:** `responsive.css`

### Politique MDP valeurs vides
**Problème:** Page `/password-policy` affichait des valeurs vides  
**Cause:** Mauvaise gestion des valeurs timedelta/FILETIME  
**Solution:** Fonctions de conversion dédiées  
**Fichier:** `routes/tools.py`

### Autres corrections
- Template LAPS erreur syntaxe (`{% endif %}` en double)
- Routes `/admin/` et `/password-audit` avec `url_for()` incorrects
- Fonctions JavaScript `showLoading()`, `hideLoading()` manquantes
- Erreur `ACTIONS['OTHER']` non définie
- Import `request` manquant dans `debug_utils.py`
- Template `debug/dashboard.html` avec objets Rule non sérialisables

---

## 🔒 Améliorations de sécurité

### Autorisations granulaires par groupe AD

**Configuration:** `routes/core.py`
```python
AD_GROUP_PERMISSIONS = {
    'read': [],
    'write': [],
    'delete': [],
    'admin': [],
    'audit_logs': [],
    'password_reset': [],
    'user_create': [],
    'user_delete': [],
    'group_modify': [],
    'backup_restore': [],
    'debug_access': []
}
```

**Fonctions:**
- `get_user_permissions(conn, username)` → Obtient les permissions
- `has_permission(permission)` → Vérifie une permission
- `require_permission(permission)` → Décorateur de route

### Détection des protocoles obsolètes

**Risques détectés:**
- SMBv1 → Vulnérabilités WannaCry, NotPetya
- NTLMv1/LM → Authentification faible
- LDAP Signing non requis → Attaques MITM
- Channel Binding non activé → Vulnérabilités AD CS

### Audit des mots de passe enrichi

**Nouvelles métriques:**
- Score numérique 0-100
- Détection FGPP (Fine-Grained Password Policies)
- Vulnérabilités "password spray"
- Recommandations avec références ANSSI

---

## 📖 Guide de mise à jour

### Étape 1: Sauvegarde
```bash
# Sauvegarder la configuration
copy data\settings.json data\settings.json.bak
copy .env .env.bak
```

### Étape 2: Mise à jour des fichiers
```bash
# Si utilisation de Git
git pull origin main

# Ou extraction manuelle
# Extraire l'archive dans C:\AD-WebInterface\
```

### Étape 3: Mise à jour des dépendances
```bash
pip install -r requirements.txt --upgrade
```

### Étape 4: Redémarrage
```bash
# Arrêter le service
net stop ADWebInterface

# Démarrer le service
net start ADWebInterface

# Ou en mode debug
python run.py
```

### Étape 5: Vérification
```
1. Accéder à http://localhost:5000/
2. Vérifier la version dans Admin → Mises à jour
3. Tester la page /alerts
4. Tester la personnalisation dans Admin → Paramètres
```

---

## 📚 Documentation

### Nouveaux fichiers de documentation
- `GUIDE_PERSONNALISATION.md` → Personnalisation complète
- `GUIDE_TEST_RESPONSIVE.md` → Tests responsive
- `CHANGELOG.md` → Historique des versions (mis à jour)

### Documentation existante mise à jour
- `README.md` → Nouvelles fonctionnalités ajoutées
- `.env.example` → Section PERSONNALISATION ajoutée

---

## 📊 Statistiques de la version

**Fichiers:**
- Nouveaux: 15 fichiers
- Modifiés: 20+ fichiers
- Total: +2500 lignes ajoutées, -200 supprimées

**Tests:**
- 8 pages testées automatiquement
- Overflow horizontal: 280px → 0px ✅
- Éléments coupés: 0 ✅
- Erreurs JavaScript: 0 ✅

---

## 🆘 Support

**Problèmes connus:** Aucun

**Contact:**
- GitHub: https://github.com/fred-selest/microsoft-active-directory
- Issues: https://github.com/fred-selest/microsoft-active-directory/issues

---

**Merci d'utiliser AD Web Interface!** 🎉
