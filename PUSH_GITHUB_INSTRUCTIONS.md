# 🚀 Instructions pour pousser sur GitHub

## Méthode 1 : Avec Git (recommandé)

### 1. Installer Git (si non installé)
```powershell
winget install Git.Git
```

### 2. Vérifier le dépôt distant
```bash
cd C:\AD-WebInterface
git remote -v
```

Si le dépôt n'est pas configuré :
```bash
git remote set-url origin https://github.com/fred-selest/microsoft-active-directory.git
```

### 3. Ajouter les fichiers et commiter
```bash
cd C:\AD-WebInterface

# Ajouter tous les fichiers
git add .

# Ou ajouter sélectivement
git add config.py features.py app.py routes/tools.py
git add templates/base.html templates/admin.html templates/feature_disabled.html
git add templates/recycle_bin.html templates/locked_accounts.html
git add .env.example MODULARITE.md RESUME_CHANGEMENTS.md

# Créer le commit
git commit -m "feat: Système de feature flags et corrections erreurs 500

- Ajout 50+ feature flags pour modularité complète (config.py, features.py)
- Correction erreurs 500 sur /recycle-bin et /locked-accounts
- Templates conditionnels selon fonctionnalités (base.html, admin.html)
- NOUVEAU: Page feature_disabled.html pour fonctionnalités désactivées
- Documentation complète (MODULARITE.md, RESUME_CHANGEMENTS.md)
- Mise à jour .env.example avec toutes les options
- 14/14 tests passés

BREAKING CHANGE: Nouvelles variables FEATURE_XXX_ENABLED dans .env
Voir MODULARITE.md pour la liste complète des feature flags."

# Pousser vers GitHub
git push origin main
```

---

## Méthode 2 : Via GitHub Desktop

1. Télécharger GitHub Desktop : https://desktop.github.com/
2. Ouvrir GitHub Desktop
3. File → Add Local Repository → Choisir `C:\AD-WebInterface`
4. Cocher tous les fichiers modifiés
5. Enter commit message : `feat: Système de feature flags et corrections`
6. Cliquer sur "Commit to main"
7. Cliquer sur "Push origin"

---

## Méthode 3 : Via l'interface web GitHub (sans Git)

### Étape 1 : Créer une archive
1. Ouvrir l'Explorateur de fichiers
2. Aller dans `C:\AD-WebInterface`
3. Sélectionner tous les fichiers **SAUF** :
   - `venv/` (environnement virtuel)
   - `logs/` (fichiers journaux)
   - `data/` (données sensibles)
   - `.env` (configuration avec secrets)
   - `__pycache__/` (cache Python)
4. Faire clic droit → Envoyer vers → Dossier compressé
5. Renommer en `microsoft-active-directory-update.zip`

### Étape 2 : Uploader sur GitHub
1. Aller sur : https://github.com/fred-selest/microsoft-active-directory
2. Cliquer sur "Add file" → "Upload files"
3. Glisser-déposer les fichiers individuellement OU
4. Utiliser Git en ligne de commande (méthode 1)

---

## 📝 Fichiers à inclure dans le commit

### Nouveaux fichiers
```
✅ features.py                          (NOUVEAU - Module feature flags)
✅ templates/feature_disabled.html      (NOUVEAU - Page fonctionnalité désactivée)
✅ MODULARITE.md                        (NOUVEAU - Documentation feature flags)
✅ RESUME_CHANGEMENTS.md                (NOUVEAU - Résumé des changements)
```

### Fichiers modifiés
```
✅ config.py                            (50+ feature flags ajoutés)
✅ app.py                               (injection feature flags)
✅ routes/tools.py                      (3 routes ajoutées)
✅ templates/base.html                  (menu conditionnel)
✅ templates/admin.html                 (redesign complet)
✅ templates/recycle_bin.html           (correction route)
✅ templates/locked_accounts.html       (correction route)
✅ .env.example                         (feature flags ajoutés)
```

### Fichiers à EXCLURE (gitignore)
```
❌ venv/                                (environnement virtuel)
❌ logs/                                (logs sensibles)
❌ data/                                (données sensibles)
❌ .env                                 (secrets)
❌ __pycache__/                         (cache)
❌ *.pyc                                (fichiers compilés)
❌ cookies.txt                          (session test)
❌ response.html                        (fichiers test)
❌ list_routes.py                       (scripts debug)
❌ test_url_for.py                      (scripts debug)
```

---

## ✅ Vérification après push

1. Aller sur : https://github.com/fred-selest/microsoft-active-directory
2. Vérifier que les nouveaux fichiers sont présents :
   - `features.py`
   - `templates/feature_disabled.html`
   - `MODULARITE.md`
3. Vérifier le dernier commit avec le message approprié
4. Vérifier que les tests passent (si GitHub Actions configuré)

---

## 📌 Note importante

Avant de pousser, assurez-vous que :
- [ ] Tous les tests passent (`python tests.py`)
- [ ] Le serveur fonctionne correctement
- [ ] Le fichier `.env` n'est PAS inclus (contient des secrets)
- [ ] Le dossier `venv/` n'est PAS inclus (trop volumineux)

---

## 🔄 Mise à jour du CHANGELOG.md

Après le push, mettez à jour `CHANGELOG.md` :

```markdown
## [1.21.0] - 2026-04-01

### Ajouté
- Système de feature flags avec 50+ options de modularité
- Module `features.py` avec utilitaires et décorateurs
- Page `feature_disabled.html` pour fonctionnalités désactivées
- Documentation `MODULARITE.md` avec guide complet

### Corrigé
- Erreur 500 sur `/recycle-bin` (route restore_deleted_object manquante)
- Erreur 500 sur `/locked-accounts` (route bulk_unlock_accounts manquante)
- Erreur `export_expiring_pdf` dans les logs

### Modifié
- `config.py` : 50+ variables FEATURE_XXX_ENABLED
- `templates/base.html` : Menu conditionnel selon feature flags
- `templates/admin.html` : Page d'administration redesignée
- `.env.example` : Ajout section Feature Flags

### Tests
- 14/14 tests automatisés passés
- 100% des pages fonctionnelles
```

---

**Prêt à pousser !** 🚀
