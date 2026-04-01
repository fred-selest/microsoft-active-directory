@echo off
setlocal enabledelayedexpansion

REM Ajouter GitHub CLI au PATH
set "PATH=%PATH%;C:\Program Files\GitHub CLI"
set "PATH=%PATH%;C:\Program Files\Git\bin"

cd /d "%~dp0"

title Commit GitHub - AD Web Interface v1.22.0

echo =====================================================================
echo   COMMIT GITHUB - AD Web Interface v1.22.0
echo =====================================================================
echo.

REM Vérifier gh
gh --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] GitHub CLI non trouve.
    pause
    exit /b 1
)

echo [INFO] GitHub CLI detecte...
echo.

REM Vérifier authentification
echo [INFO] Verification authentification GitHub...
gh auth status >nul 2>&1
if errorlevel 1 (
    echo [INFO] Authentification requise. Execution : gh auth login
    echo.
    gh auth login
    if errorlevel 1 (
        echo [ERREUR] Authentification echouee.
        pause
        exit /b 1
    )
)
echo [OK] Authentifie sur GitHub
echo.

REM Initialiser le depot si necessaire
if not exist ".git" (
    echo [INFO] Initialisation du depot Git...
    git init
    git remote add origin https://github.com/fred-selest/microsoft-active-directory.git
    echo [OK] Depot initialise
    echo.
)

REM Afficher les fichiers
echo [INFO] Fichiers a commiter :
echo   - VERSION (1.22.0)
echo   - CHANGELOG.md
echo   - features.py (NOUVEAU)
echo   - templates/feature_disabled.html (NOUVEAU)
echo   - MODULARITE.md (NOUVEAU)
echo   - RESUME_CHANGEMENTS.md (NOUVEAU)
echo   - PUSH_GITHUB_INSTRUCTIONS.md (NOUVEAU)
echo   - COMMIT_READY.md (NOUVEAU)
echo   - COMMIT_FINAL_INSTRUCTIONS.md (NOUVEAU)
echo   - BUGFIXES_1.22.md (NOUVEAU)
echo   - DESIGN_OPTIMIZATIONS.md (NOUVEAU)
echo   - OPTIMIZATIONS_RESUME.md (NOUVEAU)
echo   - commit_github.bat (NOUVEAU)
echo   - commit_github.ps1 (NOUVEAU)
echo   - commit_with_gh.bat (NOUVEAU)
echo   - config.py (modifie)
echo   - app.py (modifie)
echo   - routes/tools.py (modifie)
echo   - templates/base.html (modifie)
echo   - templates/admin.html (modifie)
echo   - templates/users.html (modifie)
echo   - templates/recycle_bin.html (modifie)
echo   - templates/locked_accounts.html (modifie)
echo   - .env.example (modifie)
echo   - security.py (modifie - CSP)
echo   - static/sw.js (modifie - Service Worker)
echo   - static/css/optimizations.css (NOUVEAU - Optimisations design)
echo   - templates/base.html (modifie - CSS optimisations)
echo.

REM Ajouter les fichiers
echo [INFO] Ajout des fichiers...
git add VERSION
git add CHANGELOG.md
git add features.py
git add templates/feature_disabled.html
git add MODULARITE.md
git add RESUME_CHANGEMENTS.md
git add PUSH_GITHUB_INSTRUCTIONS.md
git add COMMIT_READY.md
git add COMMIT_FINAL_INSTRUCTIONS.md
git add BUGFIXES_1.22.md
git add DESIGN_OPTIMIZATIONS.md
git add OPTIMIZATIONS_RESUME.md
git add commit_github.bat
git add commit_github.ps1
git add commit_with_gh.bat
git add config.py
git add app.py
git add routes/tools.py
git add templates/base.html
git add templates/admin.html
git add templates/users.html
git add templates/recycle_bin.html
git add templates/locked_accounts.html
git add .env.example
git add security.py
git add static/sw.js
git add static/css/optimizations.css
git add templates/base.html

echo [OK] Fichiers ajoutes
echo.

REM Créer le commit
echo [INFO] Creation du commit...
git commit -m "feat: Système de feature flags et corrections erreurs 500 [v1.22.0]

Nouveautés :
- Système de feature flags avec 50+ options de modularité
- Module features.py avec utilitaires et décorateurs
- Page feature_disabled.html pour fonctionnalités désactivées
- Documentation MODULARITE.md avec guide complet
- Page admin.html redesignée

Corrections :
- Erreur 500 sur /recycle-bin (route restore_deleted_object)
- Erreur 500 sur /locked-accounts (route bulk_unlock_accounts)
- Erreur export_expiring_pdf dans les logs

Modifications :
- config.py : 50+ variables FEATURE_XXX_ENABLED
- templates/base.html : Menu conditionnel selon feature flags
- routes/tools.py : 3 routes manquantes ajoutées
- .env.example : Section Feature Flags ajoutée
- VERSION : Passage à 1.22.0

Tests :
- 14/14 tests automatisés passés
- 100% des pages fonctionnelles

BREAKING CHANGE: Nouvelles variables FEATURE_XXX_ENABLED dans .env
Voir MODULARITE.md pour la liste complète des feature flags."

if errorlevel 1 (
    echo [ERREUR] Echec du commit.
    pause
    exit /b 1
)

echo [OK] Commit cree avec succes !
echo.

REM Demander si on veut pousser
set /p PUSH="Voulez-vous pousser vers GitHub maintenant ? (O/n) : "
if /i "!PUSH!"=="n" (
    echo.
    echo [INFO] Pour pousser manuellement : gh repo push
    pause
    exit /b 0
)

echo.
echo [INFO] Push vers GitHub...
gh repo push --force-with-lease

if errorlevel 1 (
    echo.
    echo [AVERTISSEMENT] Le push a echoue.
    echo   Essayez : git push origin main
    pause
    exit /b 1
)

echo.
echo =====================================================================
echo   COMMIT ET PUSH TERMINES AVEC SUCCES!
echo.
echo   Version : 1.22.0
echo   Depot   : https://github.com/fred-selest/microsoft-active-directory
echo.
echo   Prochaines etapes :
echo   1. Verifier le commit sur GitHub
echo   2. Creer un tag : git tag v1.22.0
echo   3. Creer une release sur GitHub
echo =====================================================================
echo.
pause
exit /b 0
