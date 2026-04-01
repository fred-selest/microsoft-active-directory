@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title Commit GitHub - AD Web Interface v1.22.0

echo =====================================================================
echo   COMMIT GITHUB - AD Web Interface v1.22.0
echo =====================================================================
echo.

REM Vérifier si Git est installé
git --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Git n'est pas installe ou non dans le PATH.
    echo.
    echo   Installation recommandee :
    echo   1. winget install Git.Git
    echo   2. Redemarrer ce script
    echo.
    echo   OU utiliser GitHub Desktop :
    echo   https://desktop.github.com/
    echo.
    pause
    exit /b 1
)

REM Vérifier le statut Git
echo [INFO] Verification du depot Git...
git status >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Ce dossier n'est pas un depot Git.
    echo.
    echo   Initialisation du depot...
    git init
    git remote add origin https://github.com/fred-selest/microsoft-active-directory.git
)

REM Afficher les fichiers à commiter
echo.
echo [INFO] Fichiers a commiter :
echo   - VERSION (1.22.0)
echo   - CHANGELOG.md (mis a jour)
echo   - features.py (NOUVEAU)
echo   - templates/feature_disabled.html (NOUVEAU)
echo   - MODULARITE.md (NOUVEAU)
echo   - RESUME_CHANGEMENTS.md (NOUVEAU)
echo   - PUSH_GITHUB_INSTRUCTIONS.md (NOUVEAU)
echo   - config.py (modifie)
echo   - app.py (modifie)
echo   - routes/tools.py (modifie)
echo   - templates/base.html (modifie)
echo   - templates/admin.html (modifie)
echo   - templates/recycle_bin.html (modifie)
echo   - templates/locked_accounts.html (modifie)
echo   - .env.example (modifie)
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
git add config.py
git add app.py
git add routes/tools.py
git add templates/base.html
git add templates/admin.html
git add templates/recycle_bin.html
git add templates/locked_accounts.html
git add .env.example

REM Créer le commit
echo.
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

echo [OK] Commit cree avec succes!
echo.

REM Demander si on veut pousser
set /p PUSH="Voulez-vous pousser vers GitHub maintenant ? (O/n) : "
if /i "!PUSH!"=="n" (
    echo.
    echo [INFO] Pour pousser manuellement : git push origin main
    pause
    exit /b 0
)

echo.
echo [INFO] Push vers GitHub...
git push origin main

if errorlevel 1 (
    echo.
    echo [AVERTISSEMENT] Le push a echoue.
    echo   Verifiez que vous etes authentifie sur GitHub.
    echo.
    echo   Pour pousser manuellement : git push origin main
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
echo   2. Mettre a jour CHANGELOG.md
echo   3. Creer une release sur GitHub
echo =====================================================================
echo.
pause
exit /b 0
