@echo off
REM ============================================
REM PRÉPARATION DU COMMIT - AD Web Interface v1.23.0
REM ============================================

echo.
echo ============================================================
echo   AD Web Interface - Version 1.23.0
echo   Préparation des fichiers pour GitHub
echo ============================================================
echo.

echo [INFO] Nettoyage des fichiers temporaires...
if exist logs\*.png del /Q logs\*.png 2>nul
if exist logs\*.log del /Q logs\*.log 2>nul
if exist data\settings.json del /Q data\settings.json 2>nul
if exist .env del /Q .env 2>nul
if exist __pycache__ rd /S /Q __pycache__ 2>nul

echo [INFO] Création du fichier de version...
echo 1.23.0 > VERSION

echo [INFO] Génération du fichier .gitignore...
(
echo # Python
echo __pycache__/
echo *.py[cod]
echo *.so
echo .Python
echo venv/
echo env/
echo 
echo # Logs
echo logs/*.log
echo logs/*.png
echo 
echo # Data
echo data/settings.json
echo data/backups/*
echo data/crypto_salt.bin
echo 
echo # Configuration locale
echo .env
echo .env.local
echo 
echo # IDE
echo .vscode/
echo .idea/
echo *.swp
echo *.swo
echo 
echo # OS
echo Thumbs.db
echo .DS_Store
echo 
echo # Tests
echo logs/screenshots/
echo logs/test_results.json
) > .gitignore

echo [INFO] Création du fichier README_COMMIT.md...
(
echo # AD Web Interface v1.23.0
echo.
echo ## Installation
echo.
echo 1. Extraire les fichiers dans C:\\AD-WebInterface\\
echo 2. Copier .env.example vers .env
echo 3. Éditer .env avec votre configuration
echo 4. Exécuter: pip install -r requirements.txt
echo 5. Lancer: python run.py
echo.
echo ## Nouvelles fonctionnalités v1.23.0
echo.
echo - 🔔 Système d'alertes complet (/alerts)
echo - 🔐 Case "Changer MDP à prochaine connexion" (/users/create)
echo - 🎨 Personnalisation avancée (logo, couleurs, police, CSS)
echo - 🧰 Scripts PowerShell de correction (scripts/fix_*.ps1)
echo - 🔍 Détection automatique des protocoles obsolètes
echo - 📊 Tests visuels automatisés (test_*.py)
echo.
echo ## Corrections de bugs
echo.
echo - Overflow horizontal corrigé (+280px → 0px)
echo - Boutons empilés verticalement
echo - Politique MDP valeurs vides
echo - Templates avec erreurs syntaxe
echo - Fonctions JavaScript manquantes
echo.
echo ## Documentation
echo.
echo - CHANGELOG.md - Historique complet
echo - RELEASE_NOTES_v1.23.0.md - Notes de version
echo - GUIDE_PERSONNALISATION.md - Guide de personnalisation
echo - GUIDE_TEST_RESPONSIVE.md - Tests responsive
echo.
echo ## Commit GitHub
echo.
echo Message de commit recommandé:
echo.
echo     v1.23.0 - Alertes, Personnalisation, Correction bugs et Sécurité
echo.
echo     NOUVELLES FONCTIONNALITÉS:
echo     🔔 Système d'alertes complet
echo     🔐 Case "Changer MDP à prochaine connexion"
echo     🎨 Personnalisation avancée
echo     🧰 Scripts PowerShell de correction
echo     🔍 Détection protocoles obsolètes
echo     📊 Tests visuels automatisés
echo.
echo     CORRECTIONS:
echo     - Overflow horizontal (+280px → 0px)
echo     - Boutons empilés verticalement
echo     - Politique MDP valeurs vides
echo     - Templates avec erreurs
echo     - Fonctions JavaScript manquantes
echo.
echo     SÉCURITÉ:
echo     - Autorisations granulaires AD
echo     - Détection protocoles obsolètes
echo     - Audit MDP enrichi (score 0-100)
echo.
echo     TECHNIQUE:
echo     - +2500 lignes ajoutées, -200 supprimées
echo     - 20+ fichiers modifiés
echo     - 8 pages testées automatiquement
echo.
echo ## Upload vers GitHub
echo.
echo ### Option 1: Git en ligne de commande
echo.
echo     git add -A
echo     git commit -m "v1.23.0 - Alertes, Personnalisation, Correction bugs et Sécurité"
echo     git push origin main
echo.
echo ### Option 2: GitHub Desktop
echo.
echo 1. Ouvrir GitHub Desktop
echo 2. File → Add Local Repository → C:\\AD-WebInterface
echo 3. Cocher tous les fichiers modifiés
echo 4. Commit message: v1.23.0 - Release
echo 5. Push
echo.
echo ### Option 3: GitHub Web
echo.
echo 1. Aller sur https://github.com/fred-selest/microsoft-active-directory
echo 2. Cliquer sur "Add file" → "Upload files"
echo 3. Glisser-déposer TOUS les fichiers du dossier
echo 4. Commit message: v1.23.0 - Release
echo 5. Cliquer "Commit changes"
echo.
) > README_COMMIT.md

echo [INFO] Vérification des fichiers critiques...
echo.

set ERRORS=0

if not exist app.py (
    echo [ERREUR] app.py manquant!
    set ERRORS=1
)

if not exist VERSION (
    echo [ERREUR] VERSION manquant!
    set ERRORS=1
)

if not exist CHANGELOG.md (
    echo [ERREUR] CHANGELOG.md manquant!
    set ERRORS=1
)

if not exist templates\alerts.html (
    echo [ERREUR] templates\alerts.html manquant!
    set ERRORS=1
)

if not exist scripts\fix_smbv1.ps1 (
    echo [ERREUR] scripts\fix_smbv1.ps1 manquant!
    set ERRORS=1
)

if %ERRORS%==0 (
    echo [OK] Tous les fichiers critiques sont présents
    echo.
    echo ============================================================
    echo   PRÉPARATION TERMINÉE AVEC SUCCÈS
    echo ============================================================
    echo.
    echo Fichiers créés:
    echo   - .gitignore
    echo   - README_COMMIT.md
    echo   - VERSION (1.23.0)
    echo.
    echo Prochaines étapes:
    echo   1. Vérifier que Git est installé
    echo   2. Exécuter: git add -A
    echo   3. Exécuter: git commit -m "v1.23.0 - Release"
    echo   4. Exécuter: git push origin main
    echo.
    echo OU utiliser GitHub Desktop / GitHub Web
    echo.
) else (
    echo.
    echo ============================================================
    echo   ERREURS DÉTECTÉES - Vérifiez les fichiers manquants
    echo ============================================================
    echo.
)

pause
