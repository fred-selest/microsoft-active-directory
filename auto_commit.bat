@echo off
setlocal EnableDelayedExpansion

REM ============================================
REM COMMIT AUTOMATIQUE - AD Web Interface v1.23.0
REM ============================================

echo.
echo ============================================================
echo   AD Web Interface v1.23.0 - Commit automatique
echo ============================================================
echo.

REM Chemin vers Git
set "GIT_PATH=C:\Program Files\Git\cmd\git.exe"

REM Aller dans le repertoire du projet
cd /d "C:\AD-WebInterface"

REM Initialiser le repo si necessaire
if not exist ".git" (
    echo [INFO] Initialisation du depot Git...
    "%GIT_PATH%" init
    "%GIT_PATH%" remote add origin https://github.com/fred-selest/microsoft-active-directory.git
)

echo [INFO] Ajout des fichiers...
"%GIT_PATH%" add -A

echo.
echo [INFO] Creation du commit...
"%GIT_PATH%" commit -m "v1.23.0 - Alertes, Personnalisation, Correction bugs et Securite

NOUVELLES FONCTIONNALITES:
- Systeme d'alertes complet (/alerts)
- Case Changer MDP a prochaine connexion
- Personnalisation avancee (logo, couleurs, police, CSS)
- Scripts PowerShell de correction
- Detection protocoles obsolètes
- Tests visuels automatises

CORRECTIONS:
- Overflow horizontal corrige
- Boutons empiles
- Politique MDP valeurs vides
- Templates erreurs
- Fonctions JavaScript manquantes

SECURITE:
- Autorisations granulaires AD
- Detection protocoles obsolètes
- Audit MDP enrichi

TECHNIQUE:
- +2500 lignes ajoutees, -200 supprimees
- 20+ fichiers modifies
- 8 pages testees"

if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Configuration Git necessaire...
    "%GIT_PATH%" config --global user.name "AD-Web-Admin"
    "%GIT_PATH%" config --global user.email "admin@ad-web.local"
    echo [INFO] Nouvel essai de commit...
    "%GIT_PATH%" commit -m "v1.23.0 - Release"
)

echo.
echo [INFO] Push vers GitHub...
"%GIT_PATH%" push origin main 2>&1

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================================
    echo   COMMIT ET PUSH REUSSIS!
    echo ============================================================
    echo.
    echo Votre version 1.23.0 est maintenant sur GitHub!
    echo.
    echo URL: https://github.com/fred-selest/microsoft-active-directory
    echo.
) else (
    echo.
    echo ============================================================
    echo   COMMIT REUSSI MAIS PUSH ECHEC
    echo ============================================================
    echo.
    echo Le commit local est reussi, mais le push a echoue.
    echo.
    echo Pour pousser manuellement:
    echo   1. Ouvrez GitHub Desktop
    echo   2. Ou utilisez: git push origin main
    echo.
)

pause
