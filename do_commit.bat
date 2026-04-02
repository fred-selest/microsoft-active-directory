@echo off
setlocal EnableDelayedExpansion

REM ============================================
REM COMMIT AUTOMATIQUE - AD Web Interface v1.23.0
REM ============================================

echo.
echo ============================================================
echo   AD Web Interface v1.23.0 - Commit vers GitHub
echo ============================================================
echo.

REM Chemin vers Git
set "GIT_PATH=C:\Program Files\Git\cmd\git.exe"

REM Vérifier si Git existe
if not exist "%GIT_PATH%" (
    echo [ERREUR] Git introuvable a l'adresse: %GIT_PATH%
    echo.
    echo Installez Git depuis: https://git-scm.com/download/win
    pause
    exit /b 1
)

echo [INFO] Git trouve: %GIT_PATH%
echo.

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
echo [INFO] Verification des modifications...
"%GIT_PATH%" status --short

echo.
set /p CONFIRM="Voulez-vous continuer avec le commit? (O/N): "
if /i not "%CONFIRM%"=="O" (
    echo [ANNULATION] Commit annule par l'utilisateur
    pause
    exit /b 1
)

echo.
echo [INFO] Creation du commit...
"%GIT_PATH%" commit -m "v1.23.0 - Alertes, Personnalisation, Correction bugs et Securite

NOUVELLES FONCTIONNALITES:
- Systeme d'alertes complet (/alerts)
- Case Changer MDP a prochaine connexion (/users/create)
- Personnalisation avancee (logo, couleurs, police, CSS)
- Scripts PowerShell de correction (SMBv1, NTLM, LDAP)
- Detection automatique des protocoles obsolètes
- Tests visuels automatises avec Chromium

CORRECTIONS DE BUGS:
- Overflow horizontal (+280px -> 0px)
- Boutons empiles verticalement
- Politique MDP valeurs vides
- Templates avec erreurs syntaxe
- Fonctions JavaScript manquantes

SECURITE:
- Autorisations granulaires par groupe AD
- Detection et correction protocoles obsolètes
- Audit des mots de passe enrichi (score 0-100)

TECHNIQUE:
- +2500 lignes ajoutees, -200 supprimees
- 20+ fichiers modifies
- 8 pages testees automatiquement

Voir CHANGELOG.md et RELEASE_NOTES_v1.23.0.md pour le detail complet."

if %ERRORLEVEL% NEQ 0 (
    echo [ERREUR] Echec du commit
    echo.
    echo Essayez de configurer votre nom et email Git:
    echo   git config --global user.name "Votre Nom"
    echo   git config --global user.email "votre@email.com"
    pause
    exit /b 1
)

echo.
echo [SUCCES] Commit cree avec succes!
echo.

REM Afficher le dernier commit
echo [INFO] Dernier commit:
"%GIT_PATH%" log -1 --oneline

echo.
echo ============================================================
echo   ETAPE SUIVANTE : PUSH VERS GITHUB
echo ============================================================
echo.
echo Pour pousser vers GitHub, executez:
echo.
echo   "%GIT_PATH%" push origin main
echo.
echo Ou utilisez GitHub Desktop ou l'interface web GitHub.
echo.

set /p PUSH="Voulez-vous pousser vers GitHub maintenant? (O/N): "
if /i "%PUSH%"=="O" (
    echo.
    echo [INFO] Push en cours...
    "%GIT_PATH%" push origin main
    
    if %ERRORLEVEL% NEQ 0 (
        echo.
        echo [ERREUR] Echec du push.
        echo.
        echo Verifiez:
        echo   1. Vous etes connecte a Internet
        echo   2. Vous avez les droits sur le repository
        echo   3. Vos identifiants GitHub sont configures
        echo.
        echo Essayez avec un token GitHub:
        echo   git remote set-url origin https://TOKEN@github.com/fred-selest/microsoft-active-directory.git
        echo   git push origin main
        echo.
        pause
        exit /b 1
    )
    
    echo.
    echo [SUCCES] Push reussi vers GitHub!
    echo.
    echo Rendez-vous sur:
    echo   https://github.com/fred-selest/microsoft-active-directory
    echo.
)

echo ============================================================
echo   OPERATION TERMINEE
echo ============================================================
echo.
pause
