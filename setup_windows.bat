@echo off
setlocal enabledelayedexpansion
echo ========================================
echo Installation AD Web Interface - Windows
echo ========================================
echo.

REM Chercher Python sous differentes commandes (python, py, python3)
set PYTHON_CMD=

python --version >nul 2>&1
if not errorlevel 1 (
    set PYTHON_CMD=python
    goto :python_found
)

py --version >nul 2>&1
if not errorlevel 1 (
    set PYTHON_CMD=py
    goto :python_found
)

python3 --version >nul 2>&1
if not errorlevel 1 (
    set PYTHON_CMD=python3
    goto :python_found
)

REM Aucun Python trouve - proposer de le telecharger
echo [ERREUR] Python n'est pas installe ou n'est pas dans PATH
echo.
echo Solutions:
echo   1. Telechargez Python: https://www.python.org/downloads/
echo      IMPORTANT: Cochez "Add Python to PATH" lors de l'installation
echo.
echo   2. Si Python est deja installe, ouvrez une nouvelle fenetre
echo      de commande (le PATH n'est mis a jour qu'au redemarrage).
echo.
set /p DOWNLOAD="Ouvrir la page de telechargement Python dans le navigateur? [O/n]: "
if /i not "!DOWNLOAD!"=="n" (
    start https://www.python.org/downloads/
)
pause
exit /b 1

:python_found
echo [OK] Python detecte via: %PYTHON_CMD%
%PYTHON_CMD% --version
echo.

REM Verifier que la version est >= 3.8
for /f "tokens=2" %%v in ('%PYTHON_CMD% --version 2^>^&1') do set PY_VER=%%v
for /f "tokens=1,2 delims=." %%a in ("!PY_VER!") do (
    if %%a LSS 3 (
        echo [ERREUR] Python 3.8+ requis. Version detectee: !PY_VER!
        pause
        exit /b 1
    )
    if %%a EQU 3 if %%b LSS 8 (
        echo [ERREUR] Python 3.8+ requis. Version detectee: !PY_VER!
        pause
        exit /b 1
    )
)

REM Creer venv
echo Creation de l'environnement virtuel...
if exist venv (
    echo [INFO] Environnement virtuel existe deja
) else (
    %PYTHON_CMD% -m venv venv
    if errorlevel 1 (
        echo [ERREUR] Echec creation venv
        echo Essayez: %PYTHON_CMD% -m pip install virtualenv
        pause
        exit /b 1
    )
    echo [OK] Environnement virtuel cree
)
echo.

REM Activer le venv et installer les dependances
echo Installation des dependances...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [ERREUR] Echec installation dependances
    echo Verifiez votre connexion internet et reessayez.
    pause
    exit /b 1
)
echo [OK] Dependances installees
echo.

REM Creer les dossiers necessaires
if not exist logs mkdir logs
if not exist data mkdir data
echo [OK] Dossiers crees
echo.

REM Creer .env si absent avec une SECRET_KEY aleatoire et des valeurs par defaut
if not exist .env (
    echo Generation du fichier .env...
    for /f %%i in ('python -c "import secrets; print(secrets.token_hex(32))"') do set RAND_KEY=%%i
    (
        echo # Configuration generee automatiquement au premier demarrage
        echo # Modifiez ce fichier pour configurer votre serveur Active Directory
        echo.
        echo SECRET_KEY=!RAND_KEY!
        echo FLASK_DEBUG=true
        echo FLASK_ENV=development
        echo.
        echo AD_WEB_HOST=0.0.0.0
        echo AD_WEB_PORT=5000
        echo.
        echo # Laissez vide pour configurer via l'interface web
        echo AD_SERVER=
        echo AD_PORT=389
        echo AD_USE_SSL=false
        echo AD_BASE_DN=
        echo.
        echo # Desactive pour un acces local en HTTP
        echo FORCE_HTTPS=false
        echo SESSION_COOKIE_SECURE=false
        echo.
        echo RBAC_ENABLED=true
        echo DEFAULT_ROLE=reader
        echo SESSION_TIMEOUT=30
        echo ITEMS_PER_PAGE=25
    ) > .env
    echo [OK] Fichier .env cree avec une cle secrete aleatoire
) else (
    echo [INFO] Fichier .env existe deja
)
echo.

echo ========================================
echo Installation terminee!
echo ========================================
echo.
echo Pour demarrer l'application:
echo   Double-cliquez sur run.bat
echo   Ou dans cette fenetre: run.bat
echo.
echo Acces: http://localhost:5000
echo.
pause
endlocal
