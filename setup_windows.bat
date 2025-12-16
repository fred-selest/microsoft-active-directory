@echo off
REM Installation Simple - Windows
echo ========================================
echo Installation AD Web Interface - Windows
echo ========================================
echo.

REM Verifier Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installe ou n'est pas dans PATH
    echo.
    echo Telechargez Python depuis: https://www.python.org/downloads/
    echo IMPORTANT: Cochez "Add Python to PATH" lors de l'installation
    pause
    exit /b 1
)

echo [OK] Python detecte
python --version
echo.

REM Creer venv
echo Creation environnement virtuel...
if exist venv (
    echo Environnement virtuel existe deja
) else (
    python -m venv venv
    if errorlevel 1 (
        echo [ERREUR] Echec creation venv
        pause
        exit /b 1
    )
    echo [OK] Environnement virtuel cree
)
echo.

REM Activer venv et installer
echo Installation dependances...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERREUR] Echec installation dependances
    pause
    exit /b 1
)
echo [OK] Dependances installees
echo.

REM Creer dossiers
if not exist logs mkdir logs
if not exist data mkdir data
if not exist static\images mkdir static\images
echo [OK] Dossiers crees
echo.

REM Creer .env si absent
if not exist .env (
    echo SECRET_KEY=CHANGEME-PRODUCTION> .env
    echo FLASK_ENV=production>> .env
    echo HOST=0.0.0.0>> .env
    echo PORT=5000>> .env
    echo [OK] Fichier .env cree
    echo IMPORTANT: Modifiez SECRET_KEY dans .env
) else (
    echo [INFO] Fichier .env existe deja
)
echo.

echo ========================================
echo Installation terminee!
echo ========================================
echo.
echo Pour demarrer:
echo   1. Double-cliquez sur run.bat
echo   2. Ou: run_legacy.bat (si erreur MD4 Python 3.12+)
echo.
echo Acces: http://localhost:5000
echo.
pause
