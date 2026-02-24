@echo off
REM Script de demarrage Windows pour l'interface Web AD

cd /d "%~dp0"

echo ======================================
echo   Interface Web Active Directory
echo ======================================
echo.

REM Verifier si Python est disponible
python --version >nul 2>&1
if errorlevel 1 (
    echo Erreur: Python n'est pas installe ou n'est pas dans le PATH.
    echo.
    echo Telechargez et installez Python depuis: https://python.org
    echo Cochez "Add Python to PATH" pendant l'installation.
    pause
    exit /b 1
)

REM Creer l'environnement virtuel s'il est absent
if not exist "venv\Scripts\activate.bat" (
    echo Creation de l'environnement virtuel...
    python -m venv venv
    if errorlevel 1 (
        echo Erreur lors de la creation du venv.
        pause
        exit /b 1
    )
    echo Environnement virtuel cree.
    echo.
)

REM Activer le venv
call venv\Scripts\activate.bat

REM Installer les dependances si Flask est absent
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo Installation des dependances Python...
    pip install -r requirements.txt --quiet
    if errorlevel 1 (
        echo Erreur lors de l'installation des dependances.
        pause
        exit /b 1
    )
    echo Dependances installees.
    echo.
)

REM Demarrer l'application (cree .env automatiquement si absent)
python run.py

pause
