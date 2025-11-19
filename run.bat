@echo off
REM Script de demarrage Windows pour l'interface Web AD

REM Se placer dans le repertoire du script
cd /d "%~dp0"

echo Demarrage de l'interface Web AD sur Windows...
echo Repertoire: %cd%
echo.

REM Verifier si Python est disponible
python --version >nul 2>&1
if errorlevel 1 (
    echo Erreur: Python n'est pas installe ou n'est pas dans le PATH
    echo Veuillez installer Python depuis https://python.org
    pause
    exit /b 1
)

REM Verifier si l'environnement virtuel existe
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
    echo Environnement virtuel active
) else (
    echo Note: Aucun environnement virtuel trouve. Utilisation du Python systeme.
    echo Pour creer un venv: python -m venv venv
)

REM Installer les dependances si necessaire
pip show flask >nul 2>&1
if errorlevel 1 (
    echo Installation des dependances...
    pip install -r requirements.txt
)

REM Demarrer l'application
python run.py

pause
