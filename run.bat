@echo off
REM Script de démarrage Windows pour l'interface Web AD
echo Démarrage de l'interface Web AD sur Windows...
echo.

REM Vérifier si Python est disponible
python --version >nul 2>&1
if errorlevel 1 (
    echo Erreur: Python n'est pas installé ou n'est pas dans le PATH
    echo Veuillez installer Python depuis https://python.org
    pause
    exit /b 1
)

REM Vérifier si l'environnement virtuel existe
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
    echo Environnement virtuel activé
) else (
    echo Note: Aucun environnement virtuel trouvé. Utilisation du Python système.
    echo Pour créer un venv: python -m venv venv
)

REM Installer les dépendances si nécessaire
pip show flask >nul 2>&1
if errorlevel 1 (
    echo Installation des dépendances...
    pip install -r requirements.txt
)

REM Démarrer l'application
python run.py

pause
