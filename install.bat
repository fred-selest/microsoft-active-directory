@echo off
REM Script d'installation pour Windows
REM Lance l'assistant d'installation interactif

echo ======================================================
echo   Installation - Interface Web Active Directory
echo ======================================================
echo.

REM Se placer dans le répertoire du script
cd /d "%~dp0"

REM Vérifier si Python est installé
python --version >nul 2>&1
if errorlevel 1 (
    echo Erreur: Python n'est pas installe ou n'est pas dans le PATH.
    echo.
    echo Pour installer Python :
    echo   1. Telechargez Python depuis https://python.org
    echo   2. Lors de l'installation, cochez "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

REM Afficher la version de Python
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Python %PYTHON_VERSION% detecte
echo.

REM Lancer l'assistant d'installation
python install.py

pause
