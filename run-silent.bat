@echo off
REM Script de demarrage silencieux (sans fenetre)
REM Double-cliquez sur ce fichier pour demarrer le serveur en arriere-plan

cd /d "%~dp0"

REM Definir le mode silencieux
set AD_SILENT=true

REM Chercher Python dans l'ordre de preference
if exist venv\Scripts\pythonw.exe (
    start "" /B venv\Scripts\pythonw.exe run.py
    exit /b 0
)

if exist venv\Scripts\python.exe (
    start "" /B venv\Scripts\python.exe run.py
    exit /b 0
)

REM Essayer pythonw.exe du systeme
where pythonw >nul 2>&1
if not errorlevel 1 (
    start "" /B pythonw run.py
    exit /b 0
)

REM Essayer python.exe du systeme
where python >nul 2>&1
if not errorlevel 1 (
    start "" /B python run.py
    exit /b 0
)

REM Aucun Python trouve
echo Erreur: Python n'est pas installe ou n'est pas dans le PATH
pause
