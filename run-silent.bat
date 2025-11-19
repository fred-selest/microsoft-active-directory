@echo off
REM Script de demarrage silencieux (sans fenetre)
REM Double-cliquez sur ce fichier pour demarrer le serveur en arriere-plan

cd /d "%~dp0"

REM Utiliser pythonw.exe pour eviter la fenetre console
if exist venv\Scripts\pythonw.exe (
    start "" /B venv\Scripts\pythonw.exe run.py
) else if exist venv\Scripts\python.exe (
    start "" /B venv\Scripts\python.exe run.py
) else (
    start "" /B pythonw run.py
)
