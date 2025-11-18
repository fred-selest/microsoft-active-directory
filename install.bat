@echo off
REM Script d'installation pour Windows
REM Télécharge Python si nécessaire et lance l'assistant d'installation

echo ======================================================
echo   Installation - Interface Web Active Directory
echo ======================================================
echo.

REM Se placer dans le répertoire du script
cd /d "%~dp0"

REM Vérifier si Python est installé
python --version >nul 2>&1
if errorlevel 1 (
    echo Python n'est pas installe sur ce systeme.
    echo.

    set /p INSTALL_PYTHON="Voulez-vous telecharger et installer Python automatiquement? [O/n]: "
    if /i "%INSTALL_PYTHON%"=="n" (
        echo.
        echo Installation annulee.
        echo Vous pouvez installer Python manuellement depuis https://python.org
        pause
        exit /b 1
    )

    echo.
    echo Telechargement de Python...

    REM Créer un répertoire temporaire
    if not exist "%TEMP%\ad-web-install" mkdir "%TEMP%\ad-web-install"

    REM Télécharger Python avec PowerShell
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe' -OutFile '%TEMP%\ad-web-install\python-installer.exe'}"

    if not exist "%TEMP%\ad-web-install\python-installer.exe" (
        echo.
        echo Erreur: Impossible de telecharger Python.
        echo Verifiez votre connexion internet.
        echo.
        echo Vous pouvez installer Python manuellement depuis https://python.org
        pause
        exit /b 1
    )

    echo.
    echo Installation de Python...
    echo (Cela peut prendre quelques minutes)
    echo.

    REM Installer Python silencieusement avec pip et ajout au PATH
    "%TEMP%\ad-web-install\python-installer.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_test=0

    if errorlevel 1 (
        echo.
        echo Erreur lors de l'installation de Python.
        echo Essayez d'installer Python manuellement depuis https://python.org
        pause
        exit /b 1
    )

    echo.
    echo Python installe avec succes!
    echo.
    echo IMPORTANT: Vous devez redemarrer cette fenetre de commande
    echo pour que Python soit disponible dans le PATH.
    echo.
    echo Apres avoir ferme cette fenetre, ouvrez une nouvelle invite
    echo de commandes et relancez install.bat
    echo.

    REM Nettoyer
    del "%TEMP%\ad-web-install\python-installer.exe" >nul 2>&1
    rmdir "%TEMP%\ad-web-install" >nul 2>&1

    pause
    exit /b 0
)

REM Afficher la version de Python
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Python %PYTHON_VERSION% detecte
echo.

REM Lancer l'assistant d'installation
python install.py

pause
