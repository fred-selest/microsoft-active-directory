@echo off
setlocal enabledelayedexpansion

REM Script d'installation pour Windows
REM Télécharge le projet depuis GitHub, installe Python si nécessaire, et configure le serveur

echo ======================================================
echo   Installation - Interface Web Active Directory
echo ======================================================
echo.

REM Définir les variables
set "GITHUB_REPO=fred-selest/microsoft-active-directory"
set "BRANCH=claude/cross-platform-web-interface-017bbfitWFZ7Ndcg51ZZUzC2"
set "PROJECT_DIR=microsoft-active-directory"

REM Vérifier si nous sommes déjà dans le dossier du projet (install.py existe)
if exist "install.py" (
    echo Fichiers du projet detectes.
    goto :check_python
)

REM Télécharger le projet depuis GitHub
echo Telechargement du projet depuis GitHub...
echo.

REM Vérifier si Git est installé
git --version >nul 2>&1
if not errorlevel 1 (
    echo Git detecte. Clonage du repository...
    git clone -b %BRANCH% https://github.com/%GITHUB_REPO%.git
    if errorlevel 1 (
        echo Erreur lors du clonage. Tentative de telechargement ZIP...
        goto :download_zip
    )
    cd %PROJECT_DIR%
    goto :check_python
)

:download_zip
echo Telechargement du projet en ZIP...

REM Créer un répertoire temporaire
if not exist "%TEMP%\ad-web-install" mkdir "%TEMP%\ad-web-install"

REM Télécharger le ZIP avec PowerShell
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri 'https://github.com/%GITHUB_REPO%/archive/refs/heads/%BRANCH%.zip' -OutFile '%TEMP%\ad-web-install\project.zip' -ErrorAction Stop; Write-Host 'Telechargement termine.' } catch { Write-Host 'Erreur: ' + $_.Exception.Message; exit 1 }}"

if not exist "%TEMP%\ad-web-install\project.zip" (
    echo.
    echo Erreur: Impossible de telecharger le projet.
    echo Verifiez votre connexion internet.
    echo.
    echo Vous pouvez telecharger manuellement depuis:
    echo https://github.com/%GITHUB_REPO%
    goto :end
)

echo Extraction des fichiers...

REM Extraire le ZIP avec PowerShell
powershell -Command "& {Expand-Archive -Path '%TEMP%\ad-web-install\project.zip' -DestinationPath '%TEMP%\ad-web-install\extracted' -Force}"

REM Trouver le dossier extrait (le nom inclut le nom de la branche)
for /d %%i in ("%TEMP%\ad-web-install\extracted\*") do set "EXTRACTED_DIR=%%i"

REM Copier les fichiers vers le répertoire actuel ou créer un nouveau dossier
if exist "%PROJECT_DIR%" (
    echo Le dossier %PROJECT_DIR% existe deja.
    set /p OVERWRITE="Voulez-vous le remplacer? [o/N]: "
    if /i "!OVERWRITE!"=="o" (
        rmdir /s /q "%PROJECT_DIR%"
    ) else (
        echo Installation annulee.
        goto :cleanup
    )
)

REM Déplacer le dossier extrait
move "!EXTRACTED_DIR!" "%PROJECT_DIR%" >nul

echo Fichiers extraits dans %PROJECT_DIR%
cd %PROJECT_DIR%

REM Nettoyer les fichiers temporaires
del "%TEMP%\ad-web-install\project.zip" >nul 2>&1
rmdir /s /q "%TEMP%\ad-web-install" >nul 2>&1

:check_python
echo.

REM Vérifier si Python est installé
python --version >nul 2>&1
if errorlevel 1 goto :install_python

REM Python est installé, afficher la version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Python %PYTHON_VERSION% detecte
echo.

REM Lancer l'assistant d'installation
python install.py
goto :end

:install_python
echo Python n'est pas installe sur ce systeme.
echo.

set /p INSTALL_PYTHON="Voulez-vous telecharger et installer Python automatiquement? [O/n]: "
if /i "!INSTALL_PYTHON!"=="n" (
    echo.
    echo Installation annulee.
    echo Vous pouvez installer Python manuellement depuis https://python.org
    goto :end
)

echo.
echo Telechargement de Python 3.12...

REM Créer un répertoire temporaire
if not exist "%TEMP%\ad-web-install" mkdir "%TEMP%\ad-web-install"

REM Télécharger Python avec PowerShell
echo Telechargement en cours, veuillez patienter...
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe' -OutFile '%TEMP%\ad-web-install\python-installer.exe' -ErrorAction Stop } catch { exit 1 }}"

if not exist "%TEMP%\ad-web-install\python-installer.exe" (
    echo.
    echo Erreur: Impossible de telecharger Python.
    echo Verifiez votre connexion internet.
    echo.
    echo Vous pouvez installer Python manuellement depuis https://python.org
    goto :end
)

echo Telechargement termine.
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
    goto :cleanup
)

echo.
echo Python installe avec succes!
echo.
echo ======================================================
echo IMPORTANT: Vous devez redemarrer cette fenetre
echo de commande pour que Python soit disponible.
echo.
echo Apres avoir ferme cette fenetre, ouvrez une nouvelle
echo invite de commandes et relancez install.bat
echo ======================================================
echo.

:cleanup
REM Nettoyer les fichiers temporaires
if exist "%TEMP%\ad-web-install\python-installer.exe" del "%TEMP%\ad-web-install\python-installer.exe" >nul 2>&1
if exist "%TEMP%\ad-web-install" rmdir /s /q "%TEMP%\ad-web-install" >nul 2>&1

:end
endlocal
pause
