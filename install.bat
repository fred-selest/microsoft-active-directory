@echo off
setlocal enabledelayedexpansion

REM Script d'installation pour Windows
REM Télécharge le projet depuis GitHub, installe Python si nécessaire, et configure le serveur

echo ======================================================
echo   Installation - Interface Web Active Directory
echo ======================================================
echo.

REM Se placer dans le répertoire du script
cd /d "%~dp0"

REM Définir les variables
set "GITHUB_REPO=fred-selest/microsoft-active-directory"
set "BRANCH=claude/cross-platform-web-interface-017bbfitWFZ7Ndcg51ZZUzC2"
set "PROJECT_DIR=ad-web-interface"

REM Vérifier si nous sommes déjà dans le dossier du projet (install.py existe)
if exist "install.py" (
    echo Fichiers du projet detectes.
    goto :check_python
)

REM Télécharger le projet depuis GitHub
echo Telechargement du projet depuis GitHub...
echo.

:download_zip
echo Telechargement du projet en ZIP...

REM Créer un répertoire temporaire
if not exist "%TEMP%\ad-web-install" mkdir "%TEMP%\ad-web-install"

REM Construire l'URL avec le nom de branche encodé
set "ZIP_URL=https://github.com/%GITHUB_REPO%/archive/refs/heads/%BRANCH%.zip"

REM Télécharger le ZIP avec PowerShell
echo URL: %ZIP_URL%
echo.
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri '%ZIP_URL%' -OutFile '%TEMP%\ad-web-install\project.zip' -ErrorAction Stop; Write-Host 'Telechargement termine.' } catch { Write-Host 'Erreur: ' $_.Exception.Message; exit 1 }}"

if not exist "%TEMP%\ad-web-install\project.zip" (
    echo.
    echo Erreur: Impossible de telecharger le projet.
    echo Verifiez votre connexion internet.
    echo.
    echo Vous pouvez telecharger manuellement depuis:
    echo https://github.com/%GITHUB_REPO%
    goto :end
)

echo.
echo Extraction des fichiers...

REM Supprimer l'ancien dossier d'extraction s'il existe
if exist "%TEMP%\ad-web-install\extracted" rmdir /s /q "%TEMP%\ad-web-install\extracted"

REM Extraire le ZIP avec PowerShell
powershell -Command "& {Expand-Archive -Path '%TEMP%\ad-web-install\project.zip' -DestinationPath '%TEMP%\ad-web-install\extracted' -Force}"

REM Trouver le dossier extrait (le nom inclut le nom de la branche)
set "EXTRACTED_DIR="
for /d %%i in ("%TEMP%\ad-web-install\extracted\*") do (
    set "EXTRACTED_DIR=%%i"
)

if "!EXTRACTED_DIR!"=="" (
    echo Erreur: Impossible de trouver le dossier extrait.
    goto :cleanup
)

echo Dossier extrait: !EXTRACTED_DIR!

REM Vérifier si le dossier de destination existe déjà
if exist "%PROJECT_DIR%" (
    echo.
    echo Le dossier %PROJECT_DIR% existe deja.
    set /p OVERWRITE="Voulez-vous le remplacer? [o/N]: "
    if /i "!OVERWRITE!"=="o" (
        rmdir /s /q "%PROJECT_DIR%"
    ) else (
        echo Installation annulee.
        goto :cleanup
    )
)

REM Renommer et déplacer le dossier extrait
echo Copie des fichiers vers %PROJECT_DIR%...
rename "!EXTRACTED_DIR!" "%PROJECT_DIR%"
move "%TEMP%\ad-web-install\extracted\%PROJECT_DIR%" "." >nul

if not exist "%PROJECT_DIR%" (
    echo Erreur lors du deplacement des fichiers.
    goto :cleanup
)

echo.
echo Fichiers extraits dans %PROJECT_DIR%
echo.

REM Entrer dans le dossier du projet
cd "%PROJECT_DIR%"

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
echo invite de commandes et relancez:
echo   cd %cd%
echo   python install.py
echo ======================================================
echo.

:cleanup
REM Nettoyer les fichiers temporaires
if exist "%TEMP%\ad-web-install\python-installer.exe" del "%TEMP%\ad-web-install\python-installer.exe" >nul 2>&1
if exist "%TEMP%\ad-web-install" rmdir /s /q "%TEMP%\ad-web-install" >nul 2>&1

:end
endlocal
pause
