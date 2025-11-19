@echo off
setlocal enabledelayedexpansion

REM ============================================
REM Configuration du service Windows
REM - Demarrage automatique avec Windows
REM - Ouverture du pare-feu
REM ============================================

echo.
echo ============================================
echo Configuration du service AD Web Interface
echo ============================================
echo.

REM Se placer dans le repertoire du script
cd /d "%~dp0"

REM Verifier les droits administrateur
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Ce script necessite des droits administrateur.
    echo Faites un clic droit sur le fichier et selectionnez "Executer en tant qu'administrateur"
    echo.
    pause
    exit /b 1
)

REM Lire le port depuis le fichier .env
set PORT=5000
if exist ".env" (
    for /f "tokens=1,2 delims==" %%a in (.env) do (
        if "%%a"=="AD_WEB_PORT" set PORT=%%b
    )
)

echo Port detecte: %PORT%
echo.

REM ============================================
REM Configuration du pare-feu Windows
REM ============================================
echo [1/3] Configuration du pare-feu Windows...

REM Supprimer l'ancienne regle si elle existe
netsh advfirewall firewall delete rule name="AD Web Interface" >nul 2>&1

REM Creer la nouvelle regle
netsh advfirewall firewall add rule name="AD Web Interface" dir=in action=allow protocol=tcp localport=%PORT% profile=any

if %errorlevel% equ 0 (
    echo [OK] Regle de pare-feu creee pour le port %PORT%
) else (
    echo [ERREUR] Impossible de configurer le pare-feu
)

echo.

REM ============================================
REM Creation de la tache planifiee
REM ============================================
echo [2/3] Configuration du demarrage automatique...

REM Chemin complet vers run.bat
set SCRIPT_PATH=%~dp0run.bat

REM Supprimer l'ancienne tache si elle existe
schtasks /delete /tn "AD Web Interface" /f >nul 2>&1

REM Creer la tache planifiee pour demarrer au login
schtasks /create /tn "AD Web Interface" /tr "\"%SCRIPT_PATH%\"" /sc onlogon /rl highest /f

if %errorlevel% equ 0 (
    echo [OK] Tache planifiee creee (demarrage a la connexion)
) else (
    echo [ERREUR] Impossible de creer la tache planifiee
)

echo.

REM ============================================
REM Creation du raccourci dans le menu Demarrer
REM ============================================
echo [3/3] Creation du raccourci...

set SHORTCUT_PATH=%APPDATA%\Microsoft\Windows\Start Menu\Programs\AD Web Interface.lnk
set VBS_FILE=%TEMP%\create_shortcut.vbs

REM Creer un script VBS pour creer le raccourci
(
echo Set oWS = WScript.CreateObject("WScript.Shell"^)
echo sLinkFile = "%SHORTCUT_PATH%"
echo Set oLink = oWS.CreateShortcut(sLinkFile^)
echo oLink.TargetPath = "%SCRIPT_PATH%"
echo oLink.WorkingDirectory = "%~dp0"
echo oLink.Description = "Interface Web Active Directory"
echo oLink.Save
) > "%VBS_FILE%"

cscript //nologo "%VBS_FILE%"
del "%VBS_FILE%"

if exist "%SHORTCUT_PATH%" (
    echo [OK] Raccourci cree dans le menu Demarrer
) else (
    echo [AVERTISSEMENT] Impossible de creer le raccourci
)

echo.
echo ============================================
echo Configuration terminee!
echo ============================================
echo.
echo Resume:
echo - Port: %PORT%
echo - Pare-feu: Ouvert
echo - Demarrage automatique: Active
echo - Raccourci: Menu Demarrer
echo.
echo Le serveur demarrera automatiquement a la prochaine connexion.
echo Pour demarrer maintenant, executez: run.bat
echo.
echo Acces: http://localhost:%PORT%
echo.

pause
