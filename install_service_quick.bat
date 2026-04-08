@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title Installation Rapide Service - AD Web Interface

echo =====================================================================
echo   INSTALLATION RAPIDE DU SERVICE
echo   AD Web Interface - v1.36.4
echo =====================================================================
echo.

REM Verifier les droits administrateur
net session >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Executer en tant qu'administrateur
    pause
    exit /b 1
)
echo [OK] Droits administrateur OK
echo.

REM Configuration
set SERVICE_NAME=ADWebInterface
set APP_DIR=%~dp0

REM Verifier WinSW
if not exist "%APP_DIR%nssm\WinSW.exe" (
    echo [ERREUR] WinSW.exe introuvable dans nssm\
    echo.
    echo Executez d'abord install_service.bat pour le telecharger
    pause
    exit /b 1
)
echo [OK] WinSW.exe present
echo.

REM Arret service existant
sc query "%SERVICE_NAME%" >nul 2>&1
if not errorlevel 1 (
    echo Arret du service existant...
    net stop "%SERVICE_NAME%" >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete "%SERVICE_NAME%" >nul 2>&1
    timeout /t 1 /nobreak >nul
    echo [OK] Service supprime
    echo.
)

REM Installation avec WinSW
echo Installation du service...
"%APP_DIR%nssm\WinSW.exe" install
if errorlevel 1 (
    echo [ERREUR] Echec installation
    pause
    exit /b 1
)

echo [OK] Service installe avec succes
echo.

REM Demarrage
echo Demarrage du service...
net start "%SERVICE_NAME%" >nul 2>&1
if not errorlevel 1 (
    echo [OK] Service demarre
) else (
    echo [WARNING] Service installe mais non demarre
    echo   Demarrage manuel : net start %SERVICE_NAME%
)

echo.
echo =====================================================================
echo   INSTALLATION TERMINEE
echo =====================================================================
echo.
echo Service : %SERVICE_NAME%
echo URL : http://localhost:5000
echo.
echo Commandes utiles :
echo   net start %SERVICE_NAME%   - Demarrer
echo   net stop %SERVICE_NAME%    - Arreter
echo   sc query %SERVICE_NAME%    - Statut
echo.

pause
