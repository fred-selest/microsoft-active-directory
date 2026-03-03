@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title Desinstallation Service Windows - AD Web Interface

echo =====================================================================
echo   DESINSTALLATION DU SERVICE WINDOWS
echo   Interface Web Active Directory
echo =====================================================================
echo.

REM =====================================================================
REM Verifier les droits Administrateur
REM =====================================================================
net session >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Droits administrateur requis.
    echo.
    echo   Faites un clic droit sur uninstall_service.bat
    echo   puis selectionnez "Executer en tant qu'administrateur".
    echo.
    pause
    exit /b 1
)

set SERVICE_NAME=ADWebInterface
set NSSM_EXE=%~dp0nssm\nssm.exe

REM =====================================================================
REM Verifier que le service existe
REM =====================================================================
sc query "%SERVICE_NAME%" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Le service "%SERVICE_NAME%" n'est pas installe.
    pause
    exit /b 0
)

echo Service detecte : %SERVICE_NAME%
echo.
set /p CONFIRM="Confirmer la desinstallation du service ? (O/n) : "
if /i "!CONFIRM!"=="n" (
    echo Annule.
    pause
    exit /b 0
)
echo.

REM =====================================================================
REM Arreter le service s'il tourne
REM =====================================================================
sc query "%SERVICE_NAME%" | findstr "RUNNING" >nul 2>&1
if not errorlevel 1 (
    echo Arret du service...
    net stop "%SERVICE_NAME%"
    timeout /t 3 /nobreak >nul
)

REM =====================================================================
REM Supprimer le service via NSSM ou sc
REM =====================================================================
where nssm >nul 2>&1
if not errorlevel 1 ( for /f "tokens=*" %%i in ('where nssm') do set NSSM_EXE=%%i )

if exist "%NSSM_EXE%" (
    echo Suppression du service via NSSM...
    "%NSSM_EXE%" remove "%SERVICE_NAME%" confirm
) else (
    echo Suppression du service via sc.exe...
    sc delete "%SERVICE_NAME%"
)

if errorlevel 1 (
    echo [ERREUR] Echec de la suppression du service.
    echo Essayez manuellement : sc delete %SERVICE_NAME%
    pause
    exit /b 1
)

echo.
echo [OK] Service "%SERVICE_NAME%" supprime.
echo.
echo   Les fichiers de l'application sont conserves.
echo   Les logs sont disponibles dans : %~dp0logs\
echo.
echo   Pour reinstaller : install_service.bat  (en admin)
echo.
pause
exit /b 0

endlocal
