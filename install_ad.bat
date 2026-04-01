@echo off
cd /d "%~dp0"
title Installation Active Directory - AD Web Interface

echo =====================================================================
echo   INSTALLATION ACTIVE DIRECTORY
echo   Interface Web Active Directory
echo =====================================================================
echo.

:: Verifier les privileges administrateur
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERREUR] Ce script doit etre execute en tant qu'Administrateur.
    echo Clic droit sur install_ad.bat ^> Executer en tant qu'administrateur
    pause
    exit /b 1
)

:: Lancer le script PowerShell en contournant la politique d'execution
powershell -ExecutionPolicy Bypass -File "%~dp0install_ad.ps1" %*
