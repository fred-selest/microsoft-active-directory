@echo off
REM ============================================================================
REM SIGNATURE DES SCRIPTS - AD Web Interface
REM ============================================================================
REM Script batch pour signer tous les scripts PowerShell
REM Exécuter en tant qu'administrateur
REM ============================================================================

echo.
echo ============================================================================
echo   SIGNATURE AUTHENTICODE - AD Web Interface
echo ============================================================================
echo.

REM Vérifier les droits administrateur
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERREUR] Ce script doit etre execute en tant qu'administrateur
    echo.
    echo Cliquez droit sur ce fichier et selectionnez "Executer en tant qu'administrateur"
    echo.
    pause
    exit /b 1
)

echo [OK] Droits administrateur verifies
echo.

REM Exécuter le script PowerShell
echo [INFO] Lancement de la signature...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Set-Location '%~dp0'; ^
     .\sign_scripts.ps1"

echo.
echo ============================================================================
echo   TERMINE
echo ============================================================================
echo.

pause
