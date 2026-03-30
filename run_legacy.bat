@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title AD Web Interface - Mode Legacy (MD4/NTLM)

echo ============================================
echo   AD Web Interface - Mode Legacy
echo   Support MD4/NTLM pour Python 3.12+
echo ============================================
echo.

REM 1. Definir OPENSSL_CONF pour Python 3.12+
if exist "%~dp0openssl_legacy.cnf" (
    set OPENSSL_CONF=%~dp0openssl_legacy.cnf
    echo [INFO] OPENSSL_CONF=%OPENSSL_CONF%
    echo [INFO] Support MD4/NTLM active
    echo.
) else (
    echo [ATTENTION] openssl_legacy.cnf introuvable
    echo [ATTENTION] Creation du fichier...
    (
        echo openssl_conf = openssl_init
        echo.
        echo [openssl_init]
        echo providers = providers_sect
        echo.
        echo [providers_sect]
        echo default = default_sect
        echo legacy = legacy_sect
        echo.
        echo [default_sect]
        echo activate = 1
        echo.
        echo [legacy_sect]
        echo activate = 1
    ) > "%~dp0openssl_legacy.cnf"
    set OPENSSL_CONF=%~dp0openssl_legacy.cnf
    echo [OK] openssl_legacy.cnf cree
    echo.
)

REM 2. Demarrer le serveur avec OPENSSL_CONF
echo Demarrage du serveur avec support MD4/NTLM...
echo.

set FLASK_ENV=production
set FLASK_DEBUG=false

start /min "" "venv\Scripts\python.exe" "%~dp0run.py"

echo Initialisation
set /a ATTEMPTS=0

:wait_loop
set /a ATTEMPTS+=1
if !ATTEMPTS! GTR 60 goto :timeout
powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:5000' -TimeoutSec 1 -UseBasicParsing | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    echo | set /p =.
    timeout /t 1 /nobreak >nul
    goto :wait_loop
)
echo.
echo [OK] Serveur demarre sur http://localhost:5000
echo.
echo Ouverture du navigateur...
start http://localhost:5000
echo.
echo Pour arreter : Gestionnaire des taches ^> python
echo Pour relancer : run_legacy.bat
echo.
exit /b 0

:timeout
echo.
echo [ERREUR] Le serveur n'a pas demarre apres 60 secondes
echo Consultez les logs dans : %~dp0logs\
echo.
pause
exit /b 1
