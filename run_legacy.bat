@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title Interface Web Active Directory

echo ============================================
echo   Interface Web Active Directory
echo ============================================
echo.

REM ==========================================
REM  1. Serveur deja lance ? → ouvrir le navigateur directement
REM ==========================================
powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:5000' -TimeoutSec 2 -UseBasicParsing | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 (
    echo [OK] Serveur deja en cours d'execution.
    echo Ouverture du navigateur...
    start http://localhost:5000
    exit /b 0
)

REM ==========================================
REM  2. Chercher Python (python / py / python3)
REM ==========================================
set PYTHON_CMD=

python --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=python & goto :python_found )

py --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=py & goto :python_found )

python3 --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=python3 & goto :python_found )

goto :install_python

:python_found
for /f "tokens=2" %%v in ('%PYTHON_CMD% --version 2^>^&1') do set PY_VER=%%v
echo [OK] Python !PY_VER! detecte.
echo.

REM ==========================================
REM  3. Support MD4/NTLM pour Python 3.12+
REM ==========================================
for /f "tokens=1,2 delims=." %%a in ("!PY_VER!") do (
    set PY_MAJOR=%%a
    set PY_MINOR=%%b
)
if !PY_MAJOR! GEQ 3 if !PY_MINOR! GEQ 12 (
    if exist "%~dp0openssl_legacy.cnf" (
        set OPENSSL_CONF=%~dp0openssl_legacy.cnf
        echo [INFO] Support MD4/NTLM active pour Python !PY_VER!.
    )
)

REM ==========================================
REM  4. Environnement virtuel
REM ==========================================
if not exist "venv\Scripts\python.exe" (
    echo Creation de l'environnement Python (premiere fois, patientez)...
    %PYTHON_CMD% -m venv venv
    if errorlevel 1 (
        echo.
        echo [ERREUR] Impossible de creer l'environnement virtuel.
        echo Verifiez que Python est correctement installe ^(avec pip^).
        pause
        exit /b 1
    )
    echo [OK] Environnement virtuel cree.
    echo.
)

REM ==========================================
REM  5. Dependances Python
REM ==========================================
"venv\Scripts\python.exe" -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo Installation des dependances ^(premiere fois, patientez^)...
    "venv\Scripts\pip.exe" install -r requirements.txt -q --disable-pip-version-check
    if errorlevel 1 (
        echo.
        echo [ERREUR] Echec de l'installation des dependances.
        echo Verifiez votre connexion internet et reessayez.
        pause
        exit /b 1
    )
    echo [OK] Dependances installees.
    echo.
)

REM ==========================================
REM  6. Dossiers requis
REM ==========================================
if not exist "logs" mkdir logs >nul 2>&1
if not exist "data" mkdir data >nul 2>&1

REM ==========================================
REM  7. Demarrer le serveur (sans fenetre)
REM ==========================================
echo Demarrage du serveur...

REM pythonw.exe = python sans console (herite OPENSSL_CONF du processus courant)
if exist "venv\Scripts\pythonw.exe" (
    start "" /B "venv\Scripts\pythonw.exe" "%~dp0run.py"
) else (
    REM Fallback : python.exe minimise
    start /min "" "venv\Scripts\python.exe" "%~dp0run.py"
)

REM ==========================================
REM  8. Attendre que le serveur soit pret
REM ==========================================
echo | set /p ="Initialisation"
set /a ATTEMPTS=0

:wait_loop
set /a ATTEMPTS+=1
if !ATTEMPTS! GTR 30 (
    echo.
    echo.
    echo [AVERTISSEMENT] Le demarrage prend plus de 30 secondes.
    echo Consultez logs\server.log pour diagnostiquer le probleme.
    echo.
    goto :open_browser
)
powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:5000' -TimeoutSec 1 -UseBasicParsing | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    echo | set /p ="."
    timeout /t 1 /nobreak >nul
    goto :wait_loop
)

:open_browser
echo.
echo [OK] Pret !
echo.

REM Recuperer l'IP locale pour le partage reseau
for /f "tokens=*" %%i in ('powershell -Command "try { (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^127\.' -and $_.PrefixOrigin -ne 'WellKnown' } | Sort-Object InterfaceMetric | Select-Object -First 1).IPAddress } catch { '' }"') do set LOCAL_IP=%%i

echo  Local    : http://localhost:5000
if defined LOCAL_IP (
    echo  Reseau   : http://!LOCAL_IP!:5000
    echo.
    echo  Les autres utilisateurs du reseau peuvent se connecter
    echo  via l'adresse Reseau ci-dessus ^(aucune installation requise^).
)
echo.

start http://localhost:5000

echo  Pour arreter le serveur  : Gestionnaire des taches ^> python
echo  Pour relancer l'interface : double-cliquez sur run_legacy.bat
echo.
timeout /t 5 /nobreak >nul
exit /b 0


REM ==========================================
REM  INSTALLATION AUTOMATIQUE DE PYTHON
REM ==========================================
:install_python
echo [INFO] Python n'est pas installe ou n'est pas dans le PATH.
echo.
echo Installation automatique de Python 3.12...
echo.

REM Methode 1 : winget (Windows 10 1709+ avec App Installer)
winget --version >nul 2>&1
if not errorlevel 1 (
    echo Methode : Windows Package Manager ^(winget^)...
    winget install Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements
    if not errorlevel 1 (
        REM Recharger le PATH sans redemarrer la fenetre
        for /f "tokens=*" %%i in ('powershell -Command "[System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path','User')"') do set "PATH=%%i"
        python --version >nul 2>&1
        if not errorlevel 1 ( set PYTHON_CMD=python & echo [OK] Python installe. & echo. & goto :python_found )
        py --version >nul 2>&1
        if not errorlevel 1 ( set PYTHON_CMD=py & echo [OK] Python installe. & echo. & goto :python_found )
    )
)

REM Methode 2 : telechargement depuis python.org
echo Methode : Telechargement depuis python.org...
if not exist "%TEMP%\ad-py-install" mkdir "%TEMP%\ad-py-install"

powershell -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe' -OutFile '%TEMP%\ad-py-install\python-setup.exe' -ErrorAction Stop } catch { Write-Host '[ERREUR]' $_.Exception.Message; exit 1 } }"

if not exist "%TEMP%\ad-py-install\python-setup.exe" (
    echo.
    echo [ERREUR] Impossible de telecharger Python automatiquement.
    echo.
    echo Installez Python manuellement depuis : https://www.python.org/downloads/
    echo IMPORTANT : cochez "Add Python to PATH" lors de l'installation,
    echo             puis relancez run_legacy.bat.
    echo.
    start https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Installation de Python 3.12 ^(quelques minutes^)...
"%TEMP%\ad-py-install\python-setup.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_test=0

del "%TEMP%\ad-py-install\python-setup.exe" >nul 2>&1
rmdir /s /q "%TEMP%\ad-py-install" >nul 2>&1

REM Recharger le PATH
for /f "tokens=*" %%i in ('powershell -Command "[System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path','User')"') do set "PATH=%%i"

python --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=python & echo [OK] Python installe. & echo. & goto :python_found )

py --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=py & echo [OK] Python installe. & echo. & goto :python_found )

echo.
echo [OK] Python installe avec succes.
echo Fermez cette fenetre et relancez run_legacy.bat pour demarrer.
pause
exit /b 0

endlocal
