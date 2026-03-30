@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title Serveur AD - Installation et demarrage

echo =====================================================
echo   SERVEUR - Interface Web Active Directory
echo =====================================================
echo.
echo   Ce script installe et demarre le serveur Flask.
echo   Les clients se connectent via run_client.bat.
echo   Laissez cette fenetre ouverte pendant l'utilisation.
echo =====================================================
echo.

REM ======================================================
REM ETAPE 1 : Verifier si le serveur tourne deja
REM  - Interroge http://localhost:5000 avec un timeout court
REM  - Si le serveur repond, inutile de le relancer
REM ======================================================
powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:5000' -TimeoutSec 2 -UseBasicParsing | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 (
    echo [OK] Le serveur est deja en cours d'execution.
    goto :show_addresses
)

REM ======================================================
REM ETAPE 2 : Localiser Python
REM  - Teste les commandes python, py (launcher Windows), python3
REM  - Si aucune n'est disponible, installe Python automatiquement
REM ======================================================
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

REM ======================================================
REM ETAPE 3 : Support MD4/NTLM pour Python 3.12+
REM  - A partir de Python 3.12, OpenSSL supprime le hash MD4
REM    utilise par l'authentification NTLM d'Active Directory.
REM  - openssl_legacy.cnf reactive ce support via la variable
REM    d'environnement OPENSSL_CONF, heritee par le serveur Flask.
REM ======================================================
for /f "tokens=1,2 delims=." %%a in ("!PY_VER!") do (
    set PY_MAJOR=%%a
    set PY_MINOR=%%b
)
if !PY_MAJOR! GEQ 3 if !PY_MINOR! GEQ 12 (
    if exist "%~dp0openssl_legacy.cnf" (
        set OPENSSL_CONF=%~dp0openssl_legacy.cnf
        echo [INFO] Support MD4/NTLM active ^(Python !PY_VER!^).
    )
)

REM ======================================================
REM ETAPE 4 : Environnement virtuel Python (venv)
REM  - Cree un dossier venv\ isole du Python systeme
REM  - Evite les conflits de versions entre projets
REM  - Cree une seule fois, reutilise aux demarrages suivants
REM ======================================================
if not exist "venv\Scripts\python.exe" (
    echo Creation de l'environnement virtuel ^(premiere fois^)...
    %PYTHON_CMD% -m venv venv
    if errorlevel 1 (
        echo.
        echo [ERREUR] Impossible de creer l'environnement virtuel.
        echo Verifiez que Python est installe avec pip.
        pause
        exit /b 1
    )
    echo [OK] Environnement virtuel cree dans venv\
    echo.
)

REM ======================================================
REM ETAPE 5 : Installation des dependances (requirements.txt)
REM  - Installe Flask, ldap3, cryptography, etc. dans venv\
REM  - Verifie si flask est deja present pour eviter
REM    une reinstallation inutile a chaque demarrage
REM ======================================================
"venv\Scripts\python.exe" -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo Installation des dependances ^(premiere fois, patientez^)...
    "venv\Scripts\pip.exe" install -r requirements.txt -q --disable-pip-version-check
    if errorlevel 1 (
        echo.
        echo [ERREUR] Echec de l'installation. Verifiez votre connexion internet.
        pause
        exit /b 1
    )
    echo [OK] Dependances installees.
    echo.
)

REM ======================================================
REM ETAPE 6 : Creation des dossiers de donnees
REM  - logs\ : journaux du serveur (erreurs, acces)
REM  - data\ : fichiers de donnees (favoris, audit, etc.)
REM ======================================================
if not exist "logs" mkdir logs >nul 2>&1
if not exist "data" mkdir data >nul 2>&1

REM ======================================================
REM ETAPE 7 : Demarrage du serveur Flask en arriere-plan
REM  - pythonw.exe = python sans fenetre console visible
REM  - Herite OPENSSL_CONF de ce processus (etape 3)
REM  - start /B lance en arriere-plan dans le meme contexte
REM ======================================================
echo Demarrage du serveur Flask...

if exist "venv\Scripts\pythonw.exe" (
    start "" /B "venv\Scripts\pythonw.exe" "%~dp0run.py"
) else (
    start /min "" "venv\Scripts\python.exe" "%~dp0run.py"
)

REM ======================================================
REM ETAPE 8 : Attendre que le serveur soit pret
REM  - Poll http://localhost:5000 toutes les secondes
REM  - Abandonne apres 60 tentatives (~60 secondes)
REM ======================================================
echo | set /p ="Initialisation du serveur"
set /a ATTEMPTS=0

:wait_loop
set /a ATTEMPTS+=1
if !ATTEMPTS! GTR 60 goto :svc_timeout
powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:5000' -TimeoutSec 1 -UseBasicParsing | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    echo | set /p ="."
    timeout /t 1 /nobreak >nul
    goto :wait_loop
)
echo.
echo [OK] Serveur demarre et pret.
goto :show_addresses

:svc_timeout
echo.
echo.
echo [AVERTISSEMENT] Le serveur met du temps a demarrer.
echo Consultez les logs dans : %~dp0logs\

:show_addresses

REM Recuperer l'IP locale (premiere interface non-loopback)
for /f "tokens=*" %%i in ('powershell -Command "try { (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^127\.' -and $_.PrefixOrigin -ne 'WellKnown' } | Sort-Object InterfaceMetric | Select-Object -First 1).IPAddress } catch { '' }"') do set LOCAL_IP=%%i

echo =====================================================
echo   SERVEUR OPERATIONNEL
echo.
echo   Acces local   : http://localhost:5000
if defined LOCAL_IP (
echo   Acces reseau  : http://!LOCAL_IP!:5000
)
echo.
echo   Communiquez l'adresse reseau aux utilisateurs.
echo   Ils peuvent se connecter via run_client.bat
echo   ou directement dans leur navigateur.
echo.
echo   Pour arreter : fermer cette fenetre
echo              ou stopper python dans le Gestionnaire des taches
echo =====================================================
echo.

REM Sauvegarder l'adresse reseau pour run_client.bat
if defined LOCAL_IP (
    echo http://!LOCAL_IP!:5000>"server_address.txt"
)

pause
exit /b 0


REM ======================================================
REM INSTALLATION AUTOMATIQUE DE PYTHON
REM  Methode 1 : winget (Windows 10 1709+ avec App Installer)
REM  Methode 2 : telechargement silencieux depuis python.org
REM ======================================================
:install_python
echo [INFO] Python introuvable. Installation automatique...
echo.

winget --version >nul 2>&1
if not errorlevel 1 (
    echo Methode : Windows Package Manager ^(winget^)...
    winget install Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements
    if not errorlevel 1 (
        for /f "tokens=*" %%i in ('powershell -Command "[System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path','User')"') do set "PATH=%%i"
        python --version >nul 2>&1
        if not errorlevel 1 ( set PYTHON_CMD=python & echo [OK] Python installe. & echo. & goto :python_found )
        py --version >nul 2>&1
        if not errorlevel 1 ( set PYTHON_CMD=py & echo [OK] Python installe. & echo. & goto :python_found )
    )
)

echo Methode : Telechargement depuis python.org...
if not exist "%TEMP%\ad-py-install" mkdir "%TEMP%\ad-py-install"
powershell -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe' -OutFile '%TEMP%\ad-py-install\python-setup.exe' -ErrorAction Stop } catch { Write-Host '[ERREUR]' $_.Exception.Message; exit 1 } }"

if not exist "%TEMP%\ad-py-install\python-setup.exe" (
    echo.
    echo [ERREUR] Impossible de telecharger Python.
    echo Installez-le manuellement : https://www.python.org/downloads/
    echo IMPORTANT : cochez "Add Python to PATH", puis relancez ce script.
    start https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Installation de Python 3.12 ^(quelques minutes^)...
"%TEMP%\ad-py-install\python-setup.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_test=0
del "%TEMP%\ad-py-install\python-setup.exe" >nul 2>&1
rmdir /s /q "%TEMP%\ad-py-install" >nul 2>&1

for /f "tokens=*" %%i in ('powershell -Command "[System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path','User')"') do set "PATH=%%i"
python --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=python & echo [OK] Python installe. & echo. & goto :python_found )
py --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=py & echo [OK] Python installe. & echo. & goto :python_found )

echo.
echo [OK] Python installe. Fermez cette fenetre et relancez run_server.bat.
pause
exit /b 0

endlocal
