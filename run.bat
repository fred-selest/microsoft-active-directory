@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ======================================
echo   Interface Web Active Directory
echo ======================================
echo.

REM -------------------------------------------------------
REM Chercher Python : python, py (launcher), python3
REM -------------------------------------------------------
set PYTHON_CMD=

python --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=python & goto :python_found )

py --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=py & goto :python_found )

python3 --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=python3 & goto :python_found )

REM Python introuvable : proposition d'installation automatique
goto :install_python

:python_found
echo [OK] Python detecte : %PYTHON_CMD%
%PYTHON_CMD% --version
echo.

REM -------------------------------------------------------
REM OpenSSL legacy pour Python 3.12+ (support NTLM/MD4)
REM -------------------------------------------------------
for /f "tokens=2" %%v in ('%PYTHON_CMD% --version 2^>^&1') do set PY_VER=%%v
for /f "tokens=1,2 delims=." %%a in ("!PY_VER!") do (
    set PY_MAJOR=%%a
    set PY_MINOR=%%b
)
if !PY_MAJOR! GEQ 3 if !PY_MINOR! GEQ 12 (
    if exist "%~dp0openssl_legacy.cnf" (
        set OPENSSL_CONF=%~dp0openssl_legacy.cnf
        echo [INFO] Python !PY_VER! detecte - support MD4/NTLM active.
        echo.
    )
)

REM -------------------------------------------------------
REM Creer le venv s'il est absent
REM -------------------------------------------------------
if not exist "venv\Scripts\activate.bat" (
    echo Creation de l'environnement virtuel...
    %PYTHON_CMD% -m venv venv
    if errorlevel 1 (
        echo [ERREUR] Echec creation venv.
        pause
        exit /b 1
    )
    echo [OK] Environnement virtuel cree.
    echo.
)

REM -------------------------------------------------------
REM Activer le venv et installer les dependances si besoin
REM -------------------------------------------------------
call venv\Scripts\activate.bat

python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo Installation des dependances Python...
    pip install -r requirements.txt --quiet
    if errorlevel 1 (
        echo [ERREUR] Echec installation des dependances.
        pause
        exit /b 1
    )
    echo [OK] Dependances installees.
    echo.
)

REM -------------------------------------------------------
REM Demarrer l'application (cree .env automatiquement si absent)
REM -------------------------------------------------------
python run.py
pause
exit /b 0

REM -------------------------------------------------------
REM Installation automatique de Python
REM -------------------------------------------------------
:install_python
echo [INFO] Python n'est pas detecte sur ce systeme.
echo.
set /p INSTALL="Installer Python 3 automatiquement ? [O/n]: "
if /i "!INSTALL!"=="n" (
    echo.
    echo Telechargez Python sur : https://www.python.org/downloads/
    echo IMPORTANT : cochez "Add Python to PATH" lors de l'installation.
    pause
    exit /b 1
)

echo.
echo Telechargement de Python 3.12 en cours...

if not exist "%TEMP%\ad-python-install" mkdir "%TEMP%\ad-python-install"

powershell -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe' -OutFile '%TEMP%\ad-python-install\python-setup.exe' -ErrorAction Stop; Write-Host '[OK] Telechargement termine.' } catch { Write-Host '[ERREUR] ' $_.Exception.Message; exit 1 } }"

if not exist "%TEMP%\ad-python-install\python-setup.exe" (
    echo.
    echo [ERREUR] Impossible de telecharger Python.
    echo Verifiez votre connexion internet, puis telechargez manuellement :
    echo   https://www.python.org/downloads/
    rmdir /s /q "%TEMP%\ad-python-install" >nul 2>&1
    pause
    exit /b 1
)

echo Installation de Python 3.12 ^(cela peut prendre quelques minutes^)...
"%TEMP%\ad-python-install\python-setup.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_test=0

del "%TEMP%\ad-python-install\python-setup.exe" >nul 2>&1
rmdir /s /q "%TEMP%\ad-python-install" >nul 2>&1

if errorlevel 1 (
    echo [ERREUR] L'installation de Python a echoue.
    echo Essayez de l'installer manuellement : https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Recharger le PATH utilisateur pour cette session
for /f "tokens=*" %%i in ('powershell -Command "[System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path','User')"') do set "PATH=%%i"

python --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=python & echo [OK] Python detecte. & echo. & goto :python_found )

py --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=py & echo [OK] Python detecte. & echo. & goto :python_found )

echo.
echo [OK] Python installe avec succes.
echo Fermez cette fenetre et relancez run.bat.
pause
exit /b 0

endlocal
