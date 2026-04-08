@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title Installation Service Windows - AD Web Interface

echo =====================================================================
echo   INSTALLATION EN TANT QUE SERVICE WINDOWS
echo   Interface Web Active Directory
echo =====================================================================
echo.
echo   Le service demarre automatiquement avec Windows Server,
echo   tourne en arriere-plan meme sans session utilisateur ouverte,
echo   et redemarrage automatiquement en cas de plantage.
echo =====================================================================
echo.

REM =====================================================================
REM ETAPE 1 : Verifier les droits Administrateur
REM  - L'installation d'un service Windows necessite des droits eleves.
REM  - "net session" echoue sans droits admin.
REM =====================================================================
net session >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Droits administrateur requis.
    echo.
    echo   Faites un clic droit sur install_service.bat
    echo   puis selectionnez "Executer en tant qu'administrateur".
    echo.
    pause
    exit /b 1
)
echo [OK] Droits administrateur confirmes.
echo.

REM Variables du service
set SERVICE_NAME=ADWebInterface
set SERVICE_DISPLAY=Interface Web Active Directory
set SERVICE_DESC=Serveur web Flask pour la gestion d'Active Directory (fred-selest)
set APP_DIR=%~dp0

REM =====================================================================
REM ETAPE 2 : Localiser Python
REM  - Memes verifications que run_server.bat
REM  - Propose l'installation automatique si absent
REM =====================================================================
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

REM =====================================================================
REM ETAPE 3 : Support MD4/NTLM pour Python 3.12+
REM  - Necessite OPENSSL_CONF dans l'environnement du service
REM  - NSSM transmet cette variable via AppEnvironmentExtra
REM =====================================================================
set OPENSSL_CONF_PATH=
for /f "tokens=1,2 delims=." %%a in ("!PY_VER!") do (
    set PY_MAJOR=%%a
    set PY_MINOR=%%b
)
if !PY_MAJOR! GEQ 3 if !PY_MINOR! GEQ 12 (
    if exist "%APP_DIR%openssl_legacy.cnf" (
        set OPENSSL_CONF_PATH=%APP_DIR%openssl_legacy.cnf
        echo [INFO] Support MD4/NTLM sera configure pour le service ^(Python !PY_VER!^).
    )
)

REM =====================================================================
REM ETAPE 4 : Environnement virtuel Python
REM  - Le service utilise le venv\ pour ses dependances isolees
REM =====================================================================
if not exist "venv\Scripts\python.exe" (
    echo Creation de l'environnement virtuel...
    %PYTHON_CMD% -m venv venv
    if errorlevel 1 (
        echo [ERREUR] Impossible de creer l'environnement virtuel.
        pause
        exit /b 1
    )
    echo [OK] Environnement virtuel cree.
    echo.
)

REM =====================================================================
REM ETAPE 5 : Installation des dependances
REM =====================================================================
"venv\Scripts\python.exe" -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo Installation des dependances ^(Flask, ldap3, etc.^)...
    "venv\Scripts\pip.exe" install -r requirements.txt -q --disable-pip-version-check
    if errorlevel 1 (
        echo [ERREUR] Echec de l'installation des dependances.
        pause
        exit /b 1
    )
    echo [OK] Dependances installees.
    echo.
)

REM Chemin vers Python dans le venv (utilise par le service)
set PYTHON_EXE=%APP_DIR%venv\Scripts\python.exe
set RUN_PY=%APP_DIR%run.py

REM =====================================================================
REM ETAPE 5b : Generer le fichier .env si absent
REM  - Genere une SECRET_KEY cryptographique unique (32 octets hex)
REM  - Configure le mode production et le mode silencieux (pas de console)
REM  - Ne jamais ecraser un .env existant (contiendrait deja la config)
REM =====================================================================
if not exist "%APP_DIR%.env" (
    echo Generation du fichier .env ^(configuration initiale^)...
    REM Ecrire la cle dans un fichier temporaire pour eviter les problemes
    REM de guillemets imbriques dans FOR /F avec des chemins contenant des espaces
    "%PYTHON_EXE%" -c "import secrets; print(secrets.token_hex(32))" > "%TEMP%\ad_secret.tmp"
    set /p AD_SECRET=<"%TEMP%\ad_secret.tmp"
    del "%TEMP%\ad_secret.tmp" >nul 2>&1
    (
        echo SECRET_KEY=!AD_SECRET!
        echo FLASK_ENV=production
        echo AD_SILENT=true
    ) > "%APP_DIR%.env"
    echo [OK] Fichier .env cree avec une SECRET_KEY securisee.
    echo.
) else (
    echo [OK] Fichier .env existant conserve.
    echo.
)

REM =====================================================================
REM ETAPE 6 : Obtenir un gestionnaire de service Windows
REM  - Priorite 1 : NSSM (Non-Sucking Service Manager)
REM  - Priorite 2 : WinSW (Windows Service Wrapper, github.com/winsw/winsw)
REM  - NSSM est inclus dans le package Windows ; telechargement auto si absent
REM =====================================================================
set NSSM_EXE=%APP_DIR%nssm\nssm.exe
set WINSW_EXE=%APP_DIR%nssm\WinSW.exe
set SERVICE_MGR=nssm

if not exist "%APP_DIR%nssm" mkdir "%APP_DIR%nssm"

REM NSSM deja dans le PATH ?
where nssm >nul 2>&1
if not errorlevel 1 (
    for /f "tokens=*" %%i in ('where nssm') do set NSSM_EXE=%%i
    echo [OK] NSSM detecte dans le PATH.
    goto :svc_mgr_ready
)

REM NSSM dans le dossier de l'application (inclus dans le package Windows) ?
if exist "%NSSM_EXE%" (
    echo [OK] NSSM detecte dans nssm\
    goto :svc_mgr_ready
)

REM Methode 1 : winget (Windows 10 1709+ et Windows Server 2019+)
echo Tentative d'installation de NSSM via winget...
winget --version >nul 2>&1
if not errorlevel 1 (
    winget install NSSM.NSSM --silent --accept-source-agreements --accept-package-agreements >nul 2>&1
    REM Rafraichir le PATH depuis le registre (winget ne met pas a jour le PATH courant)
    for /f "delims=" %%i in ('powershell -NoProfile -Command "[Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')"') do set "PATH=%%i"
    where nssm >nul 2>&1
    if not errorlevel 1 (
        for /f "tokens=*" %%i in ('where nssm') do set NSSM_EXE=%%i
        echo [OK] NSSM installe via winget.
        echo.
        goto :svc_mgr_ready
    )
    REM Recherche recursive dans les emplacements d'installation courants de winget
    set NSSM_FOUND=
    for /f "delims=" %%f in ('dir /s /b "%PROGRAMFILES%\nssm.exe" 2^>nul') do if not defined NSSM_FOUND set NSSM_FOUND=%%f
    if not defined NSSM_FOUND for /f "delims=" %%f in ('dir /s /b "%PROGRAMFILES(X86)%\nssm.exe" 2^>nul') do if not defined NSSM_FOUND set NSSM_FOUND=%%f
    if not defined NSSM_FOUND for /f "delims=" %%f in ('dir /s /b "%LOCALAPPDATA%\Microsoft\WinGet\nssm.exe" 2^>nul') do if not defined NSSM_FOUND set NSSM_FOUND=%%f
    if defined NSSM_FOUND (
        copy "!NSSM_FOUND!" "!NSSM_EXE!" >nul 2>&1
        if exist "!NSSM_EXE!" (
            echo [OK] NSSM installe via winget.
            echo.
            goto :svc_mgr_ready
        )
    )
    echo [INFO] winget n'a pas pu installer NSSM, passage au telechargement direct...
)

REM Methode 2 : telechargement depuis nssm.cc (source officielle)
echo Telechargement de NSSM depuis nssm.cc...
powershell -NoProfile -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri 'https://nssm.cc/release/nssm-2.24.zip' -OutFile '%TEMP%\nssm.zip' -TimeoutSec 30 -ErrorAction Stop; Write-Host '[OK] Telechargement termine.' } catch { Write-Host '[INFO] nssm.cc inaccessible.' } }"

REM Methode 3 : miroir GitHub nssm
if not exist "%TEMP%\nssm.zip" (
    echo Telechargement depuis miroir GitHub nssm...
    powershell -NoProfile -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri 'https://github.com/nicholasgondra/nssm/releases/download/nssm-2.24/nssm-2.24.zip' -OutFile '%TEMP%\nssm.zip' -TimeoutSec 30 -ErrorAction Stop; Write-Host '[OK] Telechargement termine.' } catch { Write-Host '[INFO] Miroir inaccessible.' } }"
)

REM Extraction de l'archive NSSM si telechargee
if exist "%TEMP%\nssm.zip" (
    echo Extraction de NSSM...
    powershell -NoProfile -Command "$src='$env:TEMP\nssm.zip'; $dst='$env:TEMP\nssm-extract'; if(Test-Path $src){Expand-Archive -Path $src -DestinationPath $dst -Force}; exit 0"
    del "%TEMP%\nssm.zip" >nul 2>&1
    REM Recherche recursive de nssm.exe (win64 prioritaire) dans l'arborescence extraite
    set NSSM_FOUND=
    for /f "delims=" %%f in ('dir /s /b "%TEMP%\nssm-extract\nssm.exe" 2^>nul ^| findstr /i "win64"') do if not defined NSSM_FOUND set NSSM_FOUND=%%f
    if not defined NSSM_FOUND for /f "delims=" %%f in ('dir /s /b "%TEMP%\nssm-extract\nssm.exe" 2^>nul') do if not defined NSSM_FOUND set NSSM_FOUND=%%f
    rmdir /s /q "%TEMP%\nssm-extract" >nul 2>&1
    if defined NSSM_FOUND (
        copy "!NSSM_FOUND!" "!NSSM_EXE!" >nul 2>&1
        if exist "!NSSM_EXE!" (
            echo [OK] NSSM pret.
            echo.
            goto :svc_mgr_ready
        )
    )
    echo [INFO] nssm.exe absent de l'archive, passage a WinSW...
)

REM Methode 4 : WinSW (Windows Service Wrapper) depuis github.com/winsw/winsw
REM  Alternative a NSSM si toutes les sources NSSM sont inaccessibles.
REM  WinSW est heberge sur GitHub officiel Microsoft/winsw, tres fiable.
echo Telechargement de WinSW depuis GitHub (alternative a NSSM)...
powershell -NoProfile -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe' -OutFile '%APP_DIR%nssm\WinSW.exe' -TimeoutSec 60 -ErrorAction Stop; Write-Host '[OK] WinSW telecharge.' } catch { Write-Host '[INFO] WinSW inaccessible :' $_.Exception.Message } }"

if exist "!WINSW_EXE!" (
    set SERVICE_MGR=winsw
    echo [OK] WinSW pret ^(remplace NSSM^).
    echo.
    goto :svc_mgr_ready
)

echo.
echo [ERREUR] Impossible d'obtenir un gestionnaire de service ^(NSSM ou WinSW^).
echo.
echo   Solutions :
echo   1. Telechargez NSSM manuellement : https://nssm.cc/download
echo      Placez nssm.exe dans : %APP_DIR%nssm\nssm.exe
echo   2. Ou installez-le via winget :
echo      winget install NSSM.NSSM
echo.
echo   Puis relancez ce script.
echo.
pause
exit /b 1

:svc_mgr_ready

REM =====================================================================
REM ETAPE 7 : Gestion du service existant
REM  - Si le service existe deja, proposer la reinstallation
REM =====================================================================
sc query "%SERVICE_NAME%" >nul 2>&1
if not errorlevel 1 (
    echo [INFO] Le service "%SERVICE_NAME%" existe deja.
    echo.
    set /p REINSTALL="Reinstaller le service ? (O/n) : "
    if /i "!REINSTALL!"=="n" (
        echo Annule.
        pause
        exit /b 0
    )
    echo Arret et suppression du service existant...
    net stop "%SERVICE_NAME%" >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete "%SERVICE_NAME%" >nul 2>&1
    timeout /t 1 /nobreak >nul
    echo.
)

REM =====================================================================
REM ETAPE 8 : Installation du service
REM  - Chemin A : NSSM (commandes nssm install + nssm set)
REM  - Chemin B : WinSW (fichier XML de configuration)
REM  - Les deux gerent : demarrage auto, logs, redemarrage sur crash
REM =====================================================================
echo Installation du service Windows "%SERVICE_NAME%"...
echo.

if not exist "%APP_DIR%logs" mkdir "%APP_DIR%logs" >nul 2>&1

if "!SERVICE_MGR!"=="winsw" goto :install_with_winsw

REM === Chemin A : Installation avec NSSM ===
"%NSSM_EXE%" install "%SERVICE_NAME%" "%PYTHON_EXE%" "%RUN_PY%"
if errorlevel 1 (
    echo [ERREUR] Echec de l'installation du service avec NSSM.
    pause
    exit /b 1
)
"%NSSM_EXE%" set "%SERVICE_NAME%" AppDirectory "%APP_DIR%"
"%NSSM_EXE%" set "%SERVICE_NAME%" DisplayName "%SERVICE_DISPLAY%"
"%NSSM_EXE%" set "%SERVICE_NAME%" Description "%SERVICE_DESC%"
"%NSSM_EXE%" set "%SERVICE_NAME%" Start SERVICE_AUTO_START
"%NSSM_EXE%" set "%SERVICE_NAME%" AppStdout "%APP_DIR%logs\service.log"
"%NSSM_EXE%" set "%SERVICE_NAME%" AppStderr "%APP_DIR%logs\service_error.log"
"%NSSM_EXE%" set "%SERVICE_NAME%" AppRotateFiles 1
"%NSSM_EXE%" set "%SERVICE_NAME%" AppRotateBytes 10485760
"%NSSM_EXE%" set "%SERVICE_NAME%" AppExit Default Restart
"%NSSM_EXE%" set "%SERVICE_NAME%" AppRestartDelay 5000
if defined OPENSSL_CONF_PATH (
    "%NSSM_EXE%" set "%SERVICE_NAME%" AppEnvironmentExtra "OPENSSL_CONF=%OPENSSL_CONF_PATH%"
    echo [INFO] OPENSSL_CONF configure ^(support MD4/NTLM^).
)
set SVC_LOG_OUT=%APP_DIR%logs\service.log
set SVC_LOG_ERR=%APP_DIR%logs\service_error.log

REM === Suite de l'installation ===

REM === Chemin B : Installation avec WinSW ===
:install_with_winsw
REM WinSW requiert que l'exe et le XML partagent le meme nom de base
copy "!WINSW_EXE!" "%APP_DIR%nssm\%SERVICE_NAME%.exe" >nul 2>&1
REM Generation du fichier de configuration XML
(
    echo ^<?xml version="1.0" encoding="UTF-8"?^>
    echo ^<service^>
    echo   ^<id^>%SERVICE_NAME%^</id^>
    echo   ^<name^>%SERVICE_DISPLAY%^</name^>
    echo   ^<description^>%SERVICE_DESC%^</description^>
    echo   ^<executable^>!PYTHON_EXE!^</executable^>
    echo   ^<arguments^>"!RUN_PY!"^</arguments^>
    echo   ^<workingdirectory^>%APP_DIR%^</workingdirectory^>
    echo   ^<startmode^>Automatic^</startmode^>
    echo   ^<logpath^>%APP_DIR%logs^</logpath^>
    echo   ^<log mode="roll-by-size"^>^<sizeThreshold^>10240^</sizeThreshold^>^<keepFiles^>8^</keepFiles^>^</log^>
    echo   ^<onfailure action="restart" delay="5000 ms"/^>
) > "%APP_DIR%nssm\%SERVICE_NAME%.xml"
if defined OPENSSL_CONF_PATH (
    powershell -NoProfile -Command "$f='%APP_DIR%nssm\%SERVICE_NAME%.xml'; (Get-Content $f -Raw) -replace '</service>', ('  <env name=""OPENSSL_CONF"" value=""!OPENSSL_CONF_PATH!""/>'+[char]13+[char]10+'</service>') | Set-Content $f"
    echo [INFO] OPENSSL_CONF configure ^(support MD4/NTLM^).
)
"%APP_DIR%nssm\%SERVICE_NAME%.exe" install
if errorlevel 1 (
    echo [ERREUR] Echec de l'installation du service avec WinSW.
    pause
    exit /b 1
)
set SVC_LOG_OUT=%APP_DIR%logs\%SERVICE_NAME%.out.log
set SVC_LOG_ERR=%APP_DIR%logs\%SERVICE_NAME%.err.log

REM === Suite de l'installation ===

REM =====================================================================
REM ETAPE 8b : Ouverture du port dans le pare-feu Windows
REM  - Sans cette regle, les postes clients du reseau ne peuvent pas
REM    acceder a l'interface (connexion refusee meme si le service tourne)
REM  - Supprime l'ancienne regle si elle existe, puis la recrée
REM  - N'affecte que le trafic entrant sur le port de l'application
REM =====================================================================

REM Lire le port depuis le .env si defini, sinon utiliser 5000 par defaut
set APP_PORT=5000
for /f "tokens=1,2 delims==" %%a in ('type "%APP_DIR%.env" 2^>nul ^| findstr /i "AD_WEB_PORT"') do (
    if /i "%%a"=="AD_WEB_PORT" set APP_PORT=%%b
)

echo Configuration du pare-feu Windows ^(port !APP_PORT!^)...
netsh advfirewall firewall delete rule name="AD Web Interface" >nul 2>&1
netsh advfirewall firewall add rule name="AD Web Interface" dir=in action=allow protocol=TCP localport=!APP_PORT! >nul 2>&1
if errorlevel 1 (
    echo [AVERTISSEMENT] Impossible d'ouvrir le port !APP_PORT! dans le pare-feu.
    echo   Ouvrez-le manuellement si les clients ne peuvent pas se connecter :
    echo   netsh advfirewall firewall add rule name="AD Web Interface" dir=in action=allow protocol=TCP localport=!APP_PORT!
) else (
    echo [OK] Pare-feu : port !APP_PORT! ouvert pour les connexions entrantes.
)
echo.

REM =====================================================================
REM ETAPE 9 : Demarrage du service
REM =====================================================================
echo.
echo Demarrage du service...
net start "%SERVICE_NAME%"
if errorlevel 1 (
    echo.
    echo [ERREUR] Impossible de demarrer le service.
    echo.
    echo   Consultez l'Observateur d'evenements Windows :
    echo   Evenements Windows ^> Application ^> filtre : ADWebInterface
    echo   Ou : !SVC_LOG_ERR!
    echo.
    pause
    exit /b 1
)

REM Attendre que Flask soit pret
echo | set /p ="Initialisation Flask"
set /a ATTEMPTS=0
:svc_wait
set /a ATTEMPTS+=1
if !ATTEMPTS! GTR 40 ( echo. & goto :svc_done )
powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:5000' -TimeoutSec 1 -UseBasicParsing | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 ( echo | set /p ="." & timeout /t 1 /nobreak >nul & goto :svc_wait )

:svc_done
echo.
echo.

REM Recuperer l'IP reseau
for /f "tokens=*" %%i in ('powershell -Command "try { (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^127\.' -and $_.PrefixOrigin -ne 'WellKnown' } | Sort-Object InterfaceMetric | Select-Object -First 1).IPAddress } catch { '' }"') do set LOCAL_IP=%%i

echo =====================================================================
echo   SERVICE INSTALLE ET OPERATIONNEL
echo.
echo   Nom du service  : %SERVICE_NAME%
echo   Acces local     : http://localhost:5000
if defined LOCAL_IP (
echo   Acces reseau    : http://!LOCAL_IP!:5000
)
echo.
echo   Le service demarrera automatiquement au prochain redemarrage.
echo   Les clients se connectent via run_client.bat
echo.
echo   Gestion du service :
echo     Demarrer   : net start %SERVICE_NAME%
echo     Arreter    : net stop %SERVICE_NAME%
echo     Statut     : sc query %SERVICE_NAME%
echo     Desinstall : uninstall_service.bat  ^(en admin^)
echo     Interface  : services.msc
echo.
echo   Logs : !SVC_LOG_OUT!
echo          !SVC_LOG_ERR!
echo =====================================================================
echo.
pause
exit /b 0


REM =====================================================================
REM INSTALLATION AUTOMATIQUE DE PYTHON
REM =====================================================================
:install_python
echo [INFO] Python introuvable. Installation automatique...
echo.

winget --version >nul 2>&1
if not errorlevel 1 (
    echo Methode : winget...
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
    echo [ERREUR] Impossible de telecharger Python.
    echo Installez-le manuellement : https://www.python.org/downloads/
    pause
    exit /b 1
)
echo Installation de Python 3.12...
"%TEMP%\ad-py-install\python-setup.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1 Include_test=0
del "%TEMP%\ad-py-install\python-setup.exe" >nul 2>&1
rmdir /s /q "%TEMP%\ad-py-install" >nul 2>&1
for /f "tokens=*" %%i in ('powershell -Command "[System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path','User')"') do set "PATH=%%i"
python --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=python & echo [OK] Python installe. & echo. & goto :python_found )
py --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=py & echo [OK] Python installe. & echo. & goto :python_found )
echo [ERREUR] Python installe mais non detecte. Relancez le script.
pause
exit /b 1

endlocal
