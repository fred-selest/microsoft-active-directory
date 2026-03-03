@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title Client AD - Connexion au serveur

echo =====================================================
echo   CLIENT - Interface Web Active Directory
echo =====================================================
echo.
echo   Ce script ouvre l'interface dans votre navigateur.
echo   Le serveur doit etre demarre au prealable
echo   via run_server.bat sur la machine serveur.
echo =====================================================
echo.

REM ======================================================
REM ETAPE 1 : Lire l'adresse du serveur
REM  - Cherche d'abord server_address.txt (ecrit par run_server.bat)
REM  - Sinon propose localhost:5000 par defaut
REM  - Permet de pointer vers un serveur distant sur le reseau
REM ======================================================
set SERVER_URL=

if exist "server_address.txt" (
    set /p SERVER_URL=<server_address.txt
    echo [INFO] Adresse lue depuis server_address.txt : !SERVER_URL!
    echo        ^(Supprimez ce fichier pour changer d'adresse^)
    echo.
)

if not defined SERVER_URL (
    echo Aucune adresse de serveur configuree.
    echo.
    echo  - Pour un serveur LOCAL  : http://localhost:5000
    echo  - Pour un serveur RESEAU : http://192.168.x.x:5000
    echo.
    set /p SERVER_URL="Adresse du serveur [http://localhost:5000] : "
    if not defined SERVER_URL set SERVER_URL=http://localhost:5000
    echo.
    echo Sauvegarde de l'adresse dans server_address.txt...
    echo !SERVER_URL!>"server_address.txt"
    echo ^(Pour changer : modifiez ou supprimez server_address.txt^)
    echo.
)

REM ======================================================
REM ETAPE 2 : Verifier que le serveur est accessible
REM  - Envoie une requete HTTP avec un timeout de 5 secondes
REM  - Informe l'utilisateur si le serveur est inaccessible
REM    au lieu d'ouvrir un navigateur sur une page d'erreur
REM ======================================================
echo Verification de la connexion : !SERVER_URL!...
powershell -Command "try { Invoke-WebRequest -Uri '!SERVER_URL!' -TimeoutSec 5 -UseBasicParsing | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1

if errorlevel 1 (
    echo.
    echo [ERREUR] Le serveur ne repond pas : !SERVER_URL!
    echo.
    echo Solutions possibles :
    echo   1. Demarrer le serveur avec run_server.bat sur la machine serveur
    echo   2. Verifier l'adresse IP ^(modifiez server_address.txt^)
    echo   3. Verifier que le port 5000 est ouvert dans le pare-feu Windows
    echo      ^( Pare-feu Windows > Regles de trafic entrant > Port 5000 ^)
    echo.
    set /p CHANGE="Changer l'adresse du serveur ? [O/n] : "
    if /i not "!CHANGE!"=="n" (
        echo.
        set /p SERVER_URL="Nouvelle adresse : "
        if defined SERVER_URL (
            echo !SERVER_URL!>"server_address.txt"
            echo [OK] Adresse mise a jour.
            echo Relancez run_client.bat pour vous connecter.
        )
    )
    echo.
    pause
    exit /b 1
)

REM ======================================================
REM ETAPE 3 : Ouvrir le navigateur par defaut
REM  - La commande "start URL" utilise le navigateur par defaut
REM  - Aucune installation requise cote client
REM ======================================================
echo [OK] Serveur accessible.
echo.
echo Ouverture de l'interface dans le navigateur...
start !SERVER_URL!

echo.
echo Interface ouverte. Cette fenetre peut etre fermee.
echo.
timeout /t 3 /nobreak >nul
exit /b 0

endlocal
