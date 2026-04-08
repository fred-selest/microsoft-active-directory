@echo off
REM ============================================================================
REM MISE À JOUR - AD Web Interface
REM ============================================================================
REM Script de mise à jour automatique vers la dernière version
REM Exécuter en tant qu'administrateur
REM ============================================================================

cd /d "%~dp0"
title Mise à jour AD Web Interface

echo ============================================================================
echo   MISE À JOUR - AD Web Interface
echo ============================================================================
echo.

REM Vérifier les droits administrateur
net session >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Executer en tant qu'administrateur
    pause
    exit /b 1
)
echo [OK] Droits administrateur OK
echo.

REM 1. Arrêter le service
echo Arret du service...
net stop ADWebInterface >nul 2>&1
timeout /t 3 /nobreak >nul
echo [OK] Service arrete
echo.

REM 2. Sauvegarder la configuration
echo Sauvegarde de la configuration...
if not exist "backups" mkdir backups >nul 2>&1
copy ".env" "backups\.env.%DATE:~-4%%DATE:~3,2%%DATE:~0,2%.bak" >nul 2>&1
copy "data\settings.json" "backups\settings.json.%DATE:~-4%%DATE:~3,2%%DATE:~0,2%.bak" >nul 2>&1
echo [OK] Configuration sauvegardee
echo.

REM 3. Nettoyer les fichiers temporaires
echo Nettoyage des fichiers temporaires...
del /q /s *.pyc >nul 2>&1
for /d /r %%d in (__pycache__) do @rd /s /q "%%d" >nul 2>&1
echo [OK] Nettoyage termine
echo.

REM 4. Mettre à jour le code
echo Mise a jour du code depuis GitHub...
git fetch --all >nul 2>&1
git checkout main >nul 2>&1

REM Ignorer les fichiers locaux modifiés
git checkout -- VERSION >nul 2>&1
git checkout -- .env >nul 2>&1
git checkout -- data\settings.json >nul 2>&1

git pull origin main >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Echec de la mise a jour git
    echo Essayez manuellement : git pull origin main
    pause
    exit /b 1
)
echo [OK] Code mis a jour
echo.

REM 5. Vérifier la version
for /f %%v in ('type VERSION') do set VERSION=%%v
echo [OK] Version installee : %VERSION%
echo.

REM 6. Mettre à jour les dépendances si besoin
echo Verification des dependances...
call venv\Scripts\activate.bat
pip install -r requirements.txt --quiet --upgrade
echo [OK] Dependances a jour
echo.

REM 7. Signer les scripts (si nécessaire)
if exist "scripts\sign_scripts.ps1" (
    echo Signature des scripts...
    powershell -ExecutionPolicy Bypass -Command ".\scripts\sign_scripts.ps1" >nul 2>&1
    echo [OK] Scripts signes
    echo.
)

REM 8. Démarrer le service
echo Demarrage du service...
net start ADWebInterface >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Service installe mais non demarre
    echo Demarrage manuel : net start ADWebInterface
) else (
    echo [OK] Service demarre
)
echo.

REM 9. Vérifier le service
timeout /t 5 /nobreak >nul
echo Verification du service...
curl -s http://localhost:5000/api/health >nul 2>&1
if not errorlevel 1 (
    echo [OK] Service operationnel
) else (
    echo [WARNING] Service demarre mais non repond
    echo Attendez quelques secondes et rafraichissez
)
echo.

REM ============================================================================
REM RÉSUMÉ
REM ============================================================================
echo ============================================================================
echo   MISE À JOUR TERMINÉE
echo ============================================================================
echo.
echo Version : %VERSION%
echo.
echo Prochaines étapes :
echo   1. Ouvrez http://localhost:5000
echo   2. Vérifiez que tout fonctionne
echo   3. Consultez CHANGELOG.md pour les nouveautés
echo.
echo En cas de problème :
echo   - Redémarrez : net stop ADWebInterface ^&^& net start ADWebInterface
echo   - Consultez les logs : type logs\server.log
echo.

pause
