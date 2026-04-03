@echo off
REM ========================================
REM  AUTO-RELOAD - Serveur avec rechargement automatique
REM ========================================

echo.
echo ========================================
echo  AUTO-RELOAD - AD Web Interface
echo ========================================
echo.
echo Le serveur va redémarrer automatiquement
echo à chaque modification de fichier.
echo.
echo Appuie sur Ctrl+C pour arrêter.
echo.
echo ========================================
echo.

python auto_reload.py

pause
