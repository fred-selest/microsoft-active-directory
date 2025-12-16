@echo off
REM Lancer l'application avec support MD4 (Python 3.12+)
set OPENSSL_CONF=%~dp0openssl_legacy.cnf
echo Configuration OpenSSL legacy activee
echo Demarrage du serveur...
venv\Scripts\python.exe run.py
pause
