@echo off
echo Ouvrir la page de connexion avec LDAPS pre-configures...
start http://127.0.0.1:5000/connect?server=192.168.10.252&port=636&ssl=on&base_dn=DC%3DSELEST%2CDC%3Dlocal&domain=SELEST
echo.
echo Serveur LDAPS: 192.168.10.252:636
echo Domaine: SELEST
echo.
pause
