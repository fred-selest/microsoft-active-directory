# Correction MD4 pour Python 3.12+

## Problème

Python 3.12+ a désactivé le hash MD4 par défaut, ce qui bloque l'authentification NTLM vers Active Directory.

## Solutions

### Solution 1: Utiliser run.bat (Automatique sur Windows)

`run.bat` détecte automatiquement Python 3.12+ et active le support MD4/NTLM via `openssl_legacy.cnf`.
Il suffit de lancer `run.bat` normalement, aucune action supplémentaire n'est nécessaire.

### Solution 2: Configuration manuelle

```powershell
$env:OPENSSL_CONF = "C:\chemin\vers\openssl_legacy.cnf"
python run.py
```

### Solution 3: Activer LDAPS sur le serveur AD

1. Installer un certificat sur le contrôleur de domaine
2. Le port 636 sera automatiquement disponible
3. L'application se connectera via LDAPS (plus sécurisé)

### Solution 4: Installer Python 3.11

Python 3.11 supporte encore MD4 nativement.

## Fichiers

- `openssl_legacy.cnf` - Configuration OpenSSL avec support legacy (chargée automatiquement par `run.bat`)
- `run.py` - Script de lancement standard

## Note de sécurité

MD4 est obsolète. La meilleure solution est d'activer LDAPS (port 636) sur votre serveur AD.
