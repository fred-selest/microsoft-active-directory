# Installation sur le Contrôleur de Domaine Active Directory

## 🎯 Installation Directe sur le DC

Ce guide est spécifiquement conçu pour installer l'Interface Web AD **directement sur votre contrôleur de domaine** Windows Server.

---

## ⚡ Installation Rapide (Recommandé)

### 1️⃣ Télécharger l'application

**Option A - PowerShell (Recommandé) :**

```powershell
# Créer le dossier
New-Item -ItemType Directory -Force -Path "C:\AD-Web"

# Télécharger la dernière version
Invoke-WebRequest -Uri "https://github.com/fred-selest/microsoft-active-directory/archive/refs/heads/main.zip" -OutFile "C:\AD-Web\ad-web.zip"

# Décompresser
Expand-Archive -Path "C:\AD-Web\ad-web.zip" -DestinationPath "C:\AD-Web" -Force

# Nettoyer
Remove-Item "C:\AD-Web\ad-web.zip"
```

**Option B - Navigateur :**

1. Ouvrez Edge/Chrome sur le serveur
2. Allez sur : https://github.com/fred-selest/microsoft-active-directory/releases/latest
3. Téléchargez `AD-WebInterface-1.17.9-Windows.zip`
4. Décompressez dans `C:\AD-Web\`

---

### 2️⃣ Exécuter l'installation automatique

**En tant qu'administrateur :**

```cmd
# Ouvrir CMD en admin
cd C:\AD-Web\microsoft-active-directory-main
clic droit sur install_service.bat → Exécuter en tant qu'administrateur
```

**Le script fait tout automatiquement :**
- ✅ Installe Python 3.12 si absent
- ✅ Crée l'environnement virtuel
- ✅ Installe les dépendances (Flask, ldap3, etc.)
- ✅ Génère le fichier `.env` avec SECRET_KEY
- ✅ Configure le support NTLM/MD4 (Python 3.12+)
- ✅ Installe le service Windows
- ✅ Ouvre le port 5000 dans le pare-feu
- ✅ Démarre le service

---

### 3️⃣ Vérifier l'installation

**Le script affiche :**
```
=============================================================
  SERVICE INSTALLE ET OPERATIONNEL

  Nom du service  : ADWebInterface
  Acces local     : http://localhost:5000
  Acces reseau    : http://192.168.10.253:5000

  Le service démarrera automatiquement au prochain redémarrage.
=============================================================
```

**Testez dans votre navigateur :**
```
http://localhost:5000
```

---

## 🔧 Installation Manuelle (Pour experts)

### Prérequis

```powershell
# Vérifier les droits administrateur
whoami /groups | find "S-1-5-32-544"

# Vérifier PowerShell
$PSVersionTable.PSVersion

# Vérifier le domaine
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
```

### Étape 1 - Installer Python

```powershell
# Via winget (Windows Server 2019+)
winget install Python.Python.3.12 --silent

# Ou télécharger manuellement
# https://www.python.org/downloads/windows/
```

### Étape 2 - Créer l'environnement virtuel

```cmd
cd C:\AD-Web\microsoft-active-directory
python -m venv venv
venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Étape 3 - Configurer l'application

```cmd
# Générer la SECRET_KEY
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env

# Ajouter la configuration
echo FLASK_ENV=production >> .env
echo AD_WEB_HOST=0.0.0.0 >> .env
echo AD_WEB_PORT=5000 >> .env
echo RBAC_ENABLED=true >> .env
echo DEFAULT_ROLE=admin >> .env
```

> **💡 Astuce :** Sur le DC, mettez `DEFAULT_ROLE=admin` pour que les Domain Admins aient tous les droits.

### Étape 4 - Tester le fonctionnement

```cmd
python run.py
```

Attendez 5 secondes, puis ouvrez : `http://localhost:5000`

Si ça fonctionne, arrêtez avec `Ctrl+C`

### Étape 5 - Installer en service Windows

**Avec NSSM (Recommandé) :**

```cmd
# Télécharger NSSM
powershell -Command "Invoke-WebRequest -Uri 'https://nssm.cc/release/nssm-2.24.zip' -OutFile '%TEMP%\nssm.zip'"
powershell -Command "Expand-Archive -Path '%TEMP%\nssm.zip' -DestinationPath '%TEMP%\nssm'"

# Installer le service
%TEMP%\nssm\nssm-2.24\win64\nssm.exe install ADWebInterface "C:\AD-Web\microsoft-active-directory\venv\Scripts\python.exe" "C:\AD-Web\microsoft-active-directory\run.py"

# Configurer le service
%TEMP%\nssm\nssm-2.24\win64\nssm.exe set ADWebInterface AppDirectory "C:\AD-Web\microsoft-active-directory"
%TEMP%\nssm\nssm-2.24\win64\nssm.exe set ADWebInterface DisplayName "Interface Web Active Directory"
%TEMP%\nssm\nssm-2.24\win64\nssm.exe set ADWebInterface Start SERVICE_AUTO_START
%TEMP%\nssm\nssm-2.24\win64\nssm.exe set ADWebInterface AppEnvironmentExtra "OPENSSL_CONF=C:\AD-Web\microsoft-active-directory\openssl_legacy.cnf"

# Démarrer
net start ADWebInterface
```

---

## 🔐 Configuration de Sécurité

### RBAC sur le DC

Dans le fichier `.env`, adaptez la configuration RBAC :

```ini
# Sur le contrôleur de domaine
RBAC_ENABLED=true
DEFAULT_ROLE=admin

# Seuls les Domain Admins ont accès
RBAC_ADMIN_GROUPS=Domain Admins,Administrateurs du domaine
RBAC_OPERATOR_GROUPS=
RBAC_READER_GROUPS=

# Ou ouvrir à d'autres groupes
# RBAC_READER_GROUPS=Domain Users,Authenticated Users
```

### Pare-feu Windows

```cmd
# Vérifier la règle
netsh advfirewall firewall show rule name="AD Web Interface"

# Si absente, la créer
netsh advfirewall firewall add rule name="AD Web Interface" dir=in action=allow protocol=TCP localport=5000

# Restreindre au réseau interne (optionnel)
netsh advfirewall firewall set rule name="AD Web Interface" new remoteip=192.168.0.0/16,10.0.0.0/8
```

### HTTPS (Recommandé en production)

**Option 1 - Reverse proxy IIS :**

```powershell
# Installer le module URL Rewrite
Install-WindowsFeature Web-Url-Auth

# Créer le site IIS avec certificat SSL
# Voir DOCKER.md pour la configuration complète
```

**Option 2 - Certificat auto-signé :**

```powershell
# Créer un certificat
$cert = New-SelfSignedCertificate -DnsName "dc01.entreprise.local" -CertStoreLocation "cert:\LocalMachine\My"

# Exporter
Export-PfxCertificate -Cert $cert -FilePath "C:\cert.pfx" -Password (ConvertTo-SecureString -String "password" -Force -AsPlainText)
```

---

## 🧪 Vérification de l'installation

### 1. Vérifier le service

```cmd
sc query ADWebInterface
net start ADWebInterface
```

### 2. Tester la connexion AD

Depuis un poste client :

```
http://IP_DU_DC:5000
```

La page devrait détecter automatiquement :
- Domaine : `votre-domaine.local`
- Serveur : `IP_du_DC`

### 3. Vérifier les logs

```cmd
# Logs du service
type C:\AD-Web\microsoft-active-directory\logs\service.log

# Logs d'audit
type C:\AD-Web\microsoft-active-directory\logs\audit.log
```

---

## 🔧 Dépannage

### Le service ne démarre pas

```cmd
# Voir les erreurs
type C:\AD-Web\microsoft-active-directory\logs\service_error.log

# Événements Windows
eventvwr.msc
# Journaux Windows → Application → Filtre : ADWebInterface
```

### Erreur MD4 / NTLM

Python 3.12+ ne supporte plus MD4 par défaut.

**Solution :** Le script `install_service.bat` configure automatiquement `openssl_legacy.cnf`.

Vérifiez que la variable d'environnement est définie :

```cmd
set OPENSSL_CONF
# Doit afficher : OPENSSL_CONF=C:\AD-Web\microsoft-active-directory\openssl_legacy.cnf
```

### Port 5000 déjà utilisé

```cmd
# Trouver le processus
netstat -ano | findstr :5000

# Tuer le processus (remplacer PID)
taskkill /PID 1234 /F

# Ou changer le port
echo AD_WEB_PORT=8080 >> .env
net stop ADWebInterface
net start ADWebInterface
```

### La détection automatique ne fonctionne pas

Vérifiez que le serveur est bien un contrôleur de domaine :

```powershell
# Vérifier le rôle DC
Get-Service Netlogon

# Vérifier les enregistrements DNS
Resolve-DnsName -Type SRV -Name "_ldap._tcp.dc._msdcs.$((Get-WmiObject Win32_ComputerSystem).Domain)"
```

---

## 📊 Architecture après installation

```
┌─────────────────────────────────────────┐
│  Contrôleur de Domaine (Windows Server) │
│                                         │
│  ┌──────────────────────────────────┐   │
│  │  Service ADWebInterface          │   │
│  │  (Flask + Waitress)              │   │
│  │  Port: 5000                      │   │
│  └────────────┬─────────────────────┘   │
│               │ LDAP (localhost:389)    │
│  ┌────────────▼─────────────────────┐   │
│  │  Active Directory (NTDS.dit)     │   │
│  │  - Utilisateurs                  │   │
│  │  - Groupes                       │   │
│  │  - Ordinateurs                   │   │
│  └──────────────────────────────────┘   │
└─────────────────┬───────────────────────┘
                  │ HTTP/HTTPS
     ┌────────────┴────────────┐
     │   Postes clients        │
     │   (Navigateurs web)     │
     └─────────────────────────┘
```

---

## 🚀 Mises à jour

### Mise à jour automatique (depuis l'interface)

1. Connectez-vous en admin
2. Cliquez sur la notification de mise à jour
3. L'application télécharge et applique
4. Redémarrage automatique du service

### Mise à jour manuelle

```cmd
# Arrêter le service
net stop ADWebInterface

# Sauvegarder
xcopy C:\AD-Web\microsoft-active-directory\.env C:\AD-Web\backup\.env /Y
xcopy C:\AD-Web\microsoft-active-directory\data C:\AD-Web\backup\data /E /I /Y

# Télécharger la nouvelle version
# Décompresser par-dessus l'ancienne installation

# Redémarrer
net start ADWebInterface
```

---

## 📞 Support

- **Documentation complète :** [README.md](README.md)
- **Guide d'installation :** [GUIDE_INSTALLATION_WINDOWS.md](GUIDE_INSTALLATION_WINDOWS.md)
- **Rapport de sécurité :** [SECURITY.md](SECURITY.md)
- **Issues GitHub :** https://github.com/fred-selest/microsoft-active-directory/issues

---

**Dernière mise à jour :** 2026-03-30  
**Version documentée :** 1.17.9
