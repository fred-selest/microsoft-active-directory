# 🛠️ Scripts — Outils PowerShell & Batch

**Répertoire :** `scripts/`

---

## 🎯 Rôle

Le répertoire `scripts/` contient des **scripts d'administration** PowerShell (`.ps1`) et batch (`.bat`) pour :

- L'installation et la configuration
- La résolution de problèmes LDAP/NTLM
- La gestion du service Windows
- La signature de certificats
- Les tests de connectivité

---

## 📁 Structure

```
scripts/
├── Installation & Configuration
│   ├── install_standalone.ps1      # Installation complète (venv + service)
│   ├── install_ad.ps1              # Installation sur serveur AD
│   ├── configure_service.ps1       # Configuration du service Windows
│   ├── configure_ldaps.ps1         # Configuration LDAPS
│   └── laps_management.ps1         # Gestion LAPS
│
├── Correctifs LDAP/NTLM
│   ├── fix_md4.ps1                 # Activer MD4 pour NTLM (Python 3.12+)
│   ├── fix_md4_final.ps1           # Correctif MD4 définitif
│   ├── fix_ntlm.ps1                # Activer NTLM
│   ├── fix_ldap_signing.ps1        # LDAP signing requirements
│   ├── fix_channel_binding.ps1     # Channel binding tokens
│   └── fix_smbv1.ps1               # SMBv1 (déprécié)
│
├── Signature de Code
│   ├── sign_winsw_admin.ps1        # Signer WinSW (admin)
│   ├── sign_winsw.ps1              # Signer WinSW (standard)
│   ├── sign_install.bat            # Batch de signature
│   ├── test_sign.ps1               # Test de signature
│   ├── codesign.cer                # Certificat de signature
│   ├── codesign.inf                # INF pour certificat
│   ├── codesign.req                # Requête de certificat
│   └── codesign.rsp                # Réponse de certificat
│
└── Utilitaires
    └── quick_connect_ldaps.bat     # Test rapide LDAPS
```

---

## 📦 Scripts d'Installation

### 1. `install_standalone.ps1` — Installation Complète

**Rôle :** Installe l'application en mode autonome (hors contrôleur de domaine).

**Fonctions :**
- Création de l'environnement virtuel Python
- Installation des dépendances (`requirements.txt`)
- Configuration du service Windows via WinSW
- Configuration des permissions

**Utilisation :**
```powershell
# En tant qu'administrateur
.\scripts\install_standalone.ps1
```

**Étapes :**
1. Vérifie Python 3.10+
2. Crée `venv\`
3. Installe les dépendances
4. Configure WinSW
5. Démarre le service

---

### 2. `install_ad.ps1` — Installation sur Serveur AD

**Rôle :** Installe l'application directement sur un contrôleur de domaine.

**Particularités :**
- Configure les permissions AD spécifiques
- Active les fonctionnalités AD requises
- Configure le firewall Windows

**Utilisation :**
```powershell
# Sur le contrôleur de domaine, en admin
.\scripts\install_ad.ps1
```

---

### 3. `configure_service.ps1` — Configuration du Service

**Rôle :** Configure ou reconfigure le service Windows.

**Paramètres configurables :**
- Hostname et port d'écoute
- Identité du service (LocalSystem, NetworkService, utilisateur)
- Démarrage automatique ou manuel

**Utilisation :**
```powershell
.\scripts\configure_service.ps1 -Host "0.0.0.0" -Port 5000
```

---

### 4. `configure_ldaps.ps1` — Configuration LDAPS

**Rôle :** Configure le chiffrement LDAPS sur le contrôleur de domaine.

**Actions :**
- Import du certificat SSL
- Configuration du registre pour LDAPS
- Redémarrage du service LDAP

**Prérequis :**
- Certificat SSL valide (auto-signé ou CA)
- Droits administrateur sur le DC

---

### 5. `laps_management.ps1` — Gestion LAPS

**Rôle :** Installe et configure LAPS (Local Administrator Password Solution).

**Fonctions :**
- Extension du schéma AD
- Création des GPO LAPS
- Configuration des permissions

---

## 🔧 Scripts de Correctifs

### 1. `fix_md4.ps1` — Activer MD4 pour NTLM

**Problème :** Python 3.12+ désactive MD4 par défaut, ce qui casse l'authentification NTLM.

**Solution :** Réactive MD4 dans la configuration OpenSSL.

**Utilisation :**
```powershell
.\scripts\fix_md4.ps1
```

**Actions :**
1. Copie `openssl_legacy.cnf` vers le venv Python
2. Définit la variable d'environnement `OPENSSL_CONF`
3. Teste la connexion NTLM

---

### 2. `fix_md4_final.ps1` — Correctif MD4 Définitif

**Rôle :** Version améliorée de `fix_md4.ps1` avec :
- Vérifications supplémentaires
- Backup de la configuration
- Rollback possible

---

### 3. `fix_ntlm.ps1` — Activer NTLM

**Rôle :** Configure les stratégies de sécurité pour autoriser NTLM.

**Attention :** NTLM est moins sécurisé que Kerberos. À utiliser avec précaution.

---

### 4. `fix_ldap_signing.ps1` — LDAP Signing

**Problème :** Windows Server 2025+ exige le LDAP signing par défaut.

**Solution :** Configure le serveur pour accepter les connexions non signées (ou signer).

**Options :**
```powershell
# Autoriser les connexions non signées (moins sécurisé)
.\scripts\fix_ldap_signing.ps1 -AllowUnsigned

# OU exiger le signing (plus sécurisé)
.\scripts\fix_ldap_signing.ps1 -RequireSigning
```

---

### 5. `fix_channel_binding.ps1` — Channel Binding Tokens

**Problème :** Les mises à jour de sécurité 2024+ exigent le Channel Binding pour l'authentification.

**Solution :** Configure le registre pour accepter les connexions sans CBT.

---

### 6. `fix_smbv1.ps1` — SMBv1

**⚠️ Déprécié :** SMBv1 est une faille de sécurité majeure (WannaCry).

**Rôle :** Active SMBv1 pour compatibilité legacy (déconseillé).

---

## 🔐 Scripts de Signature de Code

### 1. `sign_winsw_admin.ps1` — Signer WinSW (Admin)

**Rôle :** Signe le binaire WinSW avec un certificat auto-signé pour éviter les alertes Windows.

**Utilisation :**
```powershell
.\scripts\sign_winsw_admin.ps1
```

**Actions :**
1. Crée un certificat auto-signé
2. Signe `nssm/ADWebInterface.exe`
3. Installe le certificat dans le magasin de confiance

---

### 2. `sign_winsw.ps1` — Signer WinSW (Standard)

**Rôle :** Version standard (sans droits admin) de la signature.

---

### 3. `sign_install.bat` — Batch de Signature

**Rôle :** Script batch pour automatiser la signature.

**Utilisation :**
```batch
.\scripts\sign_install.bat
```

---

### 4. Fichiers de Certificat

| Fichier | Rôle |
|---------|------|
| `codesign.cer` | Certificat de signature |
| `codesign.inf` | Fichier INF pour création de certificat |
| `codesign.req` | Requête de certificat (CSR) |
| `codesign.rsp` | Réponse du certificat |

---

## 🧪 Scripts de Test

### 1. `test_sign.ps1` — Test de Signature

**Rôle :** Vérifie qu'un fichier est correctement signé.

**Utilisation :**
```powershell
.\scripts\test_sign.ps1 -File "C:\AD-WebInterface\nssm\ADWebInterface.exe"
```

---

### 2. `quick_connect_ldaps.bat` — Test LDAPS

**Rôle :** Test rapide d'une connexion LDAPS.

**Utilisation :**
```batch
.\scripts\quick_connect_ldaps.bat
```

---

## 🔑 Commandes PowerShell Utiles

### Gestion du Service

```powershell
# Démarrer
.\nssm\ADWebInterface.exe start

# Arrêter
.\nssm\ADWebInterface.exe stop

# Redémarrer
.\nssm\ADWebInterface.exe restart

# Vérifier le statut
.\nssm\ADWebInterface.exe status
```

### Installation du Service

```powershell
# Installer le service
.\nssm\ADWebInterface.exe install

# Désinstaller
.\nssm\ADWebInterface.exe uninstall
```

---

## ⚠️ Sécurité

### Exécution des Scripts PowerShell

Par défaut, PowerShell bloque l'exécution des scripts.

**Débloquer :**
```powershell
# Pour l'utilisateur courant
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Ou pour la machine (admin requis)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

### Signature des Scripts

Pour exécuter des scripts signés uniquement :

```powershell
Set-ExecutionPolicy -ExecutionPolicy AllSigned
```

---

## 🐛 Dépannage

### 1. Script Bloqué

**Erreur :** `cannot be loaded because running scripts is disabled`

**Solution :**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

### 2. Certificat Non Fiable

**Erreur :** `The certificate is not trusted`

**Solution :**
```powershell
# Importer dans le magasin de confiance
Import-Certificate -FilePath "scripts\codesign.cer" -CertStoreLocation Cert:\LocalMachine\Root
```

---

### 3. Service Ne Démarre Pas

**Vérifications :**
```powershell
# Voir les logs
Get-EventLog -LogName Application -Source "AD Web Interface" -Newest 20

# Vérifier le compte de service
Get-Service "ADWebInterface" | Select-Object Name, Status, StartType

# Tester manuellement
C:\AD-WebInterface\venv\Scripts\python.exe C:\AD-WebInterface\run.py
```

---

## 📝 Bonnes Pratiques

### 1. Toujours Tester en Premier

```powershell
# En mode "what if" si disponible
.\script.ps1 -WhatIf

# Ou avec verbose
.\script.ps1 -Verbose
```

### 2. Backup Avant Modification

```powershell
# Backup du registre
reg export HKLM\SYSTEM\CurrentControlSet\Services\LDAP backup.reg

# Backup de la configuration
.\scripts\backup.ps1
```

### 3. Journaliser les Actions

```powershell
Start-Transcript -Path "C:\logs\script.log"
# ... script ...
Stop-Transcript
```

---

## 🔄 Workflow Typique d'Installation

```
1. Télécharger le code
   ↓
2. Exécuter install_standalone.ps1
   ↓
3. Si erreurs LDAP → fix_md4.ps1
   ↓
4. Si erreurs signing → sign_winsw_admin.ps1
   ↓
5. Démarrer le service
   ↓
6. Tester dans le navigateur
```

---

**Version :** 1.35.0  
**Mainteneur :** Équipe AD Web Interface
