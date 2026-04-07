# 🪟 nssm — Service Windows (WinSW)

**Répertoire :** `nssm/`

---

## 🎯 Rôle

Le répertoire `nssm/` contient les fichiers nécessaires à l'exécution de l'application en tant que **service Windows** via **WinSW** (Windows Service Wrapper).

**Note :** Bien que le répertoire s'appelle `nssm/`, il utilise en réalité **WinSW** (et non NSSM). Le nom `nssm` est historique.

---

## 📁 Structure

```
nssm/
├── ADWebInterface.exe      # WinSW binaire (wrapper XML)
├── ADWebInterface.xml      # Configuration du service
└── logs/                   # Logs du service (généré)
    ├── service.log
    └── wrapper.log
```

---

## ⚙️ Configuration — `ADWebInterface.xml`

### Contenu du Fichier

```xml
<service>
    <id>ADWebInterface</id>
    <name>AD Web Interface</name>
    <description>Interface Web pour Microsoft Active Directory</description>
    <executable>C:\AD-WebInterface\venv\Scripts\python.exe</executable>
    <argument>C:\AD-WebInterface\run.py</argument>
    <logmode>reset</logmode>
    <onfailure action="restart" delay="5000"/>
    <workingdirectory>C:\AD-WebInterface</workingdirectory>
    <env name="OPENSSL_CONF" value="C:\AD-WebInterface\openssl_legacy.cnf"/>
</service>
```

### Éléments de Configuration

| Élément | Rôle | Valeur par défaut |
|---------|------|-------------------|
| `<id>` | Identifiant unique du service | `ADWebInterface` |
| `<name>` | Nom affiché dans services.msc | `AD Web Interface` |
| `<description>` | Description du service | Texte libre |
| `<executable>` | Chemin de l'exécutable | `venv\Scripts\python.exe` |
| `<argument>` | Arguments de l'exécutable | `run.py` |
| `<logmode>` | Mode de journalisation | `reset`, `append`, `roll` |
| `<onfailure>` | Action en cas d'échec | `restart` avec délai |
| `<workingdirectory>` | Répertoire de travail | Racine du projet |
| `<env>` | Variable d'environnement | `OPENSSL_CONF` pour MD4 |

---

## 🔧 Commandes du Service

### Démarrer / Arrêter / Redémarrer

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

### Installer / Désinstaller

```powershell
# Installer le service
.\nssm\ADWebInterface.exe install

# Désinstaller le service
.\nssm\ADWebInterface.exe uninstall
```

---

## 📊 Gestion via services.msc

Le service apparaît dans le gestionnaire de services Windows :

1. Ouvrir `services.msc`
2. Chercher **"AD Web Interface"**
3. Clic droit → Démarrer/Arrêter/Redémarrer
4. Propriétés :
   - **Type de démarrage :** Automatique
   - **Compte :** LocalSystem (par défaut)

---

## 📝 Logs du Service

### Emplacement

```
nssm/logs/service.log
nssm/logs/wrapper.log
```

### Consulter les Logs

```powershell
# En temps réel
Get-Content "C:\AD-WebInterface\nssm\logs\service.log" -Wait -Tail 50

# 50 dernières lignes
Get-Content "C:\AD-WebInterface\nssm\logs\service.log" -Tail 50
```

### Rotation des Logs

WinSW gère automatiquement la rotation :
- **mode `reset`** : Efface à chaque démarrage
- **mode `append`** : Ajoute sans limite
- **mode `roll`** : Archive les anciens logs

---

## 🔐 Sécurité

### Compte de Service

Par défaut, le service s'exécute sous **LocalSystem**.

**Recommandation :** Utiliser un compte dédié avec permissions minimales.

```powershell
# Changer le compte de service (via sc.exe)
sc config ADWebInterface obj= ".\adwebuser" password= "P@ssw0rd"
```

### Permissions Requises

Le compte de service doit avoir :
- **Lecture/écriture** sur `C:\AD-WebInterface\`
- **Lecture** sur l'Active Directory
- **Exécution** de Python

---

## 🐛 Dépannage

### 1. Service Ne Démarre Pas

**Vérifications :**

```powershell
# Voir les logs Windows
Get-EventLog -LogName Application -Source "AD Web Interface" -Newest 20

# Voir les logs WinSW
Get-Content "C:\AD-WebInterface\nssm\logs\service.log" -Tail 50

# Tester manuellement
C:\AD-WebInterface\venv\Scripts\python.exe C:\AD-WebInterface\run.py
```

**Causes possibles :**
- Python non trouvé (chemin incorrect)
- Port 5000 déjà utilisé
- Permissions insuffisantes
- `openssl_legacy.cnf` manquant

---

### 2. Service Redémarre en Boucle

**Cause :** L'application plante au démarrage.

**Solution :**
```powershell
# Arrêter le service
.\nssm\ADWebInterface.exe stop

# Tester manuellement pour voir l'erreur
C:\AD-WebInterface\venv\Scripts\python.exe C:\AD-WebInterface\run.py

# Corriger le problème
# ...

# Redémarrer
.\nssm\ADWebInterface.exe start
```

---

### 3. Erreur OPENSSL_CONF

**Erreur :** `digital envelope routines: EVP_DigestInit_ex: disabled for security`

**Cause :** MD4 désactivé dans Python 3.12+ (requis pour NTLM)

**Solution :** Vérifier que `<env>` est présent dans `ADWebInterface.xml` :

```xml
<env name="OPENSSL_CONF" value="C:\AD-WebInterface\openssl_legacy.cnf"/>
```

---

## 🔄 Mise à Jour du Service

### Modifier la Configuration

1. **Arrêter le service :**
   ```powershell
   .\nssm\ADWebInterface.exe stop
   ```

2. **Éditer `ADWebInterface.xml`**

3. **Redémarrer le service :**
   ```powershell
   .\nssm\ADWebInterface.exe start
   ```

---

### Changer le Port

```xml
<!-- Avant -->
<argument>C:\AD-WebInterface\run.py</argument>

<!-- Après (avec argument) -->
<argument>C:\AD-WebInterface\run.py --port 8080</argument>
```

Ou modifier `config.py` / `.env` :
```
PORT=8080
```

---

## 📦 Installation du Service

### Script d'Installation

```powershell
# scripts/install_standalone.ps1

# 1. Créer le service
.\nssm\ADWebInterface.exe install

# 2. Configurer le démarrage automatique
sc config ADWebInterface start= auto

# 3. Démarrer le service
.\nssm\ADWebInterface.exe start

# 4. Vérifier
.\nssm\ADWebInterface.exe status
```

---

### Script de Désinstallation

```powershell
# uninstall_service.bat

.\nssm\ADWebInterface.exe stop
.\nssm\ADWebInterface.exe uninstall
```

---

## 🧪 Tests

### Vérifier que le Service Tourne

```powershell
# Via PowerShell
Get-Service -Name "ADWebInterface"

# Via sc.exe
sc query ADWebInterface

# Via WinSW
.\nssm\ADWebInterface.exe status
```

---

### Test de Connexion

```powershell
# Tester l'endpoint
Invoke-WebRequest -Uri "http://localhost:5000" -UseBasicParsing

# Vérifier le code de statut
$response = Invoke-WebRequest -Uri "http://localhost:5000"
$response.StatusCode  # Doit être 200 ou 302
```

---

## 📊 Monitoring

### Via PowerShell

```powershell
# Statut du service
Get-Service ADWebInterface | Select-Object Name, Status, StartType

# Processus associé
Get-Process -Name python | Where-Object {$_.Path -like "*AD-WebInterface*"}

# Utilisation mémoire
Get-Process -Name python | Measure-Object WorkingSet -Average | Select-Object Average
```

### Via WMI

```powershell
Get-WmiObject Win32_Service -Filter "Name='ADWebInterface'" | 
    Select-Object Name, State, Status, ExitCode
```

---

## ⚠️ Bonnes Pratiques

### 1. Backup de la Configuration

```powershell
# Backup du XML
Copy-Item "C:\AD-WebInterface\nssm\ADWebInterface.xml" "C:\Backups\ADWebInterface_$(Get-Date -Format 'yyyyMMdd').xml"
```

### 2. Rotation des Logs

Configurer dans `ADWebInterface.xml` :
```xml
<logmode>roll</logmode>
<logpath>C:\AD-WebInterface\nssm\logs</logpath>
```

### 3. Surveillance

Créer une tâche planifiée pour vérifier le service :
```powershell
# check_service.ps1
$service = Get-Service ADWebInterface
if ($service.Status -ne "Running") {
    # Envoyer alerte email
    # Redémarrer le service
}
```

---

## 🔗 Liens Utiles

- **WinSW GitHub :** https://github.com/winsw/winsw
- **Documentation WinSW :** https://github.com/winsw/winsw/blob/v2/docs/xml-config-file.md
- **Services Windows :** https://docs.microsoft.com/en-us/windows/win32/services

---

**Version :** 1.35.0  
**Mainteneur :** Équipe AD Web Interface
