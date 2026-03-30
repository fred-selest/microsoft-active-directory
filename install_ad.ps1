# ============================================================================
# INSTALLATION AUTOMATIQUE - AD WEB INTERFACE
# Pour contrôleur de domaine Windows Server
# ============================================================================
# Ce script installe automatiquement l'interface web AD sur le DC
# Exécuter en tant qu'administrateur
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Port d'écoute de l'application")]
    [int]$Port = 5000,
    
    [Parameter(HelpMessage="Installer Python si absent")]
    [switch]$InstallPython = $true,
    
    [Parameter(HelpMessage="Dossier d'installation")]
    [string]$InstallDir = "C:\AD-Web\microsoft-active-directory"
)

# ============================================================================
# FONCTIONS
# ============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-DomainController {
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        Write-Log "Contrôleur de domaine détecté : $($domain.Name)" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Ce serveur n'est PAS un contrôleur de domaine" "WARNING"
        return $false
    }
}

function Install-Python {
    Write-Log "Vérification de Python..."
    
    $pythonCmd = $null
    try {
        $pythonCmd = Get-Command python -ErrorAction Stop
        $version = & python --version
        Write-Log "Python déjà installé : $version" "SUCCESS"
        return "python"
    }
    catch {
        try {
            $pythonCmd = Get-Command py -ErrorAction Stop
            $version = & py --version
            Write-Log "Python déjà installé (py) : $version" "SUCCESS"
            return "py"
        }
        catch {
            if ($InstallPython) {
                Write-Log "Installation de Python 3.12..."
                
                # Télécharger avec winget si disponible
                if (Get-Command winget -ErrorAction SilentlyContinue) {
                    Write-Log "Installation via winget..."
                    winget install Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements
                    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
                    return "python"
                }
                
                # Télécharger manuellement
                $pythonUrl = "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"
                $pythonInstaller = "$env:TEMP\python-setup.exe"
                
                Write-Log "Téléchargement de Python..."
                Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing
                
                Write-Log "Installation de Python..."
                Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_pip=1", "Include_test=0" -Wait
                
                Remove-Item $pythonInstaller -Force
                $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
                
                Write-Log "Python installé avec succès" "SUCCESS"
                return "python"
            }
            else {
                throw "Python non installé et -InstallPython non spécifié"
            }
        }
    }
}

function Install-NSSM {
    Write-Log "Vérification de NSSM..."
    
    $nssmPath = "$InstallDir\nssm\nssm.exe"
    
    if (Test-Path $nssmPath) {
        Write-Log "NSSM déjà présent" "SUCCESS"
        return $nssmPath
    }
    
    # Créer le dossier
    New-Item -ItemType Directory -Force -Path "$InstallDir\nssm" | Out-Null
    
    # Télécharger NSSM
    Write-Log "Téléchargement de NSSM..."
    $nssmZip = "$env:TEMP\nssm.zip"
    
    try {
        Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $nssmZip -UseBasicParsing
        Expand-Archive -Path $nssmZip -DestinationPath "$env:TEMP\nssm-extract" -Force
        
        # Trouver nssm.exe
        $nssmExe = Get-ChildItem -Path "$env:TEMP\nssm-extract" -Recurse -Filter "nssm.exe" | Select-Object -First 1
        if ($nssmExe) {
            Copy-Item $nssmExe.FullName -Destination $nssmPath -Force
            Write-Log "NSSM installé : $nssmPath" "SUCCESS"
            return $nssmPath
        }
    }
    catch {
        Write-Log "Échec téléchargement NSSM" "ERROR"
    }
    finally {
        if (Test-Path $nssmZip) { Remove-Item $nssmZip -Force }
        if (Test-Path "$env:TEMP\nssm-extract") { Remove-Item "$env:TEMP\nssm-extract" -Recurse -Force }
    }
    
    return $null
}

function New-EnvFile {
    Write-Log "Génération du fichier .env..."
    
    $secretKey = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | ForEach-Object {[char]$_})
    
    $envContent = @"
# Configuration générée automatiquement
SECRET_KEY=$secretKey
FLASK_DEBUG=false
FLASK_ENV=production
AD_WEB_HOST=0.0.0.0
AD_WEB_PORT=$Port
SESSION_COOKIE_SECURE=false
FORCE_HTTPS=false
RBAC_ENABLED=true
DEFAULT_ROLE=admin
RBAC_ADMIN_GROUPS=Domain Admins,Administrateurs du domaine
SESSION_TIMEOUT=30
ITEMS_PER_PAGE=25
"@
    
    $envContent | Out-File -FilePath "$InstallDir\.env" -Encoding UTF8
    Write-Log "Fichier .env créé" "SUCCESS"
}

function Install-Service {
    param([string]$PythonCmd, [string]$NssmPath)
    
    $serviceName = "ADWebInterface"
    $serviceDisplay = "Interface Web Active Directory"
    
    # Vérifier si le service existe déjà
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Log "Le service existe déjà. Suppression..." "WARNING"
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & $NssmPath remove $serviceName confirm
        Start-Sleep -Seconds 2
    }
    
    # Installer le service
    Write-Log "Installation du service Windows..."
    
    $pythonExe = "$InstallDir\venv\Scripts\python.exe"
    $runPy = "$InstallDir\run.py"
    
    & $NssmPath install $serviceName $pythonExe $runPy
    & $NssmPath set $serviceName AppDirectory $InstallDir
    & $NssmPath set $serviceName DisplayName $serviceDisplay
    & $NssmPath set $serviceName Description "Interface Web pour Microsoft Active Directory"
    & $NssmPath set $serviceName Start SERVICE_AUTO_START
    & $NssmPath set $serviceName AppStdout "$InstallDir\logs\service.log"
    & $NssmPath set $serviceName AppStderr "$InstallDir\logs\service_error.log"
    & $NssmPath set $serviceName AppRotateFiles 1
    & $NssmPath set $serviceName AppRotateBytes 10485760
    & $NssmPath set $serviceName AppExit Default Restart
    & $NssmPath set $serviceName AppRestartDelay 5000
    
    # Configurer OPENSSL_CONF pour Python 3.12+
    $opensslConf = "$InstallDir\openssl_legacy.cnf"
    if (Test-Path $opensslConf) {
        & $NssmPath set $serviceName AppEnvironmentExtra "OPENSSL_CONF=$opensslConf"
        Write-Log "Configuration MD4/NTLM activée" "SUCCESS"
    }
    
    # Ouvrir le port dans le pare-feu
    Write-Log "Ouverture du port $Port dans le pare-feu..."
    netsh advfirewall firewall delete rule name="AD Web Interface" | Out-Null
    netsh advfirewall firewall add rule name="AD Web Interface" dir=in action=allow protocol=TCP localport=$Port | Out-Null
    Write-Log "Pare-feu configuré" "SUCCESS"
    
    # Démarrer le service
    Write-Log "Démarrage du service..."
    Start-Service -Name $serviceName
    Start-Sleep -Seconds 5
    
    $serviceStatus = Get-Service -Name $serviceName
    if ($serviceStatus.Status -eq "Running") {
        Write-Log "Service démarré avec succès" "SUCCESS"
        return $true
    }
    else {
        Write-Log "Échec démarrage du service" "ERROR"
        return $false
    }
}

function Get-LocalIP {
    try {
        $ip = Get-NetIPAddress -AddressFamily IPv4 | 
              Where-Object { $_.IPAddress -notmatch '^127\.' -and $_.PrefixOrigin -ne 'WellKnown' } |
              Sort-Object InterfaceMetric |
              Select-Object -First 1 -ExpandProperty IPAddress
        return $ip
    }
    catch {
        return "localhost"
    }
}

# ============================================================================
# SCRIPT PRINCIPAL
# ============================================================================

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  INSTALLATION AUTOMATIQUE - AD WEB INTERFACE" -ForegroundColor Cyan
Write-Host "  Pour contrôleur de domaine Windows Server" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier les droits administrateur
if (-not (Test-Administrator)) {
    Write-Log "Droits administrateur requis !" "ERROR"
    Write-Log "Faites un clic droit → Exécuter en tant qu'administrateur" "ERROR"
    pause
    exit 1
}
Write-Log "Droits administrateur confirmés" "SUCCESS"

# Vérifier si c'est un DC
Test-DomainController

# Créer le dossier d'installation
Write-Log "Création du dossier d'installation : $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Set-Location $InstallDir

# Installer Python
$pythonCmd = Install-Python
if (-not $pythonCmd) {
    Write-Log "Impossible d'installer Python" "ERROR"
    pause
    exit 1
}

# Créer l'environnement virtuel
Write-Log "Création de l'environnement virtuel..."
& $pythonCmd -m venv venv
$venvPython = "$InstallDir\venv\Scripts\python.exe"

# Installer les dépendances
Write-Log "Installation des dépendances..."
if (Test-Path "requirements.txt") {
    & $venvPython -m pip install -r requirements.txt -q --disable-pip-version-check
    Write-Log "Dépendances installées" "SUCCESS"
}
else {
    Write-Log "Fichier requirements.txt introuvable" "ERROR"
    pause
    exit 1
}

# Générer le fichier .env
New-EnvFile

# Installer NSSM
$nssmPath = Install-NSSM
if (-not $nssmPath) {
    Write-Log "Impossible d'installer NSSM" "ERROR"
    pause
    exit 1
}

# Installer le service
$serviceInstalled = Install-Service -PythonCmd $pythonCmd -NssmPath $nssmPath

# Afficher les informations d'accès
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "  INSTALLATION TERMINÉE AVEC SUCCÈS" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
Write-Host ""

$localIP = Get-LocalIP

Write-Host "  Nom du service  : ADWebInterface" -ForegroundColor White
Write-Host "  Accès local     : http://localhost:$Port" -ForegroundColor Cyan
Write-Host "  Accès réseau    : http://$localIP`:$Port" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Le service démarrera automatiquement au prochain redémarrage." -ForegroundColor Yellow
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host ""

Write-Log "Ouverture du navigateur..."
Start-Process "http://localhost:$Port"

Write-Host ""
Write-Host "Appuyez sur une touche pour quitter..." -ForegroundColor Gray
pause | Out-Null
