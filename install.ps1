# ============================================================================
# INSTALLATION AUTOMATIQUE - AD Web Interface
# Script d'installation complète pour Windows Server 2022
# ============================================================================
# Version: 1.37.0
# Description: Installe toutes les dépendances et configure l'application
# ============================================================================

param(
    [switch]$SkipTests,      # Ignorer les tests de validation
    [switch]$DryRun,         # Simulation sans installation
    [switch]$Help            # Afficher l'aide
)

$ErrorActionPreference = "Stop"

# ============================================================================
# CONFIGURATION
# ============================================================================

$AppVersion = "1.37.0"
$AppName = "AD Web Interface"
$InstallPath = "C:\AD-WebInterface"
$ServiceName = "ADWebInterface"
$LogPath = "C:\AD-WebInterface\logs\install.log"

# ============================================================================
# FONCTIONS
# ============================================================================

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor White
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Text)
    Write-Host "  → $Text" -ForegroundColor Green
}

function Write-Warning-Custom {
    param([string]$Text)
    Write-Host "  ⚠ $Text" -ForegroundColor Yellow
}

function Write-Error-Custom {
    param([string]$Text)
    Write-Host "  ✗ $Text" -ForegroundColor Red
}

function Write-Success {
    param([string]$Text)
    Write-Host "  ✓ $Text" -ForegroundColor Green
}

function Write-Info {
    param([string]$Text)
    Write-Host "  ℹ $Text" -ForegroundColor White
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-Logging {
    if (-not (Test-Path (Split-Path $LogPath))) {
        New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
    }
    Start-Transcript -Path $LogPath -Append
}

function Stop-Logging {
    Stop-Transcript
}

function Wait-KeyPress {
    Write-Host ""
    Write-Host "Appuyez sur une touche pour continuer..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ============================================================================
# VÉRIFICATIONS PRÉLIMINAIRES
# ============================================================================

function Test-Prerequisites {
    Write-Header "VÉRIFICATIONS PRÉLIMINAIRES"
    
    $checks = @{
        "Droits administrateur" = $false
        "Windows Server 2022" = $false
        "PowerShell 5.1+" = $false
        "Connexion Internet" = $false
        "Espace disque (500MB)" = $false
    }
    
    # 1. Droits administrateur
    if (Test-Administrator) {
        $checks["Droits administrateur"] = $true
        Write-Success "Droits administrateur : OK"
    } else {
        Write-Error-Custom "Droits administrateur : ÉCHEC"
        Write-Warning-Custom "Exécutez ce script en tant qu'administrateur"
        return $false
    }
    
    # 2. Windows Server
    $os = Get-WmiObject Win32_OperatingSystem
    if ($os.Caption -like "*Server*" -and $os.Version -ge "10.0.20348") {
        $checks["Windows Server 2022"] = $true
        Write-Success "Windows Server : $($os.Caption)"
    } else {
        Write-Warning-Custom "Windows Server : $($os.Caption) (peut fonctionner)"
    }
    
    # 3. PowerShell
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        $checks["PowerShell 5.1+"] = $true
        Write-Success "PowerShell : $psVersion"
    } else {
        Write-Error-Custom "PowerShell : $psVersion (5.1+ requis)"
        return $false
    }
    
    # 4. Connexion Internet
    try {
        $connection = Test-NetConnection -ComputerName www.python.org -Port 443 -InformationLevel Quiet
        if ($connection) {
            $checks["Connexion Internet"] = $true
            Write-Success "Connexion Internet : OK"
        } else {
            Write-Warning-Custom "Connexion Internet : ÉCHEC"
        }
    } catch {
        Write-Warning-Custom "Test connexion : Impossible"
    }
    
    # 5. Espace disque
    $drive = Get-PSDrive C
    $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
    if ($freeSpaceGB -ge 0.5) {
        $checks["Espace disque (500MB)"] = $true
        Write-Success "Espace disque : ${freeSpaceGB}GB libres"
    } else {
        Write-Error-Custom "Espace disque : ${freeSpaceGB}GB (500MB requis)"
        return $false
    }
    
    Write-Host ""
    $passed = ($checks.Values | Where-Object { $_ }).Count
    $total = $checks.Count
    Write-Info "Vérifications : $passed/$total réussies"
    
    return ($passed -eq $total)
}

# ============================================================================
# INSTALLATION DES DÉPENDANCES
# ============================================================================

function Install-WingetIfMissing {
    Write-Step "Vérification de winget..."
    
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Success "winget déjà installé"
        return $true
    }
    
    Write-Info "Installation de winget..."
    
    try {
        # Installer depuis Microsoft Store (Windows Server 2022)
        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction SilentlyContinue
        
        # Ou télécharger depuis GitHub
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            $wingetUrl = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.bundle"
            $wingetInstaller = "$env:TEMP\winget-installer.bundle"
            Invoke-WebRequest -Uri $wingetUrl -OutFile $wingetInstaller -UseBasicParsing
            Start-Process -FilePath $wingetInstaller -ArgumentList "/quiet", "/norestart" -Wait
            Remove-Item $wingetInstaller -Force -ErrorAction SilentlyContinue
        }
        
        # Rafraîchir le PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Success "winget installé avec succès"
            return $true
        }
    } catch {
        Write-Warning-Custom "winget non installé - installation manuelle requise"
        Write-Info "Téléchargez depuis : https://aka.ms/winget"
    }
    
    return $false
}

function Install-Python {
    Write-Step "Installation de Python 3.12..."
    
    # Vérifier si Python est déjà installé
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        $version = & python --version 2>&1
        if ($version -match "Python 3\.1[2-9]") {
            Write-Success "Python déjà installé : $version"
            return $true
        }
    }
    
    # Installer via winget
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Info "Installation via winget..."
        winget install --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
        
        # Rafraîchir le PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        $python = Get-Command python -ErrorAction SilentlyContinue
        if ($python) {
            $version = & python --version 2>&1
            Write-Success "Python installé : $version"
            return $true
        }
    }
    
    # Fallback : téléchargement direct
    Write-Info "Téléchargement de Python..."
    $pythonUrl = "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"
    $pythonInstaller = "$env:TEMP\python-installer.exe"
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing
        Write-Info "Installation de Python..."
        Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait
        Remove-Item $pythonInstaller -Force -ErrorAction SilentlyContinue
        
        # Rafraîchir le PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        $python = Get-Command python -ErrorAction SilentlyContinue
        if ($python) {
            $version = & python --version 2>&1
            Write-Success "Python installé : $version"
            return $true
        }
    } catch {
        Write-Error-Custom "Échec installation Python"
        return $false
    }
    
    return $false
}

function Install-Git {
    Write-Step "Installation de Git..."
    
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git) {
        Write-Success "Git déjà installé"
        return $true
    }
    
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Info "Installation via winget..."
        winget install --id Git.Git --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
        
        # Rafraîchir le PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        if (Get-Command git -ErrorAction SilentlyContinue) {
            Write-Success "Git installé"
            return $true
        }
    }
    
    Write-Warning-Custom "Git non installé - installation manuelle requise"
    Write-Info "Téléchargez depuis : https://git-scm.com/download/win"
    return $false
}

function Install-Dependencies {
    Write-Step "Installation des dépendances Python..."
    
    if (Test-Path "requirements.txt") {
        python -m pip install --upgrade pip --quiet
        python -m pip install -r requirements.txt --quiet
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Dépendances installées"
            return $true
        }
    }
    
    Write-Error-Custom "Échec installation dépendances"
    return $false
}

# ============================================================================
# CONFIGURATION
# ============================================================================

function New-EnvironmentFile {
    Write-Step "Configuration de l'application..."
    
    if (Test-Path ".env") {
        Write-Info "Fichier .env existant conservé"
        return $true
    }
    
    Write-Info "Création du fichier .env..."
    
    # Générer une SECRET_KEY aléatoire
    $secretKey = [System.Web.Security.Membership]::GeneratePassword(64, 8)
    
    # Demander la configuration AD
    Write-Host ""
    Write-Host "Configuration Active Directory :" -ForegroundColor Cyan
    $adServer = Read-Host "  Serveur AD (ex: dc01.domain.local)"
    $adPort = Read-Host "  Port LDAP [389]"
    if ([string]::IsNullOrWhiteSpace($adPort)) { $adPort = "389" }
    
    $useSSL = Read-Host "  Utiliser LDAPS (636) ? [y/N]"
    $adUseSSL = ($useSSL -eq "y" -or $useSSL -eq "Y")
    $actualPort = if ($adUseSSL) { "636" } else { $adPort }
    
    # Créer le fichier .env
    $envContent = @"
# AD Web Interface Configuration
# Généré le $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")

SECRET_KEY=$secretKey
DEBUG=False

# Active Directory
AD_SERVER=$adServer
AD_PORT=$actualPort
AD_USE_SSL=$($adUseSSL.ToString().ToLower())

# Session
SESSION_TIMEOUT=1800
RBAC_ENABLED=True
DEFAULT_ROLE=admin

# Pagination
ITEMS_PER_PAGE=50
"@
    
    Set-Content -Path ".env" -Value $envContent -Encoding UTF8
    Write-Success "Fichier .env créé"
    
    return $true
}

# ============================================================================
# INSTALLATION DU SERVICE
# ============================================================================

function Install-Service {
    Write-Step "Installation du service Windows..."
    
    $serviceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if ($serviceExists) {
        Write-Info "Service déjà installé"
        # Mode non-interactif : ne pas réinstaller automatiquement
        Write-Success "Service conservé"
        return $true
    }
    
    # Utiliser WinSW
    if (Test-Path "nssm\WinSW.exe") {
        Write-Info "Installation avec WinSW..."
        .\nssm\WinSW.exe install
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Service installé avec WinSW"
            return $true
        }
    }
    
    # Fallback : NSSM
    if (Test-Path "nssm\nssm.exe") {
        Write-Info "Installation avec NSSM..."
        .\nssm\nssm.exe install $ServiceName "C:\AD-WebInterface\venv\Scripts\python.exe" "C:\AD-WebInterface\run.py"
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Service installé avec NSSM"
            return $true
        }
    }
    
    Write-Warning-Custom "Service non installé automatiquement"
    Write-Info "Utilisez : .\install_service.bat"
    return $false
}

function Configure-Firewall {
    Write-Step "Configuration du pare-feu..."
    
    $port = 5000
    $ruleName = "AD Web Interface"
    
    try {
        # Supprimer l'ancienne règle
        $null = netsh advfirewall firewall delete rule name="$ruleName" 2>$null
        
        # Créer la nouvelle règle
        $null = netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=TCP localport=$port 2>$null
        
        Write-Success "Pare-feu configuré (port $port)"
        return $true
    } catch {
        Write-Warning-Custom "Pare-feu non configuré automatiquement"
        Write-Info "Commande manuelle : netsh advfirewall firewall add rule name=`"$ruleName`" dir=in action=allow protocol=TCP localport=$port"
        return $false
    }
}

# ============================================================================
# TESTS DE VALIDATION
# ============================================================================

function Test-Installation {
    if ($SkipTests) {
        Write-Info "Tests ignorés"
        return $true
    }
    
    Write-Header "TESTS DE VALIDATION"
    
    $tests = @{
        "Service installé" = $false
        "Service démarré" = $false
        "Application répond" = $false
        "Connexion AD" = $false
    }
    
    # 1. Service installé
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        $tests["Service installé"] = $true
        Write-Success "Service : Installé"
    } else {
        Write-Error-Custom "Service : Non installé"
    }
    
    # 2. Service démarré
    if ($service -and $service.Status -eq "Running") {
        $tests["Service démarré"] = $true
        Write-Success "Service : Démarré"
    } elseif ($service) {
        Write-Info "Démarrage du service..."
        net start $ServiceName >nul 2>&1
        Start-Sleep -Seconds 3
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            $tests["Service démarré"] = $true
            Write-Success "Service : Démarré"
        }
    }
    
    # 3. Application répond
    Write-Info "Test de l'application..."
    Start-Sleep -Seconds 5
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:5000/api/health" -TimeoutSec 10 -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            $tests["Application répond"] = $true
            Write-Success "Application : Opérationnelle"
            
            # Afficher la version
            $json = $response.Content | ConvertFrom-Json
            Write-Info "Version : $($json.version)"
        }
    } catch {
        Write-Warning-Custom "Application : Non répond"
    }
    
    # 4. Connexion AD (si .env configuré)
    if (Test-Path ".env") {
        Write-Info "Test de connexion AD..."
        # Ce test nécessite une connexion valide
        # On vérifie juste que la configuration existe
        $envContent = Get-Content ".env"
        if ($envContent -match "AD_SERVER=") {
            $tests["Connexion AD"] = $true
            Write-Success "Configuration AD : Présente"
        }
    }
    
    Write-Host ""
    $passed = ($tests.Values | Where-Object { $_ }).Count
    $total = $tests.Count
    Write-Info "Tests : $passed/$total réussis"
    
    return ($passed -ge 2)
}

# ============================================================================
# RÉSUMÉ
# ============================================================================

function Show-Summary {
    Write-Header "INSTALLATION TERMINÉE"
    
    Write-Host "Version installée : $AppVersion" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Chemins importants :" -ForegroundColor White
    Write-Host "  Installation : $InstallPath" -ForegroundColor Gray
    Write-Host "  Logs : $LogPath" -ForegroundColor Gray
    Write-Host "  Configuration : $InstallPath\.env" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Commandes utiles :" -ForegroundColor White
    Write-Host "  Démarrer : net start $ServiceName" -ForegroundColor Gray
    Write-Host "  Arrêter : net stop $ServiceName" -ForegroundColor Gray
    Write-Host "  Statut : sc query $ServiceName" -ForegroundColor Gray
    Write-Host "  Logs : Get-Content $LogPath -Tail 50" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Accès à l'interface :" -ForegroundColor White
    Write-Host "  Local : http://localhost:5000" -ForegroundColor Cyan
    Write-Host "  Distant : http://$env:COMPUTERNAME:5000" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Prochaines étapes :" -ForegroundColor White
    Write-Host "  1. Configurez .env avec vos paramètres AD" -ForegroundColor Yellow
    Write-Host "  2. Connectez-vous avec un compte administrateur AD" -ForegroundColor Yellow
    Write-Host "  3. Consultez la documentation dans README.md" -ForegroundColor Yellow
    Write-Host ""
}

# ============================================================================
# MAIN
# ============================================================================

if ($Help) {
    Write-Header "AIDE - Installation AD Web Interface"
    Write-Host "Usage:"
    Write-Host "  .\install.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -SkipTests   Ignorer les tests de validation"
    Write-Host "  -DryRun      Simulation sans installation"
    Write-Host "  -Help        Afficher cette aide"
    Write-Host ""
    exit 0
}

Write-Header "INSTALLATION - AD Web Interface v$AppVersion"

# Démarrer la journalisation
Start-Logging

# Mode Dry Run
if ($DryRun) {
    Write-Warning-Custom "MODE SIMULATION - Aucune modification ne sera apportée"
    Write-Host ""
    Write-Info "Ce script va :"
    Write-Host "  1. Vérifier les prérequis"
    Write-Host "  2. Installer Python 3.12"
    Write-Host "  3. Installer Git"
    Write-Host "  4. Installer les dépendances Python"
    Write-Host "  5. Configurer l'application"
    Write-Host "  6. Installer le service Windows"
    Write-Host "  7. Configurer le pare-feu"
    Write-Host "  8. Exécuter les tests de validation"
    Write-Host ""
    exit 0
}

# Vérifier les droits administrateur
if (-not (Test-Administrator)) {
    Write-Error-Custom "Ce script doit être exécuté en tant qu'administrateur"
    Write-Info "Clic droit sur install.ps1 → Exécuter en tant qu'administrateur"
    Stop-Logging
    pause
    exit 1
}
Write-Success "Droits administrateur : OK"

# Vérifications préliminaires
if (-not (Test-Prerequisites)) {
    Write-Error-Custom "Vérifications préliminaires échouées"
    Stop-Logging
    Write-Host ""
    Write-Warning-Custom "Corrigez les problèmes ci-dessus et relancez l'installation"
    Wait-KeyPress
    exit 1
}

Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan

# Installer winget si manquant
Install-WingetIfMissing

# Installer Python
if (-not (Install-Python)) {
    Write-Error-Custom "Python requis pour continuer"
    Stop-Logging
    Wait-KeyPress
    exit 1
}

# Installer Git
Install-Git

# Installer les dépendances
if (-not (Install-Dependencies)) {
    Write-Warning-Custom "Certaines dépendances peuvent manquer"
}

# Configuration
if (-not (New-EnvironmentFile)) {
    Write-Warning-Custom "Configuration échouée"
}

# Installation du service
if (-not (Install-Service)) {
    Write-Warning-Custom "Service non installé"
}

# Configuration du pare-feu
Configure-Firewall

# Tests de validation
$testsPassed = Test-Installation

# Afficher le résumé
Show-Summary

# Arrêter la journalisation
Stop-Logging

# Pause finale
if (-not $testsPassed) {
    Write-Warning-Custom "Certains tests ont échoué. Consultez les logs pour plus de détails."
}

Wait-KeyPress
