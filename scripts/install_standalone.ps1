# ==============================================================================
# Installation autonome AD Web Interface
# Script de deploiement complet pour Windows Server
# ==============================================================================
# Version: 1.34.2
# Auteur: AD Web Interface Team
# Date: Avril 2026
# ==============================================================================

param(
    [string]$InstallPath = "C:\AD-WebInterface",
    [string]$Port = "5000",
    [switch]$SkipService,
    [switch]$SkipFirewall,
    [switch]$Help
)

# ==============================================================================
# CONFIGURATION
# ==============================================================================

$ErrorActionPreference = "Stop"
$AppName = "AD Web Interface"
$ServiceName = "ADWebInterface"

# ==============================================================================
# FONCTIONS
# ==============================================================================

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
}

function Write-Success {
    param([string]$Text)
    Write-Host "[OK] $Text" -ForegroundColor Green
}

function Write-ErrorMsg {
    param([string]$Text)
    Write-Host "[ERREUR] $Text" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Text)
    Write-Host "[ATTENTION] $Text" -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Text)
    Write-Host "[INFO] $Text" -ForegroundColor White
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-Python {
    Write-Info "Verification de Python..."

    # Rafraichir le PATH d'abord
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

    # Verifier si Python est installe
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        $version = & python --version 2>&1
        Write-Success "Python detecte: $version"

        # Verifier la version (3.10+ requis)
        $versionStr = $version.ToString()
        if ($versionStr -match "Python 3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 10) {
                return $true
            } else {
                Write-Warning "Python 3.10+ requis (version actuelle: $version)"
            }
        }
    }

    Write-Warning "Python non trouve ou version insuffisante. Installation..."

    # Methode 1: winget (Windows 10/11)
    Write-Info "Methode 1: winget..."
    try {
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if ($winget) {
            Write-Info "Installation de Python 3.12 via winget..."
            winget install --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null

            # Rafraichir le PATH
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

            # Verifier que Python est maintenant disponible
            $python = Get-Command python -ErrorAction SilentlyContinue
            if ($python) {
                $version = & python --version 2>&1
                Write-Success "Python installe avec succes: $version"
                return $true
            }
        }
    } catch {
        Write-Warning "winget non disponible ou echec"
    }

    # Methode 2: Telechargement direct
    Write-Info "Methode 2: Telechargement direct..."
    $pythonUrl = "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"
    $pythonInstaller = "$env:TEMP\python-installer.exe"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Info "Telechargement de Python 3.12.0..."
        Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing
        Write-Info "Installation de Python 3.12.0 en cours..."
        Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
        Remove-Item $pythonInstaller -Force -ErrorAction SilentlyContinue

        # Rafraichir le PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

        # Verifier que Python est maintenant disponible
        $python = Get-Command python -ErrorAction SilentlyContinue
        if ($python) {
            $version = & python --version 2>&1
            Write-Success "Python verifie: $version"
            return $true
        } else {
            Write-ErrorMsg "Python n'est pas dans le PATH apres installation"
            Write-Warning "Essayez de redemarrer la session PowerShell"
            return $false
        }
    } catch {
        Write-ErrorMsg "Erreur lors de l'installation de Python: $_"
        Write-Warning "Installez Python manuellement depuis https://www.python.org/downloads/"
        Write-Warning "OU utilisez: winget install Python.Python.3.12"
        return $false
    }
}

function New-VirtualEnvironment {
    param([string]$Path)

    Write-Info "Creation de l'environnement virtuel Python..."

    $venvPath = Join-Path $Path "venv"

    if (Test-Path $venvPath) {
        Write-Info "Environnement virtuel existant detecte"
        return $true
    }

    try {
        Push-Location $Path
        & python -m venv venv
        Pop-Location

        Write-Success "Environnement virtuel cree"
        return $true
    } catch {
        Write-ErrorMsg "Erreur lors de la creation de l'environnement virtuel: $_"
        return $false
    }
}

function Install-Dependencies {
    param([string]$Path)

    Write-Info "Installation des dependances Python..."

    $requirementsPath = Join-Path $Path "requirements.txt"

    if (-not (Test-Path $requirementsPath)) {
        Write-ErrorMsg "Fichier requirements.txt non trouve"
        return $false
    }

    try {
        $pipPath = Join-Path $Path "venv\Scripts\pip.exe"
        & $pipPath install --upgrade pip 2>&1 | Out-Null
        & $pipPath install -r $requirementsPath 2>&1 | Out-Null

        Write-Success "Dependances installees"
        return $true
    } catch {
        Write-ErrorMsg "Erreur lors de l'installation des dependances: $_"
        return $false
    }
}

function New-Configuration {
    param([string]$Path)

    Write-Info "Creation de la configuration..."

    $envPath = Join-Path $Path ".env"

    if (Test-Path $envPath) {
        Write-Info "Fichier .env existant detecte"
        return $true
    }

    try {
        # Generer une cle secrete
        $secretKey = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | ForEach-Object { [char]$_ })

        $envContent = @"
# Configuration AD Web Interface
# Genere automatiquement le $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

SECRET_KEY=$secretKey
FLASK_ENV=production
FLASK_DEBUG=false
SESSION_COOKIE_SECURE=false
"@

        $envContent | Out-File -FilePath $envPath -Encoding UTF8

        Write-Success "Fichier .env cree avec cle secrete"
        return $true
    } catch {
        Write-ErrorMsg "Erreur lors de la creation de la configuration: $_"
        return $false
    }
}

function New-WindowsService {
    param(
        [string]$Path,
        [string]$Port
    )

    Write-Info "Creation du service Windows..."

    # Verifier si le service existe deja
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Info "Service existant detecte - Suppression..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    try {
        $pythonPath = Join-Path $Path "venv\Scripts\python.exe"
        $runPath = Join-Path $Path "run.py"
        $nssmPath = Join-Path $Path "nssm\nssm.exe"

        if (Test-Path $nssmPath) {
            # Utiliser NSSM
            & $nssmPath install $ServiceName $pythonPath $runPath
            & $nssmPath set $ServiceName AppDirectory $Path
            & $nssmPath set $ServiceName DisplayName $AppName
            & $nssmPath set $ServiceName Description "Interface web d'administration Active Directory"
            & $nssmPath set $ServiceName Start SERVICE_AUTO_START
            & $nssmPath set $ServiceName AppStdout (Join-Path $Path "logs\server.log")
            & $nssmPath set $ServiceName AppStderr (Join-Path $Path "logs\error.log")
            Write-Success "Service Windows cree avec NSSM"
        } else {
            Write-Warning "NSSM non trouve, creation manuelle requise"
            Write-Info "Utilisez: sc.exe create $ServiceName binPath= `"$pythonPath $runPath`" start= auto"
        }

        return $true
    } catch {
        Write-ErrorMsg "Erreur lors de la creation du service: $_"
        return $false
    }
}

function New-FirewallRule {
    param([string]$Port)

    Write-Info "Configuration du pare-feu Windows..."

    $ruleName = "AD Web Interface - Port $Port"

    # Supprimer la regle existante si presente
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

    # Creer la nouvelle regle
    try {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -LocalPort $Port -Protocol TCP -Action Allow | Out-Null
        Write-Success "Regle pare-feu creee: Port $Port"
        return $true
    } catch {
        Write-ErrorMsg "Erreur lors de la configuration du pare-feu: $_"
        return $false
    }
}

function Start-ADWebInterface {
    Write-Info "Demarrage du service..."

    try {
        Start-Service -Name $ServiceName
        Start-Sleep -Seconds 3

        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Write-Success "Service demarre avec succes"
            return $true
        } else {
            Write-Warning "Le service n'a pas pu demarrer automatiquement"
            return $false
        }
    } catch {
        Write-Warning "Erreur lors du demarrage du service: $_"
        return $false
    }
}

function Show-Help {
    Write-Host @"

$AppName - Script d'installation autonome

USAGE:
    .\install_standalone.ps1 [OPTIONS]

OPTIONS:
    -InstallPath <chemin>    Chemin d'installation (defaut: C:\AD-WebInterface)
    -Port <port>             Port d'ecoute (defaut: 5000)
    -SkipService             Ne pas creer le service Windows
    -SkipFirewall            Ne pas configurer le pare-feu
    -Help                    Afficher cette aide

EXEMPLES:
    .\install_standalone.ps1
    .\install_standalone.ps1 -InstallPath D:\AD-Web -Port 8080
    .\install_standalone.ps1 -SkipService

REQUIS:
    - Windows Server 2016+ ou Windows 10+
    - Droits administrateur
    - Connexion Internet (pour Python et dependances)

"@
}

# ==============================================================================
# MAIN
# ==============================================================================

if ($Help) {
    Show-Help
    exit 0
}

Write-Header "Installation de $AppName"

# Verifier les droits administrateur
if (-not (Test-Administrator)) {
    Write-ErrorMsg "Ce script doit etre execute en tant qu'Administrateur"
    Write-Info "Clic droit sur PowerShell -> Executer en tant qu'administrateur"
    pause
    exit 1
}

Write-Success "Droits administrateur verifies"

# Afficher la configuration
Write-Info "Configuration:"
Write-Host "  Chemin d'installation: $InstallPath"
Write-Host "  Port: $Port"
Write-Host "  Creer service: $(-not $SkipService)"
Write-Host "  Configurer pare-feu: $(-not $SkipFirewall)"
Write-Host ""

# Creer le repertoire d'installation
if (-not (Test-Path $InstallPath)) {
    Write-Info "Creation du repertoire: $InstallPath"
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}

# Verifier/Installer Python
if (-not (Install-Python)) {
    Write-ErrorMsg "Echec de l'installation de Python"
    pause
    exit 1
}

# Copier les fichiers si on est dans un repertoire different
$currentDir = $PSScriptRoot
if ($currentDir -and $currentDir -ne $InstallPath) {
    Write-Info "Copie des fichiers vers $InstallPath..."

    $parentDir = Split-Path $currentDir -Parent

    $filesToCopy = @(
        "app.py", "run.py", "config.py", "requirements.txt",
        "routes", "templates", "static", "password_audit",
        "security.py", "audit.py", "alerts.py", "backup.py",
        "ldap_errors.py", "password_generator.py", "session_crypto.py",
        "granular_permissions.py", "ad_detect.py", "context_processor.py",
        "auto_reload.py", "nssm"
    )

    foreach ($file in $filesToCopy) {
        $source = Join-Path $parentDir $file
        if (Test-Path $source) {
            Copy-Item -Path $source -Destination $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Creer le repertoire logs
$logsPath = Join-Path $InstallPath "logs"
if (-not (Test-Path $logsPath)) {
    New-Item -ItemType Directory -Path $logsPath -Force | Out-Null
}

# Creer le repertoire data
$dataPath = Join-Path $InstallPath "data"
if (-not (Test-Path $dataPath)) {
    New-Item -ItemType Directory -Path $dataPath -Force | Out-Null
}

# Creer l'environnement virtuel
if (-not (New-VirtualEnvironment -Path $InstallPath)) {
    Write-ErrorMsg "Echec de la creation de l'environnement virtuel"
    pause
    exit 1
}

# Installer les dependances
if (-not (Install-Dependencies -Path $InstallPath)) {
    Write-ErrorMsg "Echec de l'installation des dependances"
    pause
    exit 1
}

# Creer la configuration
if (-not (New-Configuration -Path $InstallPath)) {
    Write-ErrorMsg "Echec de la creation de la configuration"
    pause
    exit 1
}

# Creer le service Windows
if (-not $SkipService) {
    if (-not (New-WindowsService -Path $InstallPath -Port $Port)) {
        Write-Warning "Le service n'a pas pu etre cree"
    }
}

# Configurer le pare-feu
if (-not $SkipFirewall) {
    if (-not (New-FirewallRule -Port $Port)) {
        Write-Warning "Le pare-feu n'a pas pu etre configure"
    }
}

# Demarrer le service
if (-not $SkipService) {
    Start-ADWebInterface
}

# ==============================================================================
# RESUME
# ==============================================================================

Write-Header "Installation terminee!"

Write-Host "Resume de l'installation:" -ForegroundColor White
Write-Host ""
Write-Host "  Chemin:      $InstallPath" -ForegroundColor Cyan
Write-Host "  URL:         http://localhost:$Port" -ForegroundColor Cyan
Write-Host "  Service:     $ServiceName" -ForegroundColor Cyan
Write-Host ""

if (-not $SkipService) {
    Write-Host "Commandes utiles:" -ForegroundColor White
    Write-Host "  Demarrer:    net start $ServiceName" -ForegroundColor Gray
    Write-Host "  Arreter:     net stop $ServiceName" -ForegroundColor Gray
    Write-Host "  Statut:      sc query $ServiceName" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "Prochaines etapes:" -ForegroundColor White
Write-Host "  1. Ouvrez http://localhost:$Port dans votre navigateur" -ForegroundColor Yellow
Write-Host "  2. Connectez-vous avec vos identifiants AD" -ForegroundColor Yellow
Write-Host ""

Write-Success "Installation reussie!"

pause
