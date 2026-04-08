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
SESSION_COOKIE_SECURE=true
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
# SIG # Begin signature block
# MIIcIAYJKoZIhvcNAQcCoIIcETCCHA0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBnbzJiV/F2kBMz
# Un5f2uEXi0FFQ7le9vPO59+xkdZVn6CCFl4wggMgMIICCKADAgECAhB15f8UAKT2
# qEy95UH9z4ncMA0GCSqGSIb3DQEBCwUAMCgxJjAkBgNVBAMMHUFEIFdlYiBJbnRl
# cmZhY2UgQ29kZSBTaWduaW5nMB4XDTI2MDQwNzE3MTIxMloXDTMxMDQwNzE3MjIx
# MVowKDEmMCQGA1UEAwwdQUQgV2ViIEludGVyZmFjZSBDb2RlIFNpZ25pbmcwggEi
# MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC269UaRy1MGOjCD2hW2D59Noc3
# VfDKrsuvUMg2OKWsBmUyuBerJKvYLSou9EbyOi4PXg5CbcYF4xWzdwTAmNVYjxTJ
# Rddkq4f8tTM9faXdqdOYPaBl3VWcivnTdBGAVL28FEpCkUzK6zpvfDxRKRC66fXT
# q/XpFh9HFx+h/jvYPXQ4R0dE05JbTBuyrAkewb0kvVkWdJ1Cbzi4QoGLmeZMUTMq
# FVD6/XtF/ZFH1luXUno+8nBUkYDOacw61wb1gIGHEBfRVJnvHQb6UINRNUP/EiMK
# G0rnlf7Oy3CserhIFvnxmos1tBP7S/WMGyRHC8y0KHVfIa2qm1aGXvD4gP8RAgMB
# AAGjRjBEMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNV
# HQ4EFgQUEiecK9t6ETEB2YcQWxM/ynrOgFIwDQYJKoZIhvcNAQELBQADggEBAJKE
# S3JgZimRwjZHmNeV/Kat6kaIVzlt2r/JnVrYXDEtBV9Z/MngBJRLX2Ei4mDU+UWK
# syMWATOw+tAs4aftq6IXpGPLfY9j6Up6Ghb3ESOVfyiHv0PvnXiyEjON4Aja3S/Q
# 4DtJI/eKkFvlJQ4xykkuIlwYvcag44sTma2PGAkJ8AZfGgzN3H5eh1Dp+OBLiYjs
# f9oE8ADv35mUeMzZSpy6HIdi+gQ7Ptv4vIssoNxuaCvxahH23i2lTFPUOgGzdvWm
# vu7oyE0FGMY5VHOKnxEqh9B1DxFL575+K4FiznKWPt+qTq6rldYjgK0zclR6mC0c
# KBKqMvqZQpo98V4Ti/8wggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0G
# CSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0
# IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5
# NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNV
# BAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQg
# Um9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvk
# XUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdt
# HauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu
# 34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0
# QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2
# kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM
# 1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmI
# dph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZ
# K37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72
# gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqs
# X40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyh
# HsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8E
# BTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAW
# gBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUH
# AQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYI
# KwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAE
# CjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX
# 979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offy
# ct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3
# J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0
# d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6ts
# ds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQw
# gga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1
# c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0Zo
# dLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi
# 6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNg
# xVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiF
# cMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJ
# m/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvS
# GmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1
# ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9
# MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7
# Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bG
# RinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6
# X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAd
# BgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJo
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxj
# aaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0
# hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0
# F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnT
# mpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKf
# ZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzE
# wlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbh
# OhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOX
# gpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EO
# LLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wG
# WqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWg
# AwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# MB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEy
# NTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3
# zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8Tch
# TySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWj
# FDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2Uo
# yrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjP
# KHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KS
# uNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7w
# JNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vW
# doUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOg
# rY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K
# 096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCf
# gPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zy
# Me39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezL
# TjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsG
# AQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNy
# dDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZ
# D9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/
# ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu
# +WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4o
# bEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2h
# ECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasn
# M9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol
# /DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgY
# xQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3oc
# CVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcB
# ZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRgwggUU
# AgEBMDwwKDEmMCQGA1UEAwwdQUQgV2ViIEludGVyZmFjZSBDb2RlIFNpZ25pbmcC
# EHXl/xQApPaoTL3lQf3PidwwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIB
# DDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQghtv7dFDWavm2
# p9Kcr08I3LZ9spPLfVGj3mQ1ZWtG4a8wDQYJKoZIhvcNAQEBBQAEggEAMpWtPFlr
# 9fnmDqkObryasJrPZdWcQs5Hy2n1Ns3M17zZcRYjJIk+5GVeh75s+1Q33+VBxHts
# tGM62D5l7XS+yDybZdD34i4S6WunFMk/8wB1KK0FALpywpFWduCQqRBjRiYEyMCA
# dba9/mfnckdeg7uGQzoeIv4/tz51XL/UN2tC/I3JaJ1IwwaZwwhjTLjMS4zoEv+e
# wjayIQKezlRPq319O3nZkxF5deryiMA3mfw2D+f0hGP+hVy0ylx1MYcm+u9bESTN
# Vq2CJY2x7kyP01bea+yTCVYs2AWIIgx/YGGkNzy2WCz6vYLKf/Pj/OVz3yCMc8ej
# xFutndNv7odulaGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA0MDgwNzQ1NTFa
# MC8GCSqGSIb3DQEJBDEiBCBEy9DLrJ24OFc39If5xsBsKTrwMpU6AqxcICZv8sDe
# /zANBgkqhkiG9w0BAQEFAASCAgBBT3bJD8TN4KMlBQDAKxF0IpuYCgZtCpub2NsL
# xB/Lhh9O549sLbrCiOIa1kcdhOV8y0J2IvirXWllokRauS9EX/VMZy+uEoK9zXv3
# yPvkJpkh3dQY8ukvVBGOT1Hld/maOcMDcgDuPlHD4oPb/aVKApjYuOpzhRJt0ezy
# u/O43KhlMQmHV3kU/pnqCqj+auVUIUlNhrYFJx5fMHkEqzT2/Y0WbM0xg6Fuo6PH
# sxpAikaIqcBg0+uQIDOTlUSh47UiFCOqR1XS24pL7C1TdemEWBfkbjDdB0ZlbQXg
# qSGSRwsYPiFkP4q13jl7wlEQ1zwSQFMFSlVq+pKrjj0MV6N1h0whHWEIxJjokshp
# rcM9b3g/CnSmndoF/pALaKpXmDU44+vNcsS15tC3jhuL7a8OZ3XNbC6wVKKL3VQX
# CtDThFHrOMGIC3Jd8X6D0xscbetvSILAJHOOga3nCe08UUZzEN00YKAZXEXJGx92
# JwbKAO5koYWmr+qSa0VfOLYsc1iDFVdOG9yw9/bVblTCU/7qgIbfda8+MSX7Qhdr
# /45VBZMogblXhWcHBU4MqeoviV7e87y4XNhxqcpsBp2qBppe4xpbFIkmhFI7Diaz
# ZvvoZDaNZ8INdSTgAVFzVre4OMjtf1CbxyufM7M1cCIpOAZiGUC3R8yOcqeNLbwA
# WQNk2Q==
# SIG # End signature block
