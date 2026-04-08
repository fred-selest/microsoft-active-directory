# ============================================================================
# INSTALLATION AUTOMATIQUE - AD WEB INTERFACE
# Pour contrôleur de domaine Windows Server
# ============================================================================
# Ce script installe automatiquement l'interface web AD sur le DC
# Exécuter en tant qu'administrateur
# Peut être placé dans N'IMPORTE QUEL RÉPERTOIRE
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Port d'écoute de l'application")]
    [int]$Port = 5000,
    
    [Parameter(HelpMessage="Installer Python si absent")]
    [switch]$InstallPython = $true,
    
    [Parameter(HelpMessage="Dossier d'installation (par défaut: dossier du script)")]
    [string]$InstallDir
)

# ============================================================================
# DÉTERMINER LE DOSSIER D'INSTALLATION
# ============================================================================

# Si InstallDir n'est pas spécifié, utiliser le dossier où se trouve ce script
if (-not $InstallDir -or $InstallDir -eq "") {
    $InstallDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
}

# S'assurer que le chemin est absolu
if (-not [System.IO.Path]::IsPathRooted($InstallDir)) {
    $InstallDir = Resolve-Path $InstallDir
}

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

# Vérifier que ce script est dans le bon dossier (avec les fichiers requis)
Write-Log "Vérification des fichiers requis..."
$requiredFiles = @('requirements.txt', 'app.py', 'run.py')
$missingFiles = @()

foreach ($file in $requiredFiles) {
    $filePath = Join-Path $InstallDir $file
    if (-not (Test-Path $filePath)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Log "Fichiers requis introuvables dans : $InstallDir" "ERROR"
    Write-Log "Fichiers manquants : $($missingFiles -join ', ')" "ERROR"
    Write-Log "" "INFO"
    Write-Log "Ce script doit être placé dans le dossier de l'application." "INFO"
    Write-Log "Exemple : C:\AD-WebInterface\install_ad.ps1" "INFO"
    Write-Log "" "INFO"
    pause
    exit 1
}
Write-Log "Fichiers requis vérifiés" "SUCCESS"

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

# SIG # Begin signature block
# MIIcIAYJKoZIhvcNAQcCoIIcETCCHA0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAexJmi5FPRcrx1
# 01VMpx+6WHWTsdT3W9VQzVA28dTO6qCCFl4wggMgMIICCKADAgECAhB15f8UAKT2
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgQXQIPYwGpyeA
# 3ZUFuZcV+jirtHVEsQd73E8Fkxinfc0wDQYJKoZIhvcNAQEBBQAEggEALutV+V9n
# HT/s7bJekKaXs2YE+KI00FSHghTxfirzxb7c9pMnXc/idBt8aZJCXQcjmVEo72QU
# JPqB8oSkkms6IxvbqUF1hBI6TpHArDxYEuRjxmx7bHANKMpLOJqMtw5elrksyTBN
# uy4S5Te4T+vqbpJ6PDJvO5hOtgJIhgp9YQiygCubFKSAUelnTgKwWbEFSmU9Gms5
# 3QNlOyJfeQwL5v0h0D6fbvDvEWCbHTsoiDwaTYsT/epH2UKgmOyqz9zBo/XOznvv
# ffL9Ac8ydy1PGCEXiTgktTSQguIvv6zZxkcCm0z5sSMV+XC5NCoPY8R7r20k3olE
# 75Kcplk4d8pGZ6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA0MDgwNjM4MjZa
# MC8GCSqGSIb3DQEJBDEiBCDlLHWNkM5VlhMa1qXMFFo7TQXuEHFDOdyXamvGVp2+
# aDANBgkqhkiG9w0BAQEFAASCAgCi7fhG/hqrqbMqolvOBEnVJ7O1orCfhaBppstv
# +R8dilJrrl73Lq2874o8jM0YK1xdjmPyO6x/zGldkCXnQvTNhcC4EsNtaNd7NFzv
# ZlCqs0L1YrHTNLz7qVCPh0MHHc98qZVf40AMEB1sa8iLXZAyvvgxHAfNYdGFc8Xc
# WVgBVFZrTaNGR+6wcDsddmxJXIlev5AD5G1wHQ/8FTzoDnudjqD5olkT8MNpOU9K
# GSH0jRiJx5LCdUbmo57J3TjylCbYwtXQoJk/pXJ1o97nmdbxiC9ZkUddT0lnNpQw
# GQZSnMKk6sm+e0BJFIcjL9LsBX5WyoEs7P1QWh4O7ZcZYMdq3QYCs2uelFhm+Ifa
# 23fKEv+w/7sRKG4NxQWhC1E0mX75RcyxPZYBUo2U+yi2QM0pgXLRqXix3U5fBQOD
# lrBZY/TBprGjgprQJEKXtaLcuYxz2LKMBePqryQjrz1LS+YKj2sqmYueXUSfTz7k
# f53hxQV2gUxG1HOb0uI4yUPgiv/8VXUBy6jrvHrBo6NFGjSyVI6Xxl0H2qHzcXhd
# 7LtOBIvY6eS2AqWU1ysDIq39sUbFcHOjC9Blz+YNqh2e/kUAbr7i6mOVzEM5KLK8
# zI4umwRVjin5z+/PWW+GbLvlRBstEYMkXyytO0PReS8/Ni4WSH2GEtMkx4h5ti51
# J9W+/w==
# SIG # End signature block
