# ============================================================================
# INSTALLATION AUTONOME - AD WEB INTERFACE
# Pour contrôleur de domaine Windows Server
# ============================================================================
# Ce script est AUTONOME : il télécharge l'application depuis GitHub
# puis installe Python, les dépendances et le service Windows.
#
# Usage :
#   .\install_standalone.ps1
#   .\install_standalone.ps1 -InstallDir "C:\AD-WebInterface" -Port 5000
#   .\install_standalone.ps1 -Version "1.34.0"
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Dossier d'installation")]
    [string]$InstallDir = "C:\AD-WebInterface",

    [Parameter(HelpMessage="Port d'écoute de l'application")]
    [int]$Port = 5000,

    [Parameter(HelpMessage="Version à installer (ex: 1.34.0). Laissez vide pour la dernière version.")]
    [string]$Version = "",

    [Parameter(HelpMessage="Installer Python si absent")]
    [switch]$InstallPython = $true
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
        "ERROR"   { "Red" }
        default   { "White" }
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

function Get-LatestVersion {
    Write-Log "Récupération de la dernière version disponible..."
    try {
        $apiUrl = "https://api.github.com/repos/fred-selest/microsoft-active-directory/releases/latest"
        $headers = @{ "User-Agent" = "ADWebInterface-Installer" }
        $release = Invoke-RestMethod -Uri $apiUrl -Headers $headers -UseBasicParsing
        $tag = $release.tag_name.TrimStart('v')
        Write-Log "Dernière version : $tag" "SUCCESS"
        return $tag
    }
    catch {
        Write-Log "Impossible de contacter l'API GitHub : $_" "ERROR"
        return $null
    }
}

function Download-Application {
    param([string]$TargetVersion)

    $zipName   = "AD-WebInterface-${TargetVersion}-Windows.zip"
    $downloadUrl = "https://github.com/fred-selest/microsoft-active-directory/releases/download/v${TargetVersion}/${zipName}"
    $zipPath   = "$env:TEMP\$zipName"
    $extractDir = "$env:TEMP\ADWebInterface-extract"

    Write-Log "Téléchargement de v${TargetVersion}..."
    Write-Log "URL : $downloadUrl"

    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
        Write-Log "Téléchargement terminé" "SUCCESS"
    }
    catch {
        Write-Log "Échec du téléchargement : $_" "ERROR"
        return $false
    }

    Write-Log "Extraction de l'archive..."
    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
    try {
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
    }
    catch {
        Write-Log "Échec de l'extraction : $_" "ERROR"
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        return $false
    }

    # Le zip contient un sous-dossier AD-WebInterface-<version>-Windows
    $sourceFolder = Get-ChildItem -Path $extractDir -Directory | Select-Object -First 1
    if (-not $sourceFolder) {
        Write-Log "Structure d'archive inattendue" "ERROR"
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
        return $false
    }

    Write-Log "Copie des fichiers vers $InstallDir..."
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    }

    # Copier le contenu (sans écraser .env si déjà présent)
    $envFile = Join-Path $InstallDir ".env"
    $envBackup = $null
    if (Test-Path $envFile) {
        $envBackup = "$envFile.bak"
        Copy-Item $envFile $envBackup -Force
        Write-Log "Fichier .env existant sauvegardé (.env.bak)" "WARNING"
    }

    Copy-Item -Path "$($sourceFolder.FullName)\*" -Destination $InstallDir -Recurse -Force

    # Restaurer l'ancien .env si on avait une sauvegarde
    if ($envBackup -and (Test-Path $envBackup)) {
        Copy-Item $envBackup $envFile -Force
        Remove-Item $envBackup -Force
        Write-Log "Fichier .env existant restauré" "SUCCESS"
    }

    # Nettoyage
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Log "Application installée dans $InstallDir" "SUCCESS"
    return $true
}

function Install-Python {
    Write-Log "Vérification de Python..."

    try {
        Get-Command python -ErrorAction Stop | Out-Null
        $version = & python --version 2>&1
        Write-Log "Python déjà installé : $version" "SUCCESS"
        return "python"
    }
    catch {}

    try {
        Get-Command py -ErrorAction Stop | Out-Null
        $version = & py --version 2>&1
        Write-Log "Python déjà installé (py) : $version" "SUCCESS"
        return "py"
    }
    catch {}

    if (-not $InstallPython) {
        Write-Log "Python introuvable et -InstallPython non activé" "ERROR"
        return $null
    }

    Write-Log "Installation de Python 3.12..."

    # Tentative via winget
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Log "Installation via winget..."
        winget install Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

        try {
            Get-Command python -ErrorAction Stop | Out-Null
            Write-Log "Python installé via winget" "SUCCESS"
            return "python"
        }
        catch {}
    }

    # Téléchargement manuel
    $pythonUrl       = "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"
    $pythonInstaller = "$env:TEMP\python-setup.exe"

    Write-Log "Téléchargement de Python 3.12..."
    Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing

    Write-Log "Installation silencieuse de Python..."
    Start-Process -FilePath $pythonInstaller `
        -ArgumentList "/quiet","InstallAllUsers=1","PrependPath=1","Include_pip=1","Include_test=0" `
        -Wait

    Remove-Item $pythonInstaller -Force
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

    Write-Log "Python installé avec succès" "SUCCESS"
    return "python"
}

function Install-NSSM {
    $nssmPath = "$InstallDir\nssm\nssm.exe"

    if (Test-Path $nssmPath) {
        Write-Log "NSSM déjà présent" "SUCCESS"
        return $nssmPath
    }

    New-Item -ItemType Directory -Force -Path "$InstallDir\nssm" | Out-Null

    Write-Log "Téléchargement de NSSM..."
    $nssmZip    = "$env:TEMP\nssm.zip"
    $nssmExtract = "$env:TEMP\nssm-extract"

    try {
        Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $nssmZip -UseBasicParsing
        Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force

        $nssmExe = Get-ChildItem -Path $nssmExtract -Recurse -Filter "nssm.exe" |
                   Where-Object { $_.FullName -match "win64" } |
                   Select-Object -First 1

        if (-not $nssmExe) {
            $nssmExe = Get-ChildItem -Path $nssmExtract -Recurse -Filter "nssm.exe" | Select-Object -First 1
        }

        if ($nssmExe) {
            Copy-Item $nssmExe.FullName -Destination $nssmPath -Force
            Write-Log "NSSM installé : $nssmPath" "SUCCESS"
            return $nssmPath
        }
        else {
            Write-Log "nssm.exe introuvable dans l'archive" "ERROR"
        }
    }
    catch {
        Write-Log "Échec téléchargement NSSM : $_" "ERROR"
    }
    finally {
        if (Test-Path $nssmZip)    { Remove-Item $nssmZip    -Force }
        if (Test-Path $nssmExtract){ Remove-Item $nssmExtract -Recurse -Force }
    }

    return $null
}

function New-EnvFile {
    $envFile = "$InstallDir\.env"
    if (Test-Path $envFile) {
        Write-Log "Fichier .env déjà présent, conservé tel quel" "WARNING"
        return
    }

    Write-Log "Génération du fichier .env..."

    $secretKey = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | ForEach-Object { [char]$_ })

    $envContent = @"
# Configuration générée automatiquement par install_standalone.ps1
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

    $envContent | Out-File -FilePath $envFile -Encoding UTF8
    Write-Log "Fichier .env créé" "SUCCESS"
}

function Install-Service {
    param([string]$PythonCmd, [string]$NssmPath)

    $serviceName   = "ADWebInterface"
    $serviceDisplay = "Interface Web Active Directory"
    $pythonExe     = "$InstallDir\venv\Scripts\python.exe"
    $runPy         = "$InstallDir\run.py"
    $logsDir       = "$InstallDir\logs"

    # Créer le dossier logs si absent
    if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Force -Path $logsDir | Out-Null }

    # Supprimer le service existant
    $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log "Service existant détecté — mise à jour..." "WARNING"
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & $NssmPath remove $serviceName confirm
        Start-Sleep -Seconds 2
    }

    Write-Log "Installation du service Windows..."

    & $NssmPath install $serviceName $pythonExe $runPy
    & $NssmPath set $serviceName AppDirectory    $InstallDir
    & $NssmPath set $serviceName DisplayName     $serviceDisplay
    & $NssmPath set $serviceName Description     "Interface Web pour Microsoft Active Directory"
    & $NssmPath set $serviceName Start           SERVICE_AUTO_START
    & $NssmPath set $serviceName AppStdout       "$logsDir\service.log"
    & $NssmPath set $serviceName AppStderr       "$logsDir\service_error.log"
    & $NssmPath set $serviceName AppRotateFiles  1
    & $NssmPath set $serviceName AppRotateBytes  10485760
    & $NssmPath set $serviceName AppExit         Default Restart
    & $NssmPath set $serviceName AppRestartDelay 5000

    # Support MD4/NTLM pour Python 3.12+
    $opensslConf = "$InstallDir\openssl_legacy.cnf"
    if (Test-Path $opensslConf) {
        & $NssmPath set $serviceName AppEnvironmentExtra "OPENSSL_CONF=$opensslConf"
        Write-Log "Configuration MD4/NTLM activée" "SUCCESS"
    }

    # Pare-feu
    Write-Log "Ouverture du port $Port dans le pare-feu..."
    netsh advfirewall firewall delete rule name="AD Web Interface" | Out-Null
    netsh advfirewall firewall add rule name="AD Web Interface" dir=in action=allow protocol=TCP localport=$Port | Out-Null
    Write-Log "Pare-feu configuré" "SUCCESS"

    # Démarrage
    Write-Log "Démarrage du service..."
    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5

    $status = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($status -and $status.Status -eq "Running") {
        Write-Log "Service démarré avec succès" "SUCCESS"
        return $true
    }
    else {
        Write-Log "Le service n'a pas démarré — consultez $logsDir\service_error.log" "ERROR"
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
    catch { return "localhost" }
}

# ============================================================================
# SCRIPT PRINCIPAL
# ============================================================================

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  INSTALLATION AUTONOME - AD WEB INTERFACE" -ForegroundColor Cyan
Write-Host "  Pour contrôleur de domaine Windows Server" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

# Droits administrateur
if (-not (Test-Administrator)) {
    Write-Log "Droits administrateur requis !" "ERROR"
    Write-Log "Faites un clic droit → Exécuter en tant qu'administrateur" "ERROR"
    pause
    exit 1
}
Write-Log "Droits administrateur confirmés" "SUCCESS"

# Vérification DC (non bloquant)
Test-DomainController

# Résolution de la version
if (-not $Version -or $Version -eq "") {
    $Version = Get-LatestVersion
    if (-not $Version) {
        Write-Log "Impossible de déterminer la version. Spécifiez -Version manuellement." "ERROR"
        pause
        exit 1
    }
}

# Téléchargement et décompression de l'application
$downloaded = Download-Application -TargetVersion $Version
if (-not $downloaded) {
    Write-Log "Échec du téléchargement de l'application" "ERROR"
    pause
    exit 1
}

Set-Location $InstallDir

# Python
$pythonCmd = Install-Python
if (-not $pythonCmd) {
    Write-Log "Impossible d'installer Python" "ERROR"
    pause
    exit 1
}

# Environnement virtuel
Write-Log "Création de l'environnement virtuel..."
& $pythonCmd -m venv "$InstallDir\venv"
$venvPython = "$InstallDir\venv\Scripts\python.exe"

# Dépendances
Write-Log "Installation des dépendances Python..."
$reqFile = "$InstallDir\requirements.txt"
if (Test-Path $reqFile) {
    & $venvPython -m pip install -r $reqFile -q --disable-pip-version-check
    Write-Log "Dépendances installées" "SUCCESS"
}
else {
    Write-Log "requirements.txt introuvable — installation incomplète" "ERROR"
    pause
    exit 1
}

# Fichier .env
New-EnvFile

# Dossier logs
$logsDir = "$InstallDir\logs"
if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Force -Path $logsDir | Out-Null }

# NSSM
$nssmPath = Install-NSSM
if (-not $nssmPath) {
    Write-Log "Impossible d'installer NSSM" "ERROR"
    pause
    exit 1
}

# Service Windows
$serviceOk = Install-Service -PythonCmd $pythonCmd -NssmPath $nssmPath

# ============================================================================
# RÉSUMÉ FINAL
# ============================================================================

Write-Host ""
if ($serviceOk) {
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host "  INSTALLATION TERMINÉE AVEC SUCCÈS  (v$Version)" -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Green
}
else {
    Write-Host "=================================================================" -ForegroundColor Yellow
    Write-Host "  INSTALLATION TERMINÉE AVEC AVERTISSEMENTS  (v$Version)" -ForegroundColor Yellow
    Write-Host "  Le service n'a pas démarré — vérifiez les logs." -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow
}

$localIP = Get-LocalIP

Write-Host ""
Write-Host "  Dossier          : $InstallDir" -ForegroundColor White
Write-Host "  Nom du service   : ADWebInterface" -ForegroundColor White
Write-Host "  Accès local      : http://localhost:$Port" -ForegroundColor Cyan
Write-Host "  Accès réseau     : http://$localIP`:$Port" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Logs             : $InstallDir\logs\" -ForegroundColor Gray
Write-Host "  Configuration    : $InstallDir\.env" -ForegroundColor Gray
Write-Host ""
Write-Host "  Commandes utiles :" -ForegroundColor White
Write-Host "    Get-Service ADWebInterface" -ForegroundColor Gray
Write-Host "    Start-Service ADWebInterface" -ForegroundColor Gray
Write-Host "    Stop-Service  ADWebInterface" -ForegroundColor Gray
Write-Host ""

if ($serviceOk) {
    Write-Log "Ouverture du navigateur..."
    Start-Process "http://localhost:$Port"
}

Write-Host "Appuyez sur une touche pour quitter..." -ForegroundColor Gray
pause | Out-Null
