# ============================================================================
# CONFIGURATION DU SERVICE ADWEBINTERFACE - SUPPORT MD4/NTLM
# ============================================================================
# Ce script configure le service Windows pour utiliser openssl_legacy.cnf
# Nécessaire pour Python 3.12+ qui ne supporte plus MD4 par défaut
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Chemin vers le dossier d'installation")]
    [string]$InstallDir = "C:\AD-Web\microsoft-active-directory"
)

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  CONFIGURATION DU SERVICE AD WEB INTERFACE" -ForegroundColor Cyan
Write-Host "  Activation du support MD4/NTLM pour Python 3.12+" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Vérifier les droits administrateur
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERREUR] Droits administrateur requis !" -ForegroundColor Red
    Write-Host "Faites un clic droit → Exécuter en tant qu'administrateur" -ForegroundColor Red
    pause
    exit 1
}
Write-Host "[OK] Droits administrateur confirmés" -ForegroundColor Green

# 2. Vérifier le dossier d'installation
if (-not (Test-Path $InstallDir)) {
    Write-Host "[ERREUR] Dossier introuvable : $InstallDir" -ForegroundColor Red
    Write-Host "Modifiez le script avec le bon chemin." -ForegroundColor Red
    pause
    exit 1
}

Set-Location $InstallDir
Write-Host "[OK] Dossier : $InstallDir" -ForegroundColor Green

# 3. Créer openssl_legacy.cnf s'il n'existe pas
$opensslConf = Join-Path $InstallDir "openssl_legacy.cnf"
if (-not (Test-Path $opensslConf)) {
    Write-Host "[INFO] Création de openssl_legacy.cnf..." -ForegroundColor Yellow
    
    @'
openssl_conf = openssl_init

[openssl_init]
providers = providers_sect

[providers_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
'@ | Out-File -FilePath $opensslConf -Encoding ASCII
    
    Write-Host "[OK] Fichier créé : $opensslConf" -ForegroundColor Green
} else {
    Write-Host "[OK] Fichier existant : $opensslConf" -ForegroundColor Green
}

# 4. Vérifier NSSM
$nssmPath = Join-Path $InstallDir "nssm\nssm.exe"
if (Test-Path $nssmPath) {
    Write-Host "[OK] NSSM trouvé : $nssmPath" -ForegroundColor Green
} else {
    # Chercher NSSM dans le PATH
    $nssmPath = Get-Command nssm.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source
    if ($nssmPath) {
        Write-Host "[OK] NSSM trouvé dans le PATH : $nssmPath" -ForegroundColor Green
    } else {
        Write-Host "[ERREUR] NSSM introuvable !" -ForegroundColor Red
        Write-Host "Le service a été installé comment ?" -ForegroundColor Red
        pause
        exit 1
    }
}

# 5. Vérifier le service
$serviceName = "ADWebInterface"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Host "[ERREUR] Service '$serviceName' introuvable !" -ForegroundColor Red
    Write-Host "Le service n'a pas été installé." -ForegroundColor Red
    Write-Host "Exécutez d'abord : .\install_ad.ps1" -ForegroundColor Red
    pause
    exit 1
}
Write-Host "[OK] Service trouvé : $serviceName" -ForegroundColor Green

# 6. Configurer OPENSSL_CONF
Write-Host ""
Write-Host "[INFO] Configuration de OPENSSL_CONF..." -ForegroundColor Yellow

# Arrêter le service
Write-Host "Arrêt du service..." -ForegroundColor Yellow
Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Configurer la variable d'environnement
Write-Host "Configuration de OPENSSL_CONF=$opensslConf" -ForegroundColor Yellow
& $nssmPath set $serviceName AppEnvironmentExtra "OPENSSL_CONF=$opensslConf"

if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] OPENSSL_CONF configuré avec succès" -ForegroundColor Green
} else {
    Write-Host "[ERREUR] Échec de la configuration OPENSSL_CONF" -ForegroundColor Red
    Write-Host "Code d'erreur : $LASTEXITCODE" -ForegroundColor Red
    pause
    exit 1
}

# 7. Redémarrer le service
Write-Host ""
Write-Host "Démarrage du service..." -ForegroundColor Yellow
Start-Service -Name $serviceName

Start-Sleep -Seconds 3
$serviceStatus = Get-Service -Name $serviceName
if ($serviceStatus.Status -eq "Running") {
    Write-Host "[OK] Service démarré avec succès" -ForegroundColor Green
} else {
    Write-Host "[ERREUR] Échec démarrage du service" -ForegroundColor Red
    Write-Host "Statut : $($serviceStatus.Status)" -ForegroundColor Red
}

# 8. Vérification
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  CONFIGURATION TERMINÉE" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Le service ADWebInterface est maintenant configuré avec :" -ForegroundColor White
Write-Host "  OPENSSL_CONF=$opensslConf" -ForegroundColor Cyan
Write-Host ""
Write-Host "Le support MD4/NTLM est activé pour Python 3.12+" -ForegroundColor Green
Write-Host ""
Write-Host "Testez la connexion :" -ForegroundColor White
Write-Host "  http://localhost:5000/connect" -ForegroundColor Cyan
Write-Host ""
Write-Host "En cas de problème, consultez les logs :" -ForegroundColor White
Write-Host "  $InstallDir\logs\service.log" -ForegroundColor Cyan
Write-Host "  $InstallDir\logs\service_error.log" -ForegroundColor Cyan
Write-Host ""

pause
