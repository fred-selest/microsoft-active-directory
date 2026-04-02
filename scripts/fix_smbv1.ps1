# ============================================================================
# Script de désactivation de SMBv1
# AD Web Interface - Correction des protocoles obsolètes
# ============================================================================
# Référence: ANSSI - Vulnérabilités critiques SMBv1 (WannaCry, NotPetya)
# ============================================================================

param(
    [switch]$WhatIf  # Mode simulation (ne fait pas les changements)
)

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  DÚSACTIVATION DE SMBv1" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier les privilčges administrateur
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( `
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERREUR: Ce script doit ŕtre exÚcutÚ en tant qu'administrateur" -ForegroundColor Red
    Write-Host "Conseil: Clic droit → ExÚcuter en tant qu'administrateur" -ForegroundColor Yellow
    exit 1
}

Write-Host "[1/4] VÚrification de l'Útat actuel de SMBv1..." -ForegroundColor Yellow

try {
    $smbStatus = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    
    Write-Host "  Útat actuel: $($smbStatus.State)" -ForegroundColor $(
        if ($smbStatus.State -eq 'Enabled') { 'Red' } else { 'Green' }
    )
    
    if ($smbStatus.State -eq 'Disabled') {
        Write-Host ""
        Write-Host "SUCCÉS: SMBv1 est dÚjÓ dÚsactivÚ!" -ForegroundColor Green
        Write-Host "Aucune action nÚcessaire." -ForegroundColor Gray
        exit 0
    }
}
catch {
    Write-Host "ERREUR lors de la vÚrification: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[2/4] DÚsactivation de SMBv1..." -ForegroundColor Yellow

if ($WhatIf) {
    Write-Host "  [SIMULATION] SMBv1 serait dÚsactivÚ" -ForegroundColor Cyan
}
else {
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
        Write-Host "  SMBv1 dÚsactivÚ avec succčs" -ForegroundColor Green
    }
    catch {
        Write-Host "ERREUR lors de la dÚsactivation: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "[3/4] VÚrification des composants SMBv1 supplÚmentaires..." -ForegroundColor Yellow

$smbFeatures = @(
    'SMB1ProtocolClient',
    'SMB1ProtocolServer'
)

foreach ($feature in $smbFeatures) {
    try {
        $featureStatus = Get-WindowsOptionalFeature -Online -FeatureName $feature
        
        if ($featureStatus.State -eq 'Enabled') {
            Write-Host "  $feature : $($featureStatus.State) - DÚsactivation..." -ForegroundColor Yellow
            
            if (-not $WhatIf) {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart | Out-Null
                Write-Host "    → DÚsactivÚ" -ForegroundColor Green
            }
        }
        else {
            Write-Host "  $feature : $($featureStatus.State) - DÚjÓ dÚsactivÚ" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  $feature : Non trouvÚ (ignorÚ)" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "[4/4] RÚsumÚ de l'opération..." -ForegroundColor Yellow

try {
    $finalStatus = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    Write-Host "  Útat final de SMBv1: $($finalStatus.State)" -ForegroundColor $(
        if ($finalStatus.State -eq 'Disabled') { 'Green' } else { 'Yellow' }
    )
}
catch {
    Write-Host "  Impossible de vÚrifier l'Útat final" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan

if (-not $WhatIf) {
    Write-Host "  ⚠️  REDÚMARRAGE NŃCESSAIRE" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Un redÚmarrage est requis pour appliquer les changements." -ForegroundColor White
    Write-Host ""
    
    $restart = Read-Host "Voulez-vous redÚmarrer maintenant? (O/N)"
    
    if ($restart -eq 'O' -or $restart -eq 'o' -or $restart -eq 'Y' -or $restart -eq 'y') {
        Write-Host ""
        Write-Host "RedÚmarrage en cours dans 5 secondes..." -ForegroundColor Yellow
        Write-Host "Enregistrez votre travail!" -ForegroundColor Red
        Start-Sleep -Seconds 5
        Restart-Computer -Force
    }
    else {
        Write-Host ""
        Write-Host "Conseil: RedÚmarrez le serveur lors de la prochaine maintenance." -ForegroundColor Yellow
    }
}
else {
    Write-Host ""
    Write-Host "Mode simulation terminÚ. ExÚcutez sans -WhatIf pour appliquer." -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Script terminÚ." -ForegroundColor Green
Write-Host ""
