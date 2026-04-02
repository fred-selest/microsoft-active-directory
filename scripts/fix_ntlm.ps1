# ============================================================================
# Script de durcissement NTLM (DÚsactiver LM et NTLMv1)
# AD Web Interface - Correction des protocoles obsolètes
# ============================================================================
# RÚfÚrence: ANSSI - Authentification NTLM
# ============================================================================

param(
    [switch]$WhatIf  # Mode simulation
)

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  DURCISSEMENT NTLM - Niveau 5" -ForegroundColor Cyan
Write-Host "  (Refuser LM et NTLMv1)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# VÚrifier les privilčges administrateur
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( `
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERREUR: Ce script doit ŕtre exÚcutÚ en tant qu'administrateur" -ForegroundColor Red
    exit 1
}

Write-Host "[1/4] VÚrification du niveau NTLM actuel..." -ForegroundColor Yellow

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lmLevelName = "LmCompatibilityLevel"

try {
    $currentLevel = Get-ItemProperty -Path $regPath -Name $lmLevelName -ErrorAction SilentlyContinue
    
    if ($currentLevel) {
        $levelValue = $currentLevel.$lmLevelName
        Write-Host "  Niveau actuel: $levelValue" -ForegroundColor $(
            if ($levelValue -ge 5) { 'Green' } elseif ($levelValue -ge 3) { 'Yellow' } else { 'Red' }
        )
        
        $levelNames = @{
            0 = "0 - LM et NTLMv1 autorisÚs"
            1 = "1 - NTLMv2 avec session sÚcurisÚe"
            2 = "2 - NTLMv2 seulement"
            3 = "3 - NTLMv2 seulement (audit)"
            4 = "4 - Refuser LM"
            5 = "5 - Refuser LM et NTLMv1 (RecommandÚ)"
        }
        
        Write-Host "  Description: $($levelNames[$levelValue])" -ForegroundColor Gray
    }
    else {
        Write-Host "  Niveau: Non configurÚ (par dÚfaut)" -ForegroundColor Yellow
        $levelValue = 0
    }
}
catch {
    Write-Host "ERREUR lors de la vÚrification: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ($levelValue -ge 5) {
    Write-Host ""
    Write-Host "SUCCÉS: Le niveau NTLM est dÚjÓ Ó 5!" -ForegroundColor Green
    Write-Host "Aucune action nÚcessaire." -ForegroundColor Gray
    exit 0
}

Write-Host ""
Write-Host "[2/4] Application du niveau 5 (Refuser LM et NTLMv1)..." -ForegroundColor Yellow

if ($WhatIf) {
    Write-Host "  [SIMULATION] LmCompatibilityLevel serait mis Ó 5" -ForegroundColor Cyan
}
else {
    try {
        Set-ItemProperty -Path $regPath -Name $lmLevelName -Value 5 -Type DWord -Force
        Write-Host "  Registry modifiÚ avec succčs" -ForegroundColor Green
    }
    catch {
        Write-Host "ERREUR lors de la modification: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "[3/4] Configuration de la stratÚgie de sÚcuritÚ locale..." -ForegroundColor Yellow

if ($WhatIf) {
    Write-Host "  [SIMULATION] StratÚgies de sÚcuritÚ seraient mises Ó jour" -ForegroundColor Cyan
}
else {
    # Utiliser secedit pour appliquer les changements de stratÚgie
    $tempInf = "$env:TEMP\ntlm_security.inf"
    $tempSdb = "$env:TEMP\ntlm_security.sdb"
    
    $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature=`$Chicago`$
Revision=1
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=5
"@
    
    try {
        Set-Content -Path $tempInf -Value $infContent -Force
        Write-Host "  Fichier de configuration crÚÚ" -ForegroundColor Green
        
        # Appliquer la stratÚgie
        secedit /configure /db $tempSdb /cfg $tempInf /areas SECURITYPOLICY /quiet | Out-Null
        Write-Host "  StratÚgie de sÚcuritÚ appliquÚe" -ForegroundColor Green
        
        # Nettoyer
        Remove-Item $tempInf -Force -ErrorAction SilentlyContinue
        Remove-Item $tempSdb -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Attention: Impossible d'appliquer via secedit" -ForegroundColor Yellow
        Write-Host "  Le registry a ÚtÚ modifiÚ, un redÚmarrage appliquera les changements" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "[4/4] VÚrification finale..." -ForegroundColor Yellow

try {
    $newLevel = Get-ItemProperty -Path $regPath -Name $lmLevelName -ErrorAction SilentlyContinue
    
    if ($newLevel) {
        $newValue = $newLevel.$lmLevelName
        Write-Host "  Nouveau niveau: $newValue" -ForegroundColor $(
            if ($newValue -eq 5) { 'Green' } else { 'Yellow' }
        )
        
        if ($newValue -eq 5) {
            Write-Host "  Configuration appliquÚe avec succčs!" -ForegroundColor Green
        }
        else {
            Write-Host "  Attention: Le niveau n'est pas Ó 5. Un redÚmarrage peut ŕtre nÚcessaire." -ForegroundColor Yellow
        }
    }
}
catch {
    Write-Host "  Impossible de vÚrifier le niveau final" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan

if (-not $WhatIf) {
    Write-Host "  ⚠️  REDÚMARRAGE RECOMMANDŃ" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Les changements de niveau NTLM nÚcessitent un redÚmarrage" -ForegroundColor White
    Write-Host "pour ŕtre pleinement effectifs sur tous les services." -ForegroundColor White
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
        Write-Host "Conseil: Planifiez un redÚmarrage lors de la prochaine maintenance." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "En attendant, certains services peuvent encore accepter LM/NTLMv1." -ForegroundColor Yellow
    }
}
else {
    Write-Host ""
    Write-Host "Mode simulation terminÚ. ExÚcutez sans -WhatIf pour appliquer." -ForegroundColor Cyan
}

Write-Host ""
Write-Host "RÚFŃRENCES:" -ForegroundColor Cyan
Write-Host "  - ANSSI: Recommandations de sÚcuritÚ relatives Ó l'authentification" -ForegroundColor Gray
Write-Host "  - Microsoft: Security baseline for NTLM" -ForegroundColor Gray
Write-Host ""
Write-Host "Script terminÚ." -ForegroundColor Green
Write-Host ""
