# ============================================================================
# Script d'activation du LDAP Signing
# AD Web Interface - Correction des protocoles obsolètes
# ============================================================================
# RÚfÚrence: ANSSI - Durcissement LDAP
# ============================================================================

param(
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  ACTIVATION DU LDAP SIGNING" -ForegroundColor Cyan
Write-Host "  (PrÚvention des attaques MITM)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( `
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERREUR: Administrateur requis" -ForegroundColor Red
    exit 1
}

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$regName = "LDAPServerIntegrity"

Write-Host "[1/3] VÚrification de l'Útat actuel..." -ForegroundColor Yellow

try {
    $currentValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    
    if ($currentValue) {
        $value = $currentValue.$regName
        Write-Host "  LDAPServerIntegrity: $value" -ForegroundColor $(
            if ($value -ge 2) { 'Green' } else { 'Yellow' }
        )
        
        if ($value -eq 0) { Write-Host "  → Non configurÚ (Signing autorisÚ)" -ForegroundColor Gray }
        elseif ($value -eq 1) { Write-Host "  → Signing autorisÚ (non requis)" -ForegroundColor Gray }
        elseif ($value -ge 2) { Write-Host "  → Signing requis" -ForegroundColor Green }
    }
    else {
        Write-Host "  Non configurÚ (par dÚfaut: Signing autorisÚ)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "ERREUR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[2/3] Configuration du LDAP Signing requis..." -ForegroundColor Yellow

if ($WhatIf) {
    Write-Host "  [SIMULATION] LDAPServerIntegrity serait mis Ó 2" -ForegroundColor Cyan
}
else {
    try {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $regPath -Name $regName -Value 2 -Type DWord -Force
        Write-Host "  Registry modifiÚ: LDAPServerIntegrity = 2" -ForegroundColor Green
        Write-Host "  → Le signing LDAP est maintenant REQUIS" -ForegroundColor Green
    }
    catch {
        Write-Host "ERREUR: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "[3/3] Application via stratÚgie de sÚcuritÚ..." -ForegroundColor Yellow

if ($WhatIf) {
    Write-Host "  [SIMULATION] StratÚgie serait appliquÚe" -ForegroundColor Cyan
}
else {
    $tempInf = "$env:TEMP\ldap_signing.inf"
    $tempSdb = "$env:TEMP\ldap_signing.sdb"
    
    $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature=`$Chicago`$
Revision=1
[Registry Values]
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=2
"@
    
    try {
        Set-Content -Path $tempInf -Value $infContent -Force
        secedit /configure /db $tempSdb /cfg $tempInf /areas SECURITYPOLICY /quiet | Out-Null
        Remove-Item $tempInf -Force -ErrorAction SilentlyContinue
        Remove-Item $tempSdb -Force -ErrorAction SilentlyContinue
        Write-Host "  StratÚgie appliquÚe" -ForegroundColor Green
    }
    catch {
        Write-Host "  Attention: secedit ÚchouÚ, le registry suffit" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  ✅ LDAP SIGNING ACTIVŃ" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Un redÚmarrage du contrŰleur de domaine est recommandÚ." -ForegroundColor Yellow
Write-Host ""
Write-Host "Script terminÚ." -ForegroundColor Green
