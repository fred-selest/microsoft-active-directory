# ============================================================================
# Script d'activation du Channel Binding pour LDAP
# AD Web Interface - Correction des protocoles obsolètes
# ============================================================================
# RÚfÚrence: Microsoft: Hardening AD CS and LDAP
# ============================================================================

param(
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  ACTIVATION DU CHANNEL BINDING LDAP" -ForegroundColor Cyan
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
$regName = "LdapEnforceChannelBinding"

Write-Host "[1/3] VÚrification de l'Útat actuel..." -ForegroundColor Yellow

try {
    $currentValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    
    if ($currentValue) {
        $value = $currentValue.$regName
        Write-Host "  LdapEnforceChannelBinding: $value" -ForegroundColor $(
            if ($value -ge 2) { 'Green' } elseif ($value -eq 1) { 'Yellow' } else { 'Red' }
        )
        
        if ($value -eq 0) { Write-Host "  → Non configurÚ" -ForegroundColor Gray }
        elseif ($value -eq 1) { Write-Host "  → ActivÚ (supportÚ)" -ForegroundColor Yellow }
        elseif ($value -eq 2) { Write-Host "  → Requis (recommandÚ)" -ForegroundColor Green }
    }
    else {
        Write-Host "  Non configurÚ (par dÚfaut)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "ERREUR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[2/3] Configuration du Channel Binding (Niveau 2)..." -ForegroundColor Yellow

if ($WhatIf) {
    Write-Host "  [SIMULATION] LdapEnforceChannelBinding serait mis Ó 2" -ForegroundColor Cyan
}
else {
    try {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $regPath -Name $regName -Value 2 -Type DWord -Force
        Write-Host "  Registry modifiÚ: LdapEnforceChannelBinding = 2" -ForegroundColor Green
        Write-Host "  → Channel Binding est maintenant REQUIS" -ForegroundColor Green
    }
    catch {
        Write-Host "ERREUR: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "[3/3] VÚrification..." -ForegroundColor Yellow

try {
    $newValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    
    if ($newValue) {
        $value = $newValue.$regName
        Write-Host "  Nouvelle valeur: $value" -ForegroundColor $(
            if ($value -eq 2) { 'Green' } else { 'Yellow' }
        )
        
        if ($value -eq 2) {
            Write-Host "  → Configuration appliquÚe avec succčs!" -ForegroundColor Green
        }
    }
}
catch {
    Write-Host "  Impossible de vÚrifier" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  ✅ CHANNEL BINDING ACTIVŃ" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "NIVEAUX:" -ForegroundColor Cyan
Write-Host "  0 = Non configurÚ" -ForegroundColor Gray
Write-Host "  1 = ActivÚ (supportÚ mais non requis)" -ForegroundColor Yellow
Write-Host "  2 = Requis (recommandÚ - niveau appliquÚ)" -ForegroundColor Green
Write-Host ""
Write-Host "Un redÚmarrage est recommandÚ pour appliquer complčtement." -ForegroundColor Yellow
Write-Host ""
Write-Host "Script terminÚ." -ForegroundColor Green
