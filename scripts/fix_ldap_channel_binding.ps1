# fix_ldap_channel_binding.ps1
# Corrige les restrictions LDAP sur Windows Server 2025
# Permet les connexions NTLM sur port 389 en attendant LDAPS
# Executer en tant qu'Administrateur

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Correction LDAP - Channel Binding / Signing" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Detection de la version Windows
$osInfo = Get-CimInstance Win32_OperatingSystem
$osName = $osInfo.Caption
$buildNumber = $osInfo.BuildNumber

Write-Host "Systeme detecte : $osName (Build $buildNumber)" -ForegroundColor Green
Write-Host ""

if ($buildNumber -lt 20348) {
    Write-Host "[INFO] Ce serveur n'a pas les restrictions Server 2025." -ForegroundColor Yellow
    Write-Host "Aucune action necessaire." -ForegroundColor Green
    exit 0
}

# 2. Lecture des valeurs actuelles
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"

Write-Host "[1/4] Lecture des parametres LDAP actuels..." -ForegroundColor Yellow

# LdapServerIntegrity : 0=Aucun, 1=Negocier, 2=Exiger (defaut 2025)
$integrityKey = "LdapServerIntegrity"
$integrityCurrent = Get-ItemProperty -Path $regPath -Name $integrityKey -ErrorAction SilentlyContinue

if ($integrityCurrent) {
    $integrityVal = $integrityCurrent.$integrityKey
    Write-Host "  LdapServerIntegrity = $integrityVal" -ForegroundColor Gray
} else {
    $integrityVal = 2  # Defaut Server 2025 = Exiger
    Write-Host "  LdapServerIntegrity = $integrityVal (par defaut)" -ForegroundColor Gray
}

# LdapEnforceChannelBinding : 0=Jamais, 1=Si supporte, 2=Toujours (defaut 2025)
$cbKey = "LdapEnforceChannelBinding"
$cbCurrent = Get-ItemProperty -Path $regPath -Name $cbKey -ErrorAction SilentlyContinue

if ($cbCurrent) {
    $cbVal = $cbCurrent.$cbKey
    Write-Host "  LdapEnforceChannelBinding = $cbVal" -ForegroundColor Gray
} else {
    $cbVal = 2  # Defaut Server 2025 = Toujours
    Write-Host "  LdapEnforceChannelBinding = $cbVal (par defaut)" -ForegroundColor Gray
}
Write-Host ""

# 3. Verification si modification necessaire
if ($integrityVal -le 1 -and $cbVal -le 1) {
    Write-Host "[INFO] Les parametres sont deja corrects. Aucune action." -ForegroundColor Green
    exit 0
}

Write-Host "[2/4] Application des corrections..." -ForegroundColor Yellow

# LdapServerIntegrity = 1 (Negocier le signing au lieu de l'exiger)
Set-ItemProperty -Path $regPath -Name $integrityKey -Value 1 -Type DWord -Force
Write-Host "  OK LdapServerIntegrity = 1 (Negocier)" -ForegroundColor Green

# LdapEnforceChannelBinding = 0 (Ne pas exiger le channel binding)
Set-ItemProperty -Path $regPath -Name $cbKey -Value 0 -Type DWord -Force
Write-Host "  OK LdapEnforceChannelBinding = 0 (Non exige)" -ForegroundColor Green

Write-Host ""

# 4. Redemarrer le service NTDS
Write-Host "[3/4] Redemarrage du service NTDS..." -ForegroundColor Yellow
try {
    Restart-Service -Name NTDS -Force -ErrorAction Stop
    Write-Host "  OK Service NTDS redemarre" -ForegroundColor Green
} catch {
    Write-Host "  [ATTENTION] Impossible de redemarrer NTDS: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  Redemarrez manuellement le service 'Active Directory Domain Services'" -ForegroundColor Yellow
}

Start-Sleep -Seconds 5

# 5. Verification
Write-Host "[4/4] Verification..." -ForegroundColor Yellow

$newIntegrity = (Get-ItemProperty -Path $regPath -Name $integrityKey -ErrorAction SilentlyContinue).$integrityKey
$newCb = (Get-ItemProperty -Path $regPath -Name $cbKey -ErrorAction SilentlyContinue).$cbKey

if ($newIntegrity -eq 1 -and $newCb -eq 0) {
    Write-Host "  OK Corrections appliquees avec succes !" -ForegroundColor Green
    Write-Host "SUCCESS"
} else {
    Write-Host "  [ERREUR] Verification inattendue : Integrity=$newIntegrity, CB=$newCb" -ForegroundColor Red
    Write-Host "PARTIAL"
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  CONFIGURATION TERMINEE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Les connexions NTLM sur port 389 sont maintenant autorisees." -ForegroundColor Cyan
Write-Host ""
Write-Host "RECOMMANDATION : Activez LDAPS (port 636) pour une securite maximale." -ForegroundColor Yellow
Write-Host "  Bouton 'Activer LDAPS automatiquement' sur /users/create" -ForegroundColor Yellow
Write-Host ""
