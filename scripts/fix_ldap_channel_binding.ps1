# fix_ldap_channel_binding.ps1
# Active LDAPS (port 636) et corrige les restrictions LDAP sur Windows Server 2022/2025
# - Detecte ou cree un certificat SSL pour le DC
# - Configure NTDS pour utiliser le certificat
# - Corrige le channel binding / signing si necessaire
# - Redemarre NTDS et verifie le port 636
# Executer en tant qu'Administrateur

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Activation LDAPS + Correction LDAP" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ──────────────────────────────────────────────────────────────────
# 1. Detection du systeme
# ──────────────────────────────────────────────────────────────────
Write-Host "[1/6] Detection du systeme..." -ForegroundColor Yellow

$osInfo = Get-CimInstance Win32_OperatingSystem
$osName = $osInfo.Caption
$buildNumber = $osInfo.BuildNumber
Write-Host "  Systeme : $osName (Build $buildNumber)" -ForegroundColor Gray

# Detecter le FQDN du DC et le domaine
$computerName = $env:COMPUTERNAME
$fqdn = [System.Net.Dns]::GetHostEntry($computerName).HostName
Write-Host "  FQDN    : $fqdn" -ForegroundColor Gray

# Extraire le domaine depuis le FQDN (ex: dc01.selest.local -> selest.local)
$domain = ""
if ($fqdn -match "\.(.+)$") {
    $domain = $Matches[1]
}
if (-not $domain) {
    # Fallback: utiliser la commande AD
    try {
        $domain = (Get-ADDomain -ErrorAction SilentlyContinue).DNSRoot
    } catch {
        # Dernier recours: variable d'environnement
        $domain = $env:USERDNSDOMAIN
    }
}

Write-Host "  Domaine : $domain" -ForegroundColor Gray
Write-Host ""

# ──────────────────────────────────────────────────────────────────
# 2. Certificat SSL
# ──────────────────────────────────────────────────────────────────
Write-Host "[2/6] Recherche d'un certificat SSL valide..." -ForegroundColor Yellow

$cert = $null

# Chercher un certificat existant : domaine match + cle privee + non expire + Server Auth
$certs = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
    $_.HasPrivateKey -and
    $_.NotAfter -gt (Get-Date) -and
    ($_.Subject -like "*$fqdn*" -or $_.Subject -like "*$domain*" -or
     ($_.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" } |
      ForEach-Object { $_.Format($false) }) -like "*$fqdn*")
}

if ($certs) {
    $cert = $certs | Sort-Object NotAfter -Descending | Select-Object -First 1
    Write-Host "  [OK] Certificat existant trouve" -ForegroundColor Green
    Write-Host "    Subject    : $($cert.Subject)" -ForegroundColor Gray
    Write-Host "    Thumbprint : $($cert.Thumbprint)" -ForegroundColor Gray
    Write-Host "    Expire     : $($cert.NotAfter)" -ForegroundColor Gray
} else {
    Write-Host "  Aucun certificat valide trouve, creation d'un certificat auto-signe..." -ForegroundColor Yellow

    try {
        $dnsNames = @($fqdn, $computerName, "localhost")
        if ($domain) { $dnsNames += $domain }

        $cert = New-SelfSignedCertificate `
            -DnsName $dnsNames `
            -CertStoreLocation "Cert:\LocalMachine\My" `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -KeyExportPolicy Exportable `
            -KeyUsage DigitalSignature, KeyEncipherment `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
            -NotAfter (Get-Date).AddYears(10) `
            -Subject "CN=$fqdn" `
            -FriendlyName "LDAPS - $fqdn"

        Write-Host "  [OK] Certificat auto-signe cree" -ForegroundColor Green
        Write-Host "    Subject    : CN=$fqdn" -ForegroundColor Gray
        Write-Host "    Thumbprint : $($cert.Thumbprint)" -ForegroundColor Gray
        Write-Host "    Expire     : $($cert.NotAfter)" -ForegroundColor Gray
        Write-Host "    DNS Names  : $($dnsNames -join ', ')" -ForegroundColor Gray
    } catch {
        Write-Host "  [ERREUR] Impossible de creer le certificat: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "NO_CERT"
        exit 1
    }
}
Write-Host ""

# ──────────────────────────────────────────────────────────────────
# 3. Ajouter au magasin Root si auto-signe (pour trust local)
# ──────────────────────────────────────────────────────────────────
Write-Host "[3/6] Verification du magasin de confiance (Root)..." -ForegroundColor Yellow

$rootCert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
if (-not $rootCert) {
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        $store.Open("ReadWrite")
        $store.Add($cert)
        $store.Close()
        Write-Host "  [OK] Certificat ajoute au magasin Root (confiance locale)" -ForegroundColor Green
    } catch {
        Write-Host "  [ATTENTION] Impossible d'ajouter au Root: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [OK] Certificat deja present dans Root" -ForegroundColor Green
}
Write-Host ""

# ──────────────────────────────────────────────────────────────────
# 4. Configuration NTDS avec le certificat
# ──────────────────────────────────────────────────────────────────
Write-Host "[4/6] Configuration du mapping certificat NTDS..." -ForegroundColor Yellow

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\CertMapping"
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Directory -Force | Out-Null
    Write-Host "  Cle de registre creee" -ForegroundColor Gray
}

$itemPath = "$registryPath\1"
if (-not (Test-Path $itemPath)) {
    New-Item -Path $registryPath -Name "1" -Force | Out-Null
}
New-ItemProperty -Path $itemPath -Name "Subject" -Value $cert.Subject -PropertyType String -Force | Out-Null
New-ItemProperty -Path $itemPath -Name "Thumbprint" -Value $cert.Thumbprint -PropertyType String -Force | Out-Null
New-ItemProperty -Path $itemPath -Name "MappingType" -Value 7 -PropertyType DWord -Force | Out-Null

Write-Host "  [OK] Mapping certificat configure (Thumbprint: $($cert.Thumbprint))" -ForegroundColor Green
Write-Host ""

# ──────────────────────────────────────────────────────────────────
# 5. Correction Channel Binding / Signing (Server 2022+)
# ──────────────────────────────────────────────────────────────────
Write-Host "[5/6] Correction Channel Binding / Signing..." -ForegroundColor Yellow

$ntdsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"

if ($buildNumber -ge 20348) {
    $integrityKey = "LdapServerIntegrity"
    $cbKey = "LdapEnforceChannelBinding"

    $integrityVal = (Get-ItemProperty -Path $ntdsRegPath -Name $integrityKey -ErrorAction SilentlyContinue).$integrityKey
    $cbVal = (Get-ItemProperty -Path $ntdsRegPath -Name $cbKey -ErrorAction SilentlyContinue).$cbKey

    # Valeurs par defaut Server 2025 = 2 (exiger)
    if ($null -eq $integrityVal) { $integrityVal = 2 }
    if ($null -eq $cbVal) { $cbVal = 2 }

    if ($integrityVal -le 1 -and $cbVal -le 1) {
        Write-Host "  [OK] Parametres deja corrects (Integrity=$integrityVal, CB=$cbVal)" -ForegroundColor Green
    } else {
        Set-ItemProperty -Path $ntdsRegPath -Name $integrityKey -Value 1 -Type DWord -Force
        Write-Host "  [OK] LdapServerIntegrity = 1 (Negocier)" -ForegroundColor Green

        Set-ItemProperty -Path $ntdsRegPath -Name $cbKey -Value 0 -Type DWord -Force
        Write-Host "  [OK] LdapEnforceChannelBinding = 0 (Non exige)" -ForegroundColor Green
    }
} else {
    Write-Host "  [INFO] Build $buildNumber < 20348, pas de restriction a corriger" -ForegroundColor Gray
}
Write-Host ""

# ──────────────────────────────────────────────────────────────────
# 6. Redemarrage NTDS et verification port 636
# ──────────────────────────────────────────────────────────────────
Write-Host "[6/6] Redemarrage du service NTDS..." -ForegroundColor Yellow
try {
    Restart-Service -Name NTDS -Force -ErrorAction Stop
    Write-Host "  [OK] Service NTDS redemarre" -ForegroundColor Green
} catch {
    Write-Host "  [ATTENTION] Impossible de redemarrer NTDS: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  Redemarrez manuellement le service 'Active Directory Domain Services'" -ForegroundColor Yellow
}

Write-Host "  Attente 10 secondes..." -ForegroundColor Gray
Start-Sleep -Seconds 10

Write-Host ""
Write-Host "Verification du port LDAPS (636)..." -ForegroundColor Yellow
Start-Sleep -Seconds 2
$test = Test-NetConnection -ComputerName localhost -Port 636 -WarningAction SilentlyContinue
if ($test.TcpTestSucceeded) {
    Write-Host "  [OK] Port 636 (LDAPS) ouvert et fonctionnel !" -ForegroundColor Green
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  LDAPS ACTIVE AVEC SUCCES" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Certificat : $($cert.Subject)" -ForegroundColor White
    Write-Host "Thumbprint : $($cert.Thumbprint)" -ForegroundColor White
    Write-Host "Port       : 636 (LDAPS)" -ForegroundColor White
    Write-Host ""
    Write-Host "Reconnectez-vous a AD Web Interface avec :" -ForegroundColor Yellow
    Write-Host "  - Port : 636" -ForegroundColor White
    Write-Host "  - SSL/TLS : Coche" -ForegroundColor White
    Write-Host ""
    Write-Host "SUCCESS"
} else {
    Write-Host "  [ATTENTION] Port 636 non detecte immediatement." -ForegroundColor Yellow
    Write-Host "  Le service peut necesiter quelques secondes supplementaires." -ForegroundColor Yellow
    Write-Host "  Reessayez dans 30 secondes ou redemarrez AD DS." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "PARTIAL"
}
