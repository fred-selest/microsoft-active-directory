#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Signe WinSW.exe avec un certificat de signature de code auto-signé approuvé localement.
    Élimine les popups SmartScreen/UAC à l'exécution de WinSW.
#>
$ErrorActionPreference = 'Stop'
$WinSWPath = 'C:\AD-WebInterface\nssm\WinSW.exe'
$LogPath   = 'C:\AD-WebInterface\logs\sign_winsw.log'

function Write-Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg"
    $line | Out-File -FilePath $LogPath -Append -Encoding UTF8
    Write-Output $line
}

Write-Log '=== Début signature WinSW.exe ==='

# ── 1. Créer le certificat dans LocalMachine\My ───────────────────────────────
Write-Log '[1/5] Création du certificat de signature de code...'
$cert = New-SelfSignedCertificate `
    -Subject       'CN=AD Web Interface Code Signing, O=SELEST, C=FR' `
    -CertStoreLocation 'Cert:\LocalMachine\My' `
    -KeyUsage      DigitalSignature `
    -Type          CodeSigningCert `
    -KeyAlgorithm  RSA `
    -KeyLength     4096 `
    -HashAlgorithm SHA256 `
    -NotAfter      (Get-Date).AddYears(10)

Write-Log "  Thumbprint : $($cert.Thumbprint)"
Write-Log "  Expiration : $($cert.NotAfter)"

# ── 2. Ajouter dans Trusted Root CA (LocalMachine) ───────────────────────────
Write-Log '[2/5] Ajout dans Trusted Root CA...'
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
)
$rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$rootStore.Add($cert)
$rootStore.Close()
Write-Log '  OK'

# ── 3. Ajouter dans Trusted Publishers (LocalMachine) ────────────────────────
Write-Log '[3/5] Ajout dans Trusted Publishers...'
$pubStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
)
$pubStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$pubStore.Add($cert)
$pubStore.Close()
Write-Log '  OK'

# ── 4. Signer WinSW.exe ───────────────────────────────────────────────────────
Write-Log '[4/5] Signature de WinSW.exe...'
try {
    $result = Set-AuthenticodeSignature `
        -FilePath        $WinSWPath `
        -Certificate     $cert `
        -TimestampServer 'http://timestamp.digicert.com' `
        -HashAlgorithm   SHA256
    Write-Log "  Status : $($result.Status)"
} catch {
    # Timestamp server peut être inaccessible — signer sans timestamp
    Write-Log "  Timestamp indisponible, signature sans timestamp..."
    $result = Set-AuthenticodeSignature `
        -FilePath      $WinSWPath `
        -Certificate   $cert `
        -HashAlgorithm SHA256
    Write-Log "  Status : $($result.Status)"
}

# ── 5. Supprimer le Mark-of-the-Web ──────────────────────────────────────────
Write-Log '[5/5] Suppression du Mark-of-the-Web (Zone.Identifier)...'
Unblock-File -Path $WinSWPath -ErrorAction SilentlyContinue
Write-Log '  OK'

# ── Vérification finale ───────────────────────────────────────────────────────
Write-Log ''
Write-Log '=== Vérification finale ==='
$sig = Get-AuthenticodeSignature -FilePath $WinSWPath
Write-Log "Status  : $($sig.Status)"
Write-Log "Signer  : $($sig.SignerCertificate.Subject)"
Write-Log "Issuer  : $($sig.SignerCertificate.Issuer)"

if ($sig.Status -eq 'Valid') {
    Write-Log ''
    Write-Log 'SUCCESS: WinSW.exe est maintenant signé et approuvé.'
} else {
    Write-Log ''
    Write-Log "ATTENTION: Statut inattendu: $($sig.Status)"
}

Write-Log '=== Fin ==='
