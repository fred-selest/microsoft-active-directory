#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Signe WinSW.exe et ADWebInterface.exe avec un certificat Authenticode approuvé.
    Élimine définitivement les popups SmartScreen/UAC sur ce serveur.

.USAGE
    Clic-droit → Exécuter avec PowerShell (en tant qu'administrateur)
    OU: powershell -ExecutionPolicy Bypass -File sign_winsw_admin.ps1
#>

$ErrorActionPreference = 'Continue'
$NssmDir  = Split-Path $PSScriptRoot -Parent | Join-Path -ChildPath 'nssm'
$LogFile  = Join-Path (Split-Path $PSScriptRoot -Parent) 'logs\sign_winsw.log'
$CerFile  = Join-Path $PSScriptRoot 'codesign_selest.cer'

function Write-Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg"
    $line | Out-File $LogFile -Append -Encoding UTF8
    Write-Host $line
}

Write-Log '============================================================'
Write-Log 'Signature Authenticode WinSW — démarrage'
Write-Log '============================================================'

# ── 1. Créer/récupérer le certificat de signature ─────────────────────────────
Write-Log ''
Write-Log '[1/6] Préparation du certificat de signature de code...'

$cert = Get-ChildItem 'Cert:\LocalMachine\My' |
        Where-Object { $_.Subject -like '*AD Web Interface Code Signing*' } |
        Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $cert) {
    Write-Log '  Création d''un nouveau certificat auto-signé (4096 bits, 10 ans)...'
    $cert = New-SelfSignedCertificate `
        -Subject            'CN=AD Web Interface Code Signing, O=SELEST, C=FR' `
        -CertStoreLocation  'Cert:\LocalMachine\My' `
        -KeyUsage           DigitalSignature `
        -Type               CodeSigningCert `
        -KeyAlgorithm       RSA `
        -KeyLength          4096 `
        -HashAlgorithm      SHA256 `
        -NotAfter           (Get-Date).AddYears(10)
}

Write-Log "  Thumbprint : $($cert.Thumbprint)"
Write-Log "  Expiration : $($cert.NotAfter.ToString('yyyy-MM-dd'))"

# ── 2. Installer dans les magasins LocalMachine ───────────────────────────────
Write-Log ''
Write-Log '[2/6] Installation dans Trusted Root CA (LocalMachine)...'
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
$store.Open('ReadWrite'); $store.Add($cert); $store.Close()
Write-Log '  OK'

Write-Log '[3/6] Installation dans Trusted Publishers (LocalMachine)...'
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new('TrustedPublisher','LocalMachine')
$store.Open('ReadWrite'); $store.Add($cert); $store.Close()
Write-Log '  OK'

# ── 3. Exporter le .cer pour déploiement GPO futur ───────────────────────────
$certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[IO.File]::WriteAllBytes($CerFile, $certBytes)
Write-Log "  Certificat exporté : $CerFile (utilisable en GPO)"

# ── 4. Arrêter le service ─────────────────────────────────────────────────────
Write-Log ''
Write-Log '[4/6] Arrêt du service ADWebInterface...'
try {
    Stop-Service ADWebInterface -Force -ErrorAction Stop
    Start-Sleep -Seconds 3
    Get-Process python,pythonw -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
    Write-Log '  Service arrêté'
} catch {
    Write-Log "  AVERTISSEMENT arrêt service: $_"
}

# ── 5. Signer les exécutables ─────────────────────────────────────────────────
Write-Log ''
Write-Log '[5/6] Signature des exécutables WinSW...'

$timestampServers = @(
    'http://timestamp.digicert.com',
    'http://timestamp.sectigo.com',
    'http://tsa.starfieldtech.com'
)

foreach ($exe in @('WinSW.exe', 'ADWebInterface.exe')) {
    $path = Join-Path $NssmDir $exe
    if (-not (Test-Path $path)) {
        Write-Log "  $exe — introuvable, ignoré"
        continue
    }

    # Supprimer MOTW
    Unblock-File $path -ErrorAction SilentlyContinue

    # Essayer les serveurs de timestamp
    $signed = $false
    foreach ($ts in $timestampServers) {
        try {
            $r = Set-AuthenticodeSignature $path -Certificate $cert `
                 -TimestampServer $ts -HashAlgorithm SHA256
            if ($r.Status -eq 'Valid') {
                Write-Log "  $exe — signé avec timestamp ($ts) ✅"
                $signed = $true
                break
            }
        } catch {}
    }

    if (-not $signed) {
        # Sans timestamp (fonctionnel mais expire avec le cert)
        try {
            $r = Set-AuthenticodeSignature $path -Certificate $cert -HashAlgorithm SHA256
            Write-Log "  $exe — signé SANS timestamp (status: $($r.Status))"
        } catch {
            Write-Log "  $exe — ERREUR signature: $_"
        }
    }
}

# ── 6. Redémarrer le service ──────────────────────────────────────────────────
Write-Log ''
Write-Log '[6/6] Redémarrage du service...'
try {
    Start-Service ADWebInterface
    Start-Sleep -Seconds 5
    $status = (Get-Service ADWebInterface).Status
    Write-Log "  Service: $status"
} catch {
    Write-Log "  ERREUR démarrage service: $_"
}

# ── Vérification finale ───────────────────────────────────────────────────────
Write-Log ''
Write-Log '=== VÉRIFICATION FINALE ==='
foreach ($exe in @('WinSW.exe', 'ADWebInterface.exe')) {
    $path = Join-Path $NssmDir $exe
    if (Test-Path $path) {
        $sig = Get-AuthenticodeSignature $path
        Write-Log "$exe : $($sig.Status) — $($sig.SignerCertificate.Subject)"
    }
}

Write-Log ''
Write-Log 'Terminé. Les popups SmartScreen ne devraient plus apparaître.'
Write-Log 'Pour déployer sur d''autres machines du domaine : GPO → distribuer codesign_selest.cer'
Write-Log '    dans Trusted Publishers et Trusted Root CA.'
Write-Log '============================================================'

Read-Host 'Appuyez sur Entrée pour fermer'
