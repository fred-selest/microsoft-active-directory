# ============================================================================
# SIGNATURE DES SCRIPTS POWERSHELL - AD Web Interface
# ============================================================================
# Ce script signe tous les scripts PowerShell avec un certificat Authenticode
# Pour éviter les avertissements Windows lors de l'exécution
# ============================================================================

param(
    [switch]$CreateCert,      # Créer un nouveau certificat
    [switch]$SignOnly,        # Signer sans créer de certificat
    [switch]$Verify,          # Vérifier les signatures existantes
    [switch]$Clean            # Nettoyer les certificats expirés
)

$ErrorActionPreference = "Stop"

# ============================================================================
# CONFIGURATION
# ============================================================================

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot
$CertPath = Join-Path $ScriptRoot "codesign.cer"
$CertStoreLocal = "Cert:\LocalMachine\My"
$CertStoreRoot = "Cert:\LocalMachine\Root"
$CertSubject = "CN=AD Web Interface, O=AD Web Interface, C=FR"
$CertFriendlyName = "AD Web Interface Code Signing"

# ============================================================================
# FONCTIONS
# ============================================================================

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor White
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Text)
    Write-Host "  → $Text" -ForegroundColor Green
}

function Write-Error-Custom {
    param([string]$Text)
    Write-Host "  ✗ $Text" -ForegroundColor Red
}

function Write-Success {
    param([string]$Text)
    Write-Host "  ✓ $Text" -ForegroundColor Green
}

# ============================================================================
# CRÉER UN CERTIFICAT
# ============================================================================

function New-SigningCertificate {
    Write-Header "CRÉATION DU CERTIFICAT DE SIGNATURE"
    
    # Vérifier si le certificat existe déjà
    Write-Step "Recherche d'un certificat existant..."
    $existingCert = Get-ChildItem -Path $CertStoreLocal -CodeSigningCert | 
        Where-Object { $_.Subject -like "*AD Web Interface*" } | 
        Select-Object -First 1
    
    if ($existingCert) {
        Write-Success "Certificat existant trouvé : $($existingCert.Subject)"
        Write-Step "Date d'expiration : $($existingCert.NotAfter)"
        
        if ($existingCert.NotAfter -lt (Get-Date)) {
            Write-Error-Custom "Certificat expiré !"
            return $null
        }
        
        return $existingCert
    }
    
    # Créer un nouveau certificat
    Write-Step "Création d'un nouveau certificat auto-signé..."
    
    try {
        $cert = New-SelfSignedCertificate -DnsName "AD Web Interface" `
                                          -FriendlyName $CertFriendlyName `
                                          -CertStoreLocation $CertStoreLocal `
                                          -Type CodeSigningCert `
                                          -KeyUsage DigitalSignature `
                                          -KeyLength 2048 `
                                          -HashAlgorithm SHA256 `
                                          -NotAfter (Get-Date).AddYears(2)
        
        Write-Success "Certificat créé avec succès"
        Write-Step "Sujet : $($cert.Subject)"
        Write-Step "Empreinte : $($cert.Thumbprint)"
        Write-Step "Expiration : $($cert.NotAfter)"
        
        # Exporter le certificat public
        Write-Step "Export du certificat public vers $CertPath..."
        Export-Certificate -Cert $cert -FilePath $CertPath -Force | Out-Null
        Write-Success "Certificat exporté"
        
        # Importer dans Trusted Root (nécessaire pour la confiance locale)
        Write-Step "Import du certificat dans Trusted Root..."
        Import-Certificate -FilePath $CertPath -CertStoreLocation $CertStoreRoot | Out-Null
        Write-Success "Certificat ajouté aux autorités de confiance"
        
        return $cert
    }
    catch {
        Write-Error-Custom "Échec de création du certificat : $($_.Exception.Message)"
        Write-Host ""
        Write-Host "Solution alternative : Exécuter ce script en tant qu'administrateur" -ForegroundColor Yellow
        return $null
    }
}

# ============================================================================
# SIGNER UN SCRIPT
# ============================================================================

function Set-ScriptSignature {
    param(
        [string]$FilePath,
        $Certificate
    )
    
    try {
        # Vérifier si le fichier existe
        if (-not (Test-Path $FilePath)) {
            Write-Error-Custom "Fichier introuvable : $FilePath"
            return $false
        }
        
        # Signer le script
        $signature = Set-AuthenticodeSignature -FilePath $FilePath `
                                               -Certificate $Certificate `
                                               -TimestampServer "http://timestamp.digicert.com" `
                                               -HashAlgorithm SHA256
        
        # Vérifier le résultat
        if ($signature.Status -eq "Valid") {
            return $true
        }
        else {
            Write-Error-Custom "Échec de signature : $($signature.Status)"
            return $false
        }
    }
    catch {
        Write-Error-Custom "Erreur : $($_.Exception.Message)"
        return $false
    }
}

# ============================================================================
# SIGNER TOUS LES SCRIPTS
# ============================================================================

function Sign-AllScripts {
    param($Certificate)
    
    Write-Header "SIGNATURE DES SCRIPTS POWERSHELL"
    
    if (-not $Certificate) {
        Write-Error-Custom "Aucun certificat fourni"
        return $false
    }
    
    # Trouver tous les scripts PowerShell
    Write-Step "Recherche des scripts à signer..."
    $scripts = Get-ChildItem -Path $ProjectRoot -Include *.ps1 -Recurse |
        Where-Object { $_.FullName -notlike "*\venv\*" -and 
                       $_.FullName -notlike "*\.git\*" -and
                       $_.FullName -notlike "*\node_modules\*" }
    
    Write-Step "$($scripts.Count) scripts trouvés"
    Write-Host ""
    
    $signed = 0
    $failed = 0
    $skipped = 0
    
    foreach ($script in $scripts) {
        $relativePath = $script.FullName.Replace($ProjectRoot, "").TrimStart("\")
        Write-Host "  [$([System.Math]::Min($signed + $failed + $skipped, 99))/99] $relativePath" -NoNewline
        
        # Vérifier si déjà signé avec le même certificat
        $existingSig = Get-AuthenticodeSignature -FilePath $script.FullName -ErrorAction SilentlyContinue
        
        if ($existingSig -and 
            $existingSig.SignerCertificate.Thumbprint -eq $Certificate.Thumbprint -and 
            $existingSig.Status -eq "Valid") {
            Write-Host " [✓ Déjà signé]" -ForegroundColor Gray
            $skipped++
            continue
        }
        
        # Signer le script
        if (Set-ScriptSignature -FilePath $script.FullName -Certificate $Certificate) {
            Write-Host " [✓ Signé]" -ForegroundColor Green
            $signed++
        }
        else {
            Write-Host " [✗ Échec]" -ForegroundColor Red
            $failed++
        }
    }
    
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  RÉSUMÉ" -ForegroundColor White
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  Scripts signés :    $signed" -ForegroundColor Green
    Write-Host "  Scripts ignorés :   $skipped (déjà signés)" -ForegroundColor Yellow
    Write-Host "  Scripts échoués :   $failed" -ForegroundColor Red
    Write-Host ""
    
    return $failed -eq 0
}

# ============================================================================
# VÉRIFIER LES SIGNATURES
# ============================================================================

function Verify-Signatures {
    Write-Header "VÉRIFICATION DES SIGNATURES"
    
    $scripts = Get-ChildItem -Path $ProjectRoot -Include *.ps1 -Recurse |
        Where-Object { $_.FullName -notlike "*\venv\*" -and 
                       $_.FullName -notlike "*\.git\*" }
    
    $valid = 0
    $invalid = 0
    $unsigned = 0
    
    foreach ($script in $scripts) {
        $relativePath = $script.FullName.Replace($ProjectRoot, "").TrimStart("\")
        $signature = Get-AuthenticodeSignature -FilePath $script.FullName -ErrorAction SilentlyContinue
        
        if (-not $signature -or -not $signature.SignerCertificate) {
            Write-Host "  [✗ Non signé]    $relativePath" -ForegroundColor Red
            $unsigned++
        }
        elseif ($signature.Status -eq "Valid") {
            Write-Host "  [✓ Valide]       $relativePath" -ForegroundColor Green
            $valid++
        }
        else {
            Write-Host "  [⚠ Invalide]     $relativePath ($($signature.Status))" -ForegroundColor Yellow
            $invalid++
        }
    }
    
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  RÉSUMÉ" -ForegroundColor White
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  Signatures valides :  $valid" -ForegroundColor Green
    Write-Host "  Signatures invalides : $invalid" -ForegroundColor Yellow
    Write-Host "  Scripts non signés :  $unsigned" -ForegroundColor Red
    Write-Host ""
}

# ============================================================================
# NETTOYER LES CERTIFICATS EXPIRÉS
# ============================================================================

function Clean-ExpiredCerts {
    Write-Header "NETTOYAGE DES CERTIFICATS EXPIRÉS"
    
    $certs = Get-ChildItem -Path $CertStoreLocal -CodeSigningCert |
        Where-Object { $_.NotAfter -lt (Get-Date) }
    
    if ($certs.Count -eq 0) {
        Write-Success "Aucun certificat expiré trouvé"
        return
    }
    
    Write-Step "$($certs.Count) certificat(s) expiré(s) trouvé(s)"
    
    foreach ($cert in $certs) {
        Write-Host "  - $($cert.Subject) (expiré le $($cert.NotAfter))"
        Remove-Item -Path $cert.PSPath -Force
        Write-Success "Supprimé"
    }
    
    Write-Success "Nettoyage terminé"
}

# ============================================================================
# MAIN
# ============================================================================

Write-Header "SIGNATURE AUTHENTICODE - AD Web Interface"
Write-Host "  Répertoire du projet : $ProjectRoot" -ForegroundColor Gray
Write-Host "  Répertoire des scripts : $ScriptRoot" -ForegroundColor Gray
Write-Host ""

# Mode vérification
if ($Verify) {
    Verify-Signatures
    exit 0
}

# Mode nettoyage
if ($Clean) {
    Clean-ExpiredCerts
    exit 0
}

# Mode création de certificat
if ($CreateCert) {
    $cert = New-SigningCertificate
    if ($cert) {
        Write-Success "Certificat prêt à l'emploi"
        Write-Host ""
        Write-Host "Exécutez maintenant ce script SANS -CreateCert pour signer les scripts" -ForegroundColor Yellow
    }
    exit 0
}

# Mode signature seule (ou par défaut)
$cert = Get-ChildItem -Path $CertStoreLocal -CodeSigningCert | 
    Where-Object { $_.Subject -like "*AD Web Interface*" } | 
    Select-Object -First 1

if (-not $cert) {
    Write-Step "Aucun certificat trouvé. Création automatique..."
    $cert = New-SigningCertificate
}

if ($cert) {
    Sign-AllScripts -Certificate $cert
    
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  TERMINÉ" -ForegroundColor Green
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Prochaine étape : Exécuter .\scripts\install_standalone.ps1" -ForegroundColor White
    Write-Host ""
}
else {
    Write-Error-Custom "Impossible de créer ou trouver un certificat"
    Write-Host ""
    Write-Host "Solution manuelle :" -ForegroundColor Yellow
    Write-Host "  1. Ouvrir PowerShell en tant qu'administrateur" -ForegroundColor White
    Write-Host "  2. Exécuter : .\scripts\sign_scripts.ps1 -CreateCert" -ForegroundColor White
    Write-Host "  3. Puis exécuter : .\scripts\sign_scripts.ps1" -ForegroundColor White
    Write-Host ""
    exit 1
}
