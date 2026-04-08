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

# SIG # Begin signature block
# MIIcIAYJKoZIhvcNAQcCoIIcETCCHA0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCPVZ1s5fFx7h8r
# Sz7muncMjCCV8nEwZDMDKqCaoXmN4aCCFl4wggMgMIICCKADAgECAhB15f8UAKT2
# qEy95UH9z4ncMA0GCSqGSIb3DQEBCwUAMCgxJjAkBgNVBAMMHUFEIFdlYiBJbnRl
# cmZhY2UgQ29kZSBTaWduaW5nMB4XDTI2MDQwNzE3MTIxMloXDTMxMDQwNzE3MjIx
# MVowKDEmMCQGA1UEAwwdQUQgV2ViIEludGVyZmFjZSBDb2RlIFNpZ25pbmcwggEi
# MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC269UaRy1MGOjCD2hW2D59Noc3
# VfDKrsuvUMg2OKWsBmUyuBerJKvYLSou9EbyOi4PXg5CbcYF4xWzdwTAmNVYjxTJ
# Rddkq4f8tTM9faXdqdOYPaBl3VWcivnTdBGAVL28FEpCkUzK6zpvfDxRKRC66fXT
# q/XpFh9HFx+h/jvYPXQ4R0dE05JbTBuyrAkewb0kvVkWdJ1Cbzi4QoGLmeZMUTMq
# FVD6/XtF/ZFH1luXUno+8nBUkYDOacw61wb1gIGHEBfRVJnvHQb6UINRNUP/EiMK
# G0rnlf7Oy3CserhIFvnxmos1tBP7S/WMGyRHC8y0KHVfIa2qm1aGXvD4gP8RAgMB
# AAGjRjBEMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNV
# HQ4EFgQUEiecK9t6ETEB2YcQWxM/ynrOgFIwDQYJKoZIhvcNAQELBQADggEBAJKE
# S3JgZimRwjZHmNeV/Kat6kaIVzlt2r/JnVrYXDEtBV9Z/MngBJRLX2Ei4mDU+UWK
# syMWATOw+tAs4aftq6IXpGPLfY9j6Up6Ghb3ESOVfyiHv0PvnXiyEjON4Aja3S/Q
# 4DtJI/eKkFvlJQ4xykkuIlwYvcag44sTma2PGAkJ8AZfGgzN3H5eh1Dp+OBLiYjs
# f9oE8ADv35mUeMzZSpy6HIdi+gQ7Ptv4vIssoNxuaCvxahH23i2lTFPUOgGzdvWm
# vu7oyE0FGMY5VHOKnxEqh9B1DxFL575+K4FiznKWPt+qTq6rldYjgK0zclR6mC0c
# KBKqMvqZQpo98V4Ti/8wggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0G
# CSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0
# IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5
# NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNV
# BAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQg
# Um9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvk
# XUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdt
# HauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu
# 34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0
# QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2
# kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM
# 1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmI
# dph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZ
# K37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72
# gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqs
# X40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyh
# HsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8E
# BTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAW
# gBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUH
# AQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYI
# KwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAE
# CjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX
# 979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offy
# ct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3
# J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0
# d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6ts
# ds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQw
# gga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1
# c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0Zo
# dLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi
# 6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNg
# xVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiF
# cMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJ
# m/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvS
# GmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1
# ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9
# MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7
# Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bG
# RinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6
# X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAd
# BgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJo
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxj
# aaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0
# hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0
# F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnT
# mpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKf
# ZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzE
# wlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbh
# OhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOX
# gpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EO
# LLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wG
# WqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWg
# AwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# MB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEy
# NTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3
# zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8Tch
# TySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWj
# FDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2Uo
# yrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjP
# KHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KS
# uNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7w
# JNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vW
# doUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOg
# rY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K
# 096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCf
# gPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zy
# Me39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezL
# TjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsG
# AQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNy
# dDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZ
# D9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/
# ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu
# +WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4o
# bEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2h
# ECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasn
# M9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol
# /DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgY
# xQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3oc
# CVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcB
# ZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRgwggUU
# AgEBMDwwKDEmMCQGA1UEAwwdQUQgV2ViIEludGVyZmFjZSBDb2RlIFNpZ25pbmcC
# EHXl/xQApPaoTL3lQf3PidwwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIB
# DDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgKoAQCfN2mF6Y
# Tz+0To3s/9hce+vQpNwxiBPixLCeOBswDQYJKoZIhvcNAQEBBQAEggEAmtelztGM
# XMhjHG+BAyAedCvqulgrpt/DlGas8QR0g6WcHlNKz0N0+k2E/uD1HiOxkxorzE5K
# kXIgPmvazcDD0Oc6sY0bDgbJvUpwcvf/JTbWFGbxgLW0X6GTLy3/g/dtHogQ+kUe
# AG/Unx6rf16wzJi3YDs6DNI3voYFhy34L6shqJbqRSISot32Kewmbo/ovNHvFuJ8
# iW07M+OrWIKo8HGzHYPPefXErQGp2Yyhyd1dwVKV3/SIHxZ6D7wuX80fX+YYHXY6
# qEpmtVFLuOokXJMPWjv426cpfY5tFbACvD91/02iyCnTjJRneOSfVkwtRW839I1b
# 72+pmy7hB0LtO6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA0MDgwNjM4Mjda
# MC8GCSqGSIb3DQEJBDEiBCCJbPMzcQAhhyLFTvMClhhWU0O8ktcXNYLRlsgE0L/g
# DTANBgkqhkiG9w0BAQEFAASCAgDCMGqpKlfsU+nriKiA+JO/Bprt8sanmt3rlMmb
# +r8/kDfsWLjtN3UA3nu3uOAntiye267UpY7ms/Igd0cCyDAg5ER30uBOiTeqKQbD
# gVcRWfYoC3ZoVAFtl5Fi48SYdxiSS9/+4h+5bNBHE9Z6/XZIKrLuym0c0aWgtM1u
# iFnp475n8X0RrGbleMIam5+LIEsKEkZSAO4lfd6jwwQOhqZuKK+tCmP7PpbhiodZ
# IXlCU4iHAlo+KX89O5HJ7YCNruqs7uoElTClWPsj+OK3xQRIMGZOBoTyjYWs2yyE
# Qt72LUUzPBrTVJCeSFv3t4fybfuMCyJfsZ+8Q8NorNl4gUo5bsqHuvEpm7tAEyNC
# U+uFiCl0CwIjmN/f46FDcbKN3pU2QI1qhke/EgA4mMwsiXkCYTpXaa6IsAsdCpFP
# GWUJE6TB1xab3pQcE1F+6W3Xk4zfWAtmZE7XvP55JG+ITCI7q1yfS1a8Cw0KwbCj
# 1GCz4xeSOADRDFslnGuXkidHQ+KlnFbznZVJrSdqgPGLq8N/emW8HVy4B9XPX47+
# j5rU3QswRGAiQxYjKWzc4irl4sh/G9xAmg96fWB6/HJyMdjBI2NC/E/2rHb/ZNAR
# KBsfQLDRcl0GuLDfaud9M8z2/Xa6oJ5EN8PiRBd39zbxPGGzr0v7qPyh7CHNB9Nn
# Roecqw==
# SIG # End signature block
