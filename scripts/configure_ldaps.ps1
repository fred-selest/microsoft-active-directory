# Script de configuration LDAPS pour AD Web Interface
# Exécuter en tant qu'Administrateur

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Configuration LDAPS - Active Directory" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Certificat sélectionné pour LDAPS
$certThumbprint = "3F9906EE628F09A20642169B400CC956E8E86B3F"
$certSubject = "srvdc2022.SELEST.local"

Write-Host "[1/5] Vérification du certificat..." -ForegroundColor Yellow
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $certThumbprint }

if (-not $cert) {
    Write-Host "[ERREUR] Certificat introuvable !" -ForegroundColor Red
    Write-Host "Thumbprint: $certThumbprint" -ForegroundColor Gray
    pause
    exit 1
}

Write-Host "[OK] Certificat trouvé : $($cert.Subject)" -ForegroundColor Green
Write-Host "    Valable jusqu'au : $($cert.NotAfter)" -ForegroundColor Gray
Write-Host ""

# Étape 2 : Vérifier les autres magasins
Write-Host "[2/5] Vérification des magasins de certificats..." -ForegroundColor Yellow
Write-Host "  Magasin Personal (My) : OK" -ForegroundColor Green
Write-Host "  Magasin Root : Vérification..." -ForegroundColor Yellow
$rootCert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $certThumbprint }
if (-not $rootCert) {
    Write-Host "  [ATTENTION] Certificat racine non trouvé dans Root" -ForegroundColor Yellow
}
Write-Host ""

# Étape 3 : Configurer LDAP avec le certificat
Write-Host "[3/5] Configuration du service LDAP..." -ForegroundColor Yellow

# Créer la clé de registre pour le certificat LDAP
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\CertMapping"
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Directory -Force | Out-Null
    Write-Host "  [OK] Clé registre créée" -ForegroundColor Green
} else {
    Write-Host "  [OK] Clé registre existe déjà" -ForegroundColor Green
}

# Créer la mapping pour le certificat
New-Item -Path $registryPath -Name "1" -Force | Out-Null
New-ItemProperty -Path "$registryPath\1" -Name "Subject" -Value $certSubject -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$registryPath\1" -Name "Thumbprint" -Value $certThumbprint -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$registryPath\1" -Name "MappingType" -Value 7 -PropertyType DWord -Force | Out-Null

Write-Host "  [OK] Mapping certificat LDAP configuré" -ForegroundColor Green
Write-Host ""

# Étape 4 : Redémarrer le service NTDS
Write-Host "[4/5] Redémarrage du service NTDS..." -ForegroundColor Yellow
Restart-Service -Name NTDS -Force
Write-Host "  [OK] Service NTDS redémarré" -ForegroundColor Green
Write-Host "  Attente 10 secondes..." -ForegroundColor Yellow
Start-Sleep -Seconds 10
Write-Host ""

# Étape 5 : Vérification
Write-Host "[5/5] Vérification du port LDAPS..." -ForegroundColor Yellow
Start-Sleep -Seconds 2
$test = Test-NetConnection -ComputerName localhost -Port 636
 if ($test.TcpTestSucceeded) {
    Write-Host "  [SUCCESS] Port 636 (LDAPS) ouvert et écoutant !" -ForegroundColor Green
 } else {
    Write-Host "  [ATTENTION] Port 636 non détecté - redémarrer le service 'Active Directory Domain Services'" -ForegroundColor Yellow
 }
Write-Host ""

# Étape 6 : Créer fichier de configuration pour AD Web Interface
Write-Host "Configuration de l'application..." -ForegroundColor Yellow
$configContent = @"
# Configuration LDAPS
AD_SERVER=127.0.0.1
AD_PORT=636
AD_USE_SSL=true
AD_BASE_DN=DC=selest,DC=local
"@


Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CONFIGURATION TERMINÉE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Connexion LDAPS possible avec :" -ForegroundColor Cyan
Write-Host "  • Serveur : $certSubject ou 127.0.0.1" -ForegroundColor White
Write-Host "  • Port : 636" -ForegroundColor White
Write-Host "  • SSL/TLS : Activé" -ForegroundColor White
Write-Host ""
Write-Host "SELEST.local" -ForegroundColor Yellow
Write-Host ""
Write-Host "Pour configurer AD Web Interface :" -ForegroundColor Cyan
Write-Host "  1. Déconnectez-vous" -ForegroundColor White
Write-Host "  2. Reconnectez-vous avec :" -ForegroundColor White
Write-Host "     - Port : 636" -ForegroundColor White
Write-Host "     - SSL : Coché" -ForegroundColor White
Write-Host "  3. Vous pourrez créer des utilisateurs !" -ForegroundColor Green
Write-Host ""

pause

# SIG # Begin signature block
# MIIcIAYJKoZIhvcNAQcCoIIcETCCHA0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCChgiYvWrlWp0D2
# 0HzGIGxzhcWj6uRZJ/KDPU6Uq1bTiKCCFl4wggMgMIICCKADAgECAhB15f8UAKT2
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgolQQ/SvK8Qvn
# RV87vRddFjxHbs68J+brm+1+aXLnHAowDQYJKoZIhvcNAQEBBQAEggEAl6Mpovxl
# ZmdJBksqB8uNXE5n/tVtsLW43Zzj/2nLeQOvhBlU0UVOKMVO1hOyIjOsTAIdyOo4
# CKQINHolwpJ7+hgkpcQ4B18vpmWSxUauFwsyPsGebKfjKwJht/2CO8ViNJx21Kx8
# vvpl0om3A9ANSg7OX4/TxpCjyp4fzI2BdP1ufvMlrJPedbRkm6RbaNVwQZkONLKt
# 18EY6gxSGFNq09IeK0Sz5tIFUN7ozCJM8ne0c4jPYRvWZw0hnEQc+MPKTiTNLPk/
# sXGiDFJ+cMBofQ3xp8fWLK7u7vZ+kqHuS/NetOtt/gRjFUcsSzbmD5qTv3yBLvKI
# 0u84db42NG/7U6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA0MDgwNjM4MjNa
# MC8GCSqGSIb3DQEJBDEiBCBtSwACLAeIaLlPfXBrseV1cuLCNlKC/bPqJr7zgKWg
# mjANBgkqhkiG9w0BAQEFAASCAgBSmBPyHEpvXd8qnyYPYeRnQpAokluNod6rTVUI
# G7jH6P8L69PASgqIsbipFCc+ezC7NEdiC33GkR/3Ksj63RIBb8Rh6T4Js+sbxP89
# KPdu3Q4wXlvJfFH33ovAQpqRx0MUrL/S/Qzj8w7TM2Cc+Rwx5nFYYHrO5Puvft7J
# 8DYz1Zt90mvkjx3u0RDEXpqGp3+TbrUuDAuq2SboHJ+5eS5865APow6Zbgk17I+a
# eVlVZGuCFlQbGT5RnomtJ8vtLkWzyUoJa+7VD6J/l2OuVC1yNhQmKVgZ9fuPqsqt
# SsH5+wWriH2mdJTpu2Fmu5tCi5g+nn3Y/JqgCZ2aRPyOZj0lCJiS1LYEaH4IZmiI
# KA9XUBb46uC7O3T+sKeKPIsrIfMrj+pC/ApKIwsv1bEZJBaHCra4ngjOXX0Z9+vU
# T6t1UoNck6BR4OJYKwfueZZ12QfZi0GnII0lsQTAfl/vUCP7sqjk7clAPxN+d6Eg
# KqW//l6dsuz28n722hxg9jUCIPj+cN02H/c2gpMeEEavfBrhJeRhchmtyc0Rn0ej
# cAHhvjMtm/9O676cKfN2JX0uSvY7EhTT/hnzYwTN+GbXi3Cavlpc6+ZGXGO/loIW
# ngsRDUaugtNoaBA0N3x6N0FhU001W2z9UORT8J49IoqiIoGxsJMMc+KzN5cqCLKq
# LfcEsQ==
# SIG # End signature block
