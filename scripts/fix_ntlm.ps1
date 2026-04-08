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

# SIG # Begin signature block
# MIIcIAYJKoZIhvcNAQcCoIIcETCCHA0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB52/6L0CvZf4bs
# 3D/PEptp2YuH9ARv3DND2v7pLnxXdqCCFl4wggMgMIICCKADAgECAhB15f8UAKT2
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgnOHOoRz67WQv
# qozo/mGg/VhYhhpC/ezAYGSibf6TNyMwDQYJKoZIhvcNAQEBBQAEggEAW8BAqO4R
# VWoZHDf0DxTzUe8Fo8vn4i41Us9sdUSrCvPoDRHoShu3AMbUP4PUBpjv9kwrLXMO
# ngho0jbLQ/+1SxaM6pHYeSMVg0JsPbNY+sEjUt0aHM4qS7BiS0Z2BEOkHBkf9jPd
# 2fg22tyUVM3nQEQ0USbfAyZHXCd0LzMuFuVxCdjscuiosyqBO7ppxUwdn15m8drt
# fsKCHuxxykMVuzWRlIv8Jlk98YH+vkcC7XVcCu5PEEudsLYw0nVnnqluO7ow7TBS
# Vpr7no4a5YE5QBMfzQZo51v8JHindk6yvkq6hDlWA/3RyERDKfC2l02X0+x/meLN
# zARfLhjoohcgD6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA0MDgwNjM4MjVa
# MC8GCSqGSIb3DQEJBDEiBCCrlco8Wd5fYfKuHcT6MpwIaChixLQH3g+EXVuh0k+L
# ADANBgkqhkiG9w0BAQEFAASCAgAeNDFxxoIdbg4d8NroAAXct+wB+M/JAdXz4ZM5
# rioGdGe5Akq1zYbrsKsayFwKOc1oAzAidKQuvpRCC1FJS/VxTkYTgGX45P3dWkUt
# c33WrJo12HOnCpHvXEHOAJ/0a1o3stBZe0wLcCtX4K1qFtXNFYChVwqix9pQBeLb
# CvcFKjU9eHsD7hiW3MbOfmPqU/9rofJMyO2cDTyV5SmnlC1RZNi7gYc687zwBfib
# vRdcfHeBQ9gl/j0GKvwwQeIyirTjP6JppAt/kxKIWbInbuXTq+FfsMc/Sgt+J+/h
# LvFzGoAXP0wFazVeaKPgTvaKCSEWPjjBoOzm9ZXOU9/wAqrU+atiH0WAmQJkoiSN
# TIM+MTKsHEhLqTGEZb4z+WaZNtZ8CUp97H+jsLcbUxsjSSLF1bgAkjN4qviAXbNP
# 8NWj7Y9NAJSvsiovPLlPUAk6BVHMpPHHYTFpPJo1mAE3H83eKps7p5OLckMsa2e3
# E8yJD2bPAOASFAL23+m1LLIHk0B9GXV4bRn5ldbVeQspnOJWUCVJI+J894+FfX32
# n/L/Y6p9AUTvVHi/XvxzHJXkh+SQxw39VdbfTQJajGInxHpTLQVhjWVWe8T7YbRa
# /JRC7VUOTje8VR7VZRIuW5Mn265m0bw9PU73jOrBArRLh4CqYXEAUQR3NCB7Z0iA
# UpwRuw==
# SIG # End signature block
