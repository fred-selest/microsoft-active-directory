# -*- coding: utf-8 -*-
"""
Scripts PowerShell pour la gestion complète de LAPS (Local Administrator Password Solution).
"""

INSTALL_LAPS_PS1 = r"""
# Installer LAPS sur le domaine
param(
    [string]$LapsPath = "C:\Program Files\AdmPwd\Core\AdmPwd.dll"
)

Write-Host "=== Installation de LAPS ===" -ForegroundColor Cyan

# Vérifier si LAPS est déjà installé
if (Test-Path $LapsPath) {
    Write-Host "LAPS est déjà installé." -ForegroundColor Green
} else {
    Write-Host "Téléchargement de LAPS..." -ForegroundColor Yellow
    
    # Télécharger LAPS depuis Microsoft
    $lapsUrl = "https://download.microsoft.com/download/C/7/A/C7A99444-302D-41DD-A428-6BE4F38D3A1E/LAPS.x64.msi"
    $lapsInstaller = "$env:TEMP\LAPS.x64.msi"
    
    try {
        Invoke-WebRequest -Uri $lapsUrl -OutFile $lapsInstaller
        Write-Host "Téléchargement terminé." -ForegroundColor Green
        
        # Installer LAPS
        Write-Host "Installation de LAPS..." -ForegroundColor Yellow
        Start-Process msiexec.exe -Wait -ArgumentList "/i $lapsInstaller /quiet"
        Write-Host "LAPS installé avec succès." -ForegroundColor Green
    }
    catch {
        Write-Error "Échec du téléchargement ou de l'installation: $_"
        exit 1
    }
    finally {
        # Nettoyer le fichier d'installation
        if (Test-Path $lapsInstaller) {
            Remove-Item $lapsInstaller -Force
        }
    }
}

Write-Host "=== Installation terminée ===" -ForegroundColor Green
"""

EXTEND_SCHEMA_PS1 = r"""
# Étendre le schéma Active Directory pour LAPS
param(
    [switch]$Force
)

Write-Host "=== Extension du schéma Active Directory pour LAPS ===" -ForegroundColor Cyan

try {
    # Importer le module LAPS
    Import-Module AdmPwd.PS -ErrorAction Stop
    
    # Vérifier si le schéma a déjà été étendu
    $schemaChecked = $false
    try {
        $attrs = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter "(name=ms-Mcs-AdmPwd)" -Properties name
        if ($attrs) {
            Write-Host "L'attribut ms-Mcs-AdmPwd existe déjà dans le schéma." -ForegroundColor Yellow
            $schemaChecked = $true
        }
    }
    catch {
        # L'attribut n'existe pas
    }
    
    try {
        $attrs = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter "(name=ms-Mcs-AdmPwdExpirationTime)" -Properties name
        if ($attrs) {
            Write-Host "L'attribut ms-Mcs-AdmPwdExpirationTime existe déjà dans le schéma." -ForegroundColor Yellow
            $schemaChecked = $true
        }
    }
    catch {
        # L'attribut n'existe pas
    }
    
    if ($schemaChecked -and -not $Force) {
        Write-Host "Le schéma a déjà été étendu pour LAPS." -ForegroundColor Green
        Write-Host "Utilisez -Force pour forcer l'extension." -ForegroundColor Yellow
        return
    }
    
    # Étendre le schéma
    Write-Host "Extension du schéma en cours..." -ForegroundColor Yellow
    Update-AdmPwdADSchema -Confirm:$false
    
    Write-Host "Schéma étendu avec succès !" -ForegroundColor Green
    Write-Host "Attributs créés:" -ForegroundColor Cyan
    Write-Host "  - ms-Mcs-AdmPwd" -ForegroundColor White
    Write-Host "  - ms-Mcs-AdmPwdExpirationTime" -ForegroundColor White
}
catch {
    Write-Error "Échec de l'extension du schéma: $_"
    Write-Host "Vérifiez que vous êtes Administrateur du schéma." -ForegroundColor Red
    exit 1
}

Write-Host "=== Extension terminée ===" -ForegroundColor Green
"""

VERIFY_SCHEMA_PS1 = r"""
# Vérifier l'extension du schéma LAPS
Write-Host "=== Vérification du schéma LAPS ===" -ForegroundColor Cyan

try {
    $schemaContext = (Get-ADRootDSE).schemaNamingContext
    
    # Vérifier ms-Mcs-AdmPwd
    $legacyAttr = Get-ADObject -SearchBase $schemaContext -LDAPFilter "(name=ms-Mcs-AdmPwd)" -Properties name -ErrorAction SilentlyContinue
    $legacyExists = $null -ne $legacyAttr
    
    # Vérifier ms-Mcs-AdmPwdExpirationTime
    $legacyExpAttr = Get-ADObject -SearchBase $schemaContext -LDAPFilter "(name=ms-Mcs-AdmPwdExpirationTime)" -Properties name -ErrorAction SilentlyContinue
    $legacyExpExists = $null -ne $legacyExpAttr
    
    # Vérifier Windows LAPS (msLAPS-Password)
    $newAttr = Get-ADObject -SearchBase $schemaContext -LDAPFilter "(name=msLAPS-Password)" -Properties name -ErrorAction SilentlyContinue
    $newExists = $null -ne $newAttr
    
    # Vérifier msLAPS-PasswordExpirationTime
    $newExpAttr = Get-ADObject -SearchBase $schemaContext -LDAPFilter "(name=msLAPS-PasswordExpirationTime)" -Properties name -ErrorAction SilentlyContinue
    $newExpExists = $null -ne $newExpAttr
    
    Write-Host "`nRésultats:" -ForegroundColor Cyan
    Write-Host "  LAPS Legacy (ms-Mcs-AdmPwd):" -ForegroundColor Yellow
    Write-Host "    - ms-Mcs-AdmPwd: $('✅ Présent' -if $legacyExists -else '❌ Absent')" -ForegroundColor $(if($legacyExists){"Green"}else{"Red"})
    Write-Host "    - ms-Mcs-AdmPwdExpirationTime: $('✅ Présent' -if $legacyExpExists -else '❌ Absent')" -ForegroundColor $(if($legacyExpExists){"Green"}else{"Red"})
    
    Write-Host "  Windows LAPS (msLAPS-Password):" -ForegroundColor Yellow
    Write-Host "    - msLAPS-Password: $('✅ Présent' -if $newExists -else '❌ Absent')" -ForegroundColor $(if($newExists){"Green"}else{"Red"})
    Write-Host "    - msLAPS-PasswordExpirationTime: $('✅ Présent' -if $newExpExists -else '❌ Absent')" -ForegroundColor $(if($newExpExists){"Green"}else{"Red"})
    
    if ($legacyExists -or $newExists) {
        Write-Host "`n✅ LAPS est correctement installé dans le schéma." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "`n❌ LAPS n'est pas installé dans le schéma." -ForegroundColor Red
        Write-Host "Exécutez Extend-LapsSchema.ps1 pour l'installer." -ForegroundColor Yellow
        exit 1
    }
}
catch {
    Write-Error "Erreur lors de la vérification: $_"
    exit 1
}
"""

SET_COMPUTER_PERMISSIONS_PS1 = r"""
# Accorder aux ordinateurs le droit de mettre à jour leur mot de passe LAPS
param(
    [string]$ComputerOU = "",  # OU vide = tous les ordinateurs
    [switch]$Verbose
)

Write-Host "=== Configuration des permissions LAPS pour les ordinateurs ===" -ForegroundColor Cyan

try {
    Import-Module AdmPwd.PS -ErrorAction Stop
    
    if ([string]::IsNullOrEmpty($ComputerOU)) {
        Write-Host "Application à TOUS les ordinateurs du domaine..." -ForegroundColor Yellow
        Set-AdmPwdComputerSelfPermission -Identity (Get-ADDomain).DistinguishedName -Verbose:$Verbose
    } else {
        Write-Host "Application à l'OU: $ComputerOU" -ForegroundColor Yellow
        Set-AdmPwdComputerSelfPermission -Identity $ComputerOU -Verbose:$Verbose
    }
    
    Write-Host "✅ Permissions accordées avec succès !" -ForegroundColor Green
    Write-Host "Les ordinateurs peuvent maintenant mettre à jour leur mot de passe LAPS." -ForegroundColor Cyan
}
catch {
    Write-Error "Échec de la configuration: $_"
    Write-Host "Vérifiez que vous êtes Administrateur du domaine." -ForegroundColor Red
    exit 1
}

Write-Host "=== Configuration terminée ===" -ForegroundColor Green
"""

SET_READ_PERMISSIONS_PS1 = r"""
# Accorder les permissions de lecture/réinitialisation LAPS à un groupe
param(
    [Parameter(Mandatory=$true)]
    [string]$GroupName,  # Nom du groupe (ex: "Domain Admins" ou "Helpdesk")
    
    [switch]$ResetPassword,  # Accorder aussi le droit de réinitialiser
    [string]$ComputerOU = ""  # OU vide = tous les ordinateurs
)

Write-Host "=== Configuration des permissions LAPS pour le groupe: $GroupName ===" -ForegroundColor Cyan

try {
    Import-Module AdmPwd.PS -ErrorAction Stop
    
    # Vérifier si le groupe existe
    $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop
    Write-Host "Groupe trouvé: $($group.SamAccountName)" -ForegroundColor Green
    
    if ([string]::IsNullOrEmpty($ComputerOU)) {
        $ouPath = (Get-ADDomain).DistinguishedName
        Write-Host "Application à TOUS les ordinateurs du domaine..." -ForegroundColor Yellow
    } else {
        $ouPath = $ComputerOU
        Write-Host "Application à l'OU: $ouPath" -ForegroundColor Yellow
    }
    
    # Accorder la permission de lecture
    Write-Host "Accord de la permission de LECTURE..." -ForegroundColor Yellow
    Set-AdmPwdReadPasswordPermission -Identity $ouPath -AllowedPrincipals $GroupName -Verbose
    
    if ($ResetPassword) {
        # Accorder la permission de réinitialisation
        Write-Host "Accord de la permission de RÉINITIALISATION..." -ForegroundColor Yellow
        Set-AdmPwdResetPasswordPermission -Identity $ouPath -AllowedPrincipals $GroupName -Verbose
    }
    
    Write-Host "✅ Permissions accordées avec succès !" -ForegroundColor Green
    Write-Host "Le groupe '$GroupName' peut maintenant:" -ForegroundColor Cyan
    Write-Host "  - Lire les mots de passe LAPS" -ForegroundColor White
    if ($ResetPassword) {
        Write-Host "  - Réinitialiser les mots de passe LAPS" -ForegroundColor White
    }
}
catch {
    Write-Error "Échec de la configuration: $_"
    Write-Host "Vérifiez que le groupe existe et que vous êtes Administrateur du domaine." -ForegroundColor Red
    exit 1
}

Write-Host "=== Configuration terminée ===" -ForegroundColor Green
"""

CREATE_GPO_LAPS_PS1 = r"""
# Créer et configurer la GPO LAPS
param(
    [string]$GPOName = "LAPS Configuration",
    [string]$TargetOU = "",  # OU à laquelle lier la GPO (vide = domaine)
    [int]$PasswordLength = 14,
    [int]$PasswordAge = 30,  # Jours
    [string]$AdminAccountName = "Administrator"  # Nom du compte administrateur local
)

Write-Host "=== Création et configuration de la GPO LAPS ===" -ForegroundColor Cyan

try {
    Import-Module GroupPolicy -ErrorAction Stop
    
    # Vérifier si la GPO existe déjà
    $existingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if ($existingGPO) {
        Write-Host "La GPO '$GPOName' existe déjà." -ForegroundColor Yellow
        Write-Host "Suppression de l'ancienne GPO..." -ForegroundColor Yellow
        Remove-GPO -Name $GPOName -Confirm:$false
    }
    
    # Créer la GPO
    Write-Host "Création de la GPO: $GPOName" -ForegroundColor Yellow
    $gpo = New-GPO -Name $GPOName -Comment "Configuration LAPS - Générée automatiquement"
    Write-Host "GPO créée avec le GUID: $($gpo.Id)" -ForegroundColor Green
    
    # Configurer les paramètres LAPS
    Write-Host "Configuration des paramètres LAPS..." -ForegroundColor Yellow
    
    # Activer LAPS
    Set-GPRegistryValue -Name $GPOName `
        -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" `
        -ValueName "AdmPwdEnabled" -Type DWord -Value 1
    
    # Longueur du mot de passe
    Set-GPRegistryValue -Name $GPOName `
        -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" `
        -ValueName "PasswordLength" -Type DWord -Value $PasswordLength
    
    # Âge du mot de passe (en jours)
    Set-GPRegistryValue -Name $GPOName `
        -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" `
        -ValueName "PasswordAgeDays" -Type DWord -Value $PasswordAge
    
    # Nom du compte administrateur local
    Set-GPRegistryValue -Name $GPOName `
        -Key "HKLM\Software\Policies\Microsoft Services\AdmPwd" `
        -ValueName "AdminAccountName" -Type String -Value $AdminAccountName
    
    Write-Host "Paramètres LAPS configurés:" -ForegroundColor Cyan
    Write-Host "  - Longueur: $PasswordLength caractères" -ForegroundColor White
    Write-Host "  - Âge: $PasswordAge jours" -ForegroundColor White
    Write-Host "  - Compte admin: $AdminAccountName" -ForegroundColor White
    
    # Lier la GPO à l'OU
    if ([string]::IsNullOrEmpty($TargetOU)) {
        $TargetOU = (Get-ADDomain).DistinguishedName
        Write-Host "Liaison au domaine..." -ForegroundColor Yellow
    } else {
        Write-Host "Liaison à l'OU: $TargetOU" -ForegroundColor Yellow
    }
    
    New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled Yes -Enforced No | Out-Null
    
    Write-Host "✅ GPO LAPS créée et configurée avec succès !" -ForegroundColor Green
}
catch {
    Write-Error "Échec de la création de la GPO: $_"
    Write-Host "Vérifiez que vous êtes Administrateur du domaine." -ForegroundColor Red
    exit 1
}

Write-Host "=== Configuration terminée ===" -ForegroundColor Green
"""

CREATE_LOCAL_ADMIN_PS1 = r"""
# Créer le compte administrateur local personnalisé pour LAPS
param(
    [Parameter(Mandatory=$true)]
    [string]$AccountName,  # Nom du compte (ex: "LocalAdmin")
    
    [string]$FullName = "Administrateur Local",
    [string]$Description = "Compte administrateur local géré par LAPS"
)

Write-Host "=== Création du compte administrateur local: $AccountName ===" -ForegroundColor Cyan

try {
    # Script pour créer le compte via GPO Preferences
    $gpoScript = @"
# Créer le compte administrateur local
`$accountName = "$AccountName"
`$fullName = "$FullName"
`$description = "$Description"

# Vérifier si le compte existe déjà
`$existingUser = Get-LocalUser -Name `$accountName -ErrorAction SilentlyContinue
if (`$existingUser) {
    Write-Host "Le compte `$accountName existe déjà." -ForegroundColor Yellow
} else {
    # Créer le compte
    `$securePassword = ConvertTo-SecureString (Get-Random -Maximum 999999999999 | Out-String) -AsPlainText -Force
    New-LocalUser -Name `$accountName -Password `$securePassword -FullName `$fullName -Description `$description -AccountNeverExpires
    Add-LocalGroupMember -Group "Administrators" -Member `$accountName
    Write-Host "Compte `$accountName créé et ajouté aux Administrateurs." -ForegroundColor Green
}
"@
    
    Write-Host "Script généré pour GPO Preferences:" -ForegroundColor Cyan
    Write-Host $gpoScript
    Write-Host "`nPour déployer ce compte :" -ForegroundColor Yellow
    Write-Host "1. Ouvrez Gestion de stratégie de groupe" -ForegroundColor White
    Write-Host "2. Modifiez la GPO LAPS" -ForegroundColor White
    Write-Host "3. Allez dans : Configuration ordinateur → Préférences → Paramètres du Panneau de configuration → Utilisateurs locaux" -ForegroundColor White
    Write-Host "4. Créez un nouvel utilisateur avec les paramètres ci-dessus" -ForegroundColor White
    
    Write-Host "`n✅ Script généré avec succès !" -ForegroundColor Green
}
catch {
    Write-Error "Erreur: $_"
    exit 1
}
"""

GET_LAPS_PASSWORD_PS1 = r"""
# Récupérer un mot de passe LAPS pour un ordinateur
param(
    [Parameter(Mandatory=$true)]
    [string]$ComputerName  # Nom de l'ordinateur
)

Write-Host "=== Récupération du mot de passe LAPS pour: $ComputerName ===" -ForegroundColor Cyan

try {
    Import-Module AdmPwd.PS -ErrorAction Stop
    
    # Rechercher l'ordinateur
    $computer = Get-ADComputer -Identity $ComputerName -Properties "ms-Mcs-AdmPwd","ms-Mcs-AdmPwdExpirationTime","msLAPS-Password","msLAPS-PasswordExpirationTime" -ErrorAction Stop
    
    if (-not $computer) {
        throw "Ordinateur '$ComputerName' introuvable"
    }
    
    # Vérifier LAPS Legacy
    $legacyPwd = $computer."ms-Mcs-AdmPwd"
    $legacyExp = $computer."ms-Mcs-AdmPwdExpirationTime"
    
    # Vérifier Windows LAPS
    $newPwd = $computer."msLAPS-Password"
    $newExp = $computer."msLAPS-PasswordExpirationTime"
    
    Write-Host "`nRésultats pour $($computer.Name):" -ForegroundColor Cyan
    
    if ($legacyPwd) {
        Write-Host "`n  LAPS Legacy:" -ForegroundColor Yellow
        Write-Host "    Mot de passe: $legacyPwd" -ForegroundColor Green
        if ($legacyExp) {
            $expDate = [datetime]::FromFileTime($legacyExp)
            Write-Host "    Expiration: $expDate" -ForegroundColor White
        }
    }
    
    if ($newPwd) {
        Write-Host "`n  Windows LAPS:" -ForegroundColor Yellow
        # Le mot de passe Windows LAPS est chiffré, nécessite une解密
        Write-Host "    Mot de passe: [Nécessite décryptage]" -ForegroundColor Gray
        if ($newExp) {
            $expDate = [datetime]::FromFileTime($newExp)
            Write-Host "    Expiration: $expDate" -ForegroundColor White
        }
    }
    
    if (-not $legacyPwd -and -not $newPwd) {
        Write-Host "  Aucun mot de passe LAPS trouvé." -ForegroundColor Red
        Write-Host "  Vérifiez que LAPS est installé sur cet ordinateur." -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Erreur: $_"
    exit 1
}

Write-Host "`n=== Récupération terminée ===" -ForegroundColor Green
"""

FORCE_LAPS_ROTATION_PS1 = r"""
# Forcer la rotation du mot de passe LAPS
param(
    [Parameter(Mandatory=$true)]
    [string]$ComputerName  # Nom de l'ordinateur
)

Write-Host "=== Force la rotation LAPS pour: $ComputerName ===" -ForegroundColor Cyan

try {
    # La rotation LAPS se fait côté client via la tâche planifiée
    # On peut forcer en réinitialisant l'attribut d'expiration
    
    $computer = Get-ADComputer -Identity $ComputerName -Properties "DistinguishedName" -ErrorAction Stop
    
    # Réinitialiser l'expiration (force la rotation au prochain cycle)
    Set-ADComputer -Identity $computer.DistinguishedName -Replace @{"ms-Mcs-AdmPwdExpirationTime"="0"}
    
    Write-Host "✅ Rotation forcée avec succès !" -ForegroundColor Green
    Write-Host "Le mot de passe sera mis à jour lors du prochain cycle LAPS (généralement dans les 5 minutes)." -ForegroundColor Cyan
    Write-Host "Pour vérifier immédiatement, exécutez sur l'ordinateur cible :" -ForegroundColor Yellow
    Write-Host "  Start-ScheduledTask -TaskPath '\Microsoft\Windows\AdmPwd\' -TaskName 'AdmPwdPasswordRotation'" -ForegroundColor White
}
catch {
    Write-Error "Erreur: $_"
    exit 1
}

Write-Host "=== Rotation terminée ===" -ForegroundColor Green
"""
# SIG # Begin signature block
# MIIcIAYJKoZIhvcNAQcCoIIcETCCHA0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDIhE6RbLRkFOBC
# AMBwfWRjW+45aedFPKJdl1Xb+NAOm6CCFl4wggMgMIICCKADAgECAhB15f8UAKT2
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgrvSE2oPl4yjX
# TxjVYbjtCtMAUCCOGAhUTp8yI7RSnn4wDQYJKoZIhvcNAQEBBQAEggEAEeXyxbtQ
# Yr9ATi5xIewA+MzBbY2o1CzpTFjWZwgusBmVyMpgMSeK8YxsB7E/Wsb/2uywSlI9
# fWZszSg3IhPxFOYs02KcqFGWNnd9ndW6pnrReSRphWpIYqDIvKmWUF7kovezj1tt
# zoSflyFlexUyteFzbZtDIzv7XqErkIBZAkSNtt+umjearqI0tZ0r+jVn3sv9EgIf
# uzTLdG6lUcijH2+wMTcz8yI3B7TIdZr6Hcncn846BkyiDUxdvgaTw6WSaRJHi4eY
# 48Cogct7TPzmD27UqGaUnv98kGXnEyQ/MyCIppNYuzO2XRumXmRe0CettRuxbO2t
# xY1Ph8w++dCtzKGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA0MDgwNjM4Mjda
# MC8GCSqGSIb3DQEJBDEiBCBhfxaBulELQTWTSPKfBbcXtLQ5tOnKQq1+awDJZ5kT
# SjANBgkqhkiG9w0BAQEFAASCAgBJOqwoAt1JVUjdoEYj/FCMwida+MhXvavu+qjk
# eTbsNtOi9ENoMOhXfX4diEnCWWXRK5m8WkTRvqCbM0Sd8R5peVPaBnVEg+feBymt
# aNCrbvVnwZrNXx7968VcRNLMWCDwMYGBKLWvNL1yexGVxy1GYvaJewF1lPIOeRfj
# mNhsQqaEFZzOVtp6thh9uohNLXGaYVFZ7vw/H7LTbaIo9o239+pgl8vMRxpsZrGG
# 2GWlhytoW4vqaQyMMWD7kEnNyVVx1bf1eugf/dxISfSTpUf7hpdfqWa0Zls2QUfT
# xSUNb9TgctM4eg024/8mqpyQu9Jb0OAb1nqA5OI+heqW+Up2u8pAi1x39Mz8hSsf
# KDmnlcwy9+5Gpiwo+8RNRTlS0Sy4/Guykso1K57BnkOy1ZGTugSeMs8YtvASoFVr
# k11wHLMUl1CL/S/v7mog4ZhRBgFKQcxPNCDmUiUJrjnEQwbjwLsv8w1S1WO1nn8t
# gq2iNCSzGgfufYN8nsshKsIij3WmPIc8p8OZLbbSgRHMc7s1tINj/h4ynoXVGbE0
# JYUiEe9cIPVBVh4AqUSmeNdWWz7NJSkBbKecpG31LloGYeaTgWwzXsLHrnz+0lob
# lZxI1h/O1lj7Odd4md9smH0+dzK7Urs+89Q0nM0hM8BD0H9K7ErCrR9NKvf+edIA
# i4yorw==
# SIG # End signature block
