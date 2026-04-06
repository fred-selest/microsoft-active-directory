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