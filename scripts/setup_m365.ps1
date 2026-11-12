<#
.SYNOPSIS
    Mise en place de la liaison Microsoft 365 (Exchange Online) pour AD Web Interface.

.DESCRIPTION
    A lancer UNE fois, sur le serveur de l'application, dans une console PowerShell
    ouverte « en tant qu'administrateur ». Une fenetre de connexion Microsoft 365
    s'ouvre : utilisez un compte Administrateur general.

    Le script :
      1. installe les modules PowerShell necessaires (ExchangeOnlineManagement,
         Microsoft.Graph) ;
      2. cree un certificat sur ce serveur (magasin de l'ordinateur, cle privee
         non exportable) ;
      3. cree dans Entra ID l'application « AD Web Interface - Exchange », avec ce
         certificat pour seule preuve d'identite (aucun mot de passe) ;
      4. lui accorde le droit Exchange.ManageAsApp et le role
         « Administrateur des destinataires Exchange » ;
      5. ecrit data\m365.json, que l'application lit pour se connecter.

    Pour tout retirer : supprimez l'application dans Entra ID (Inscriptions
    d'applications) et le certificat dans certlm.msc (Personnel > Certificats).

.PARAMETER Years
    Duree de validite du certificat, en annees (2 par defaut).
#>
[CmdletBinding()]
param([int]$Years = 2)

$ErrorActionPreference = 'Stop'
$appName = 'AD Web Interface - Exchange'
$root = Split-Path -Parent $PSScriptRoot
$outFile = Join-Path $root 'data\m365.json'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Ouvrez PowerShell « en tant qu'administrateur » puis relancez ce script." }

Write-Host "1/5 Modules PowerShell..." -ForegroundColor Cyan
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
}
foreach ($module in 'ExchangeOnlineManagement', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications',
                    'Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.Identity.Governance') {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "    installation de $module"
        Install-Module -Name $module -Scope AllUsers -Force -AllowClobber
    }
}

Write-Host "2/5 Connexion a Microsoft 365 (compte Administrateur general)..." -ForegroundColor Cyan
Connect-MgGraph -NoWelcome -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All',
                                    'RoleManagement.ReadWrite.Directory', 'Organization.Read.All'
$org = Get-MgOrganization
$organization = ($org.VerifiedDomains | Where-Object { $_.IsInitial }).Name
if (-not $organization) { throw "Domaine initial (.onmicrosoft.com) introuvable." }
Write-Host "    locataire : $organization"

Write-Host "3/5 Certificat..." -ForegroundColor Cyan
$cert = New-SelfSignedCertificate -Subject "CN=$appName ($env:COMPUTERNAME)" `
    -CertStoreLocation 'Cert:\LocalMachine\My' -KeyExportPolicy NonExportable -KeySpec Signature `
    -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears($Years)
Write-Host "    empreinte : $($cert.Thumbprint) (valide jusqu'au $($cert.NotAfter.ToString('dd/MM/yyyy')))"

Write-Host "4/5 Application Entra ID..." -ForegroundColor Cyan
# Office 365 Exchange Online : identifiant d'application fixe chez Microsoft.
$exo = Get-MgServicePrincipal -Filter "appId eq '00000002-0000-0ff1-ce00-000000000000'"
if (-not $exo) { throw "Exchange Online n'est pas present dans ce locataire." }
$manageAsApp = $exo.AppRoles | Where-Object { $_.Value -eq 'Exchange.ManageAsApp' }
if (-not $manageAsApp) { throw "Droit Exchange.ManageAsApp introuvable." }

$existing = Get-MgApplication -Filter "displayName eq '$appName'"
if ($existing) {
    $app = $existing | Select-Object -First 1
    Write-Host "    application existante reutilisee : $($app.AppId)"
    $keys = @($app.KeyCredentials) + @(@{ Type = 'AsymmetricX509Cert'; Usage = 'Verify'; Key = $cert.RawData
                                          DisplayName = $cert.Subject })
    Update-MgApplication -ApplicationId $app.Id -KeyCredentials $keys
} else {
    $app = New-MgApplication -DisplayName $appName -SignInAudience 'AzureADMyOrg' `
        -KeyCredentials @(@{ Type = 'AsymmetricX509Cert'; Usage = 'Verify'; Key = $cert.RawData
                             DisplayName = $cert.Subject }) `
        -RequiredResourceAccess @(@{ ResourceAppId = $exo.AppId
                                     ResourceAccess = @(@{ Id = $manageAsApp.Id; Type = 'Role' }) })
    Write-Host "    application creee : $($app.AppId)"
}
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
if (-not $sp) { $sp = New-MgServicePrincipal -AppId $app.AppId }

$granted = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id |
    Where-Object { $_.AppRoleId -eq $manageAsApp.Id }
if (-not $granted) {
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id `
        -ResourceId $exo.Id -AppRoleId $manageAsApp.Id | Out-Null
}

$role = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Exchange Recipient Administrator'"
if (-not $role) { throw "Role « Exchange Recipient Administrator » introuvable." }
$assigned = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($sp.Id)' and roleDefinitionId eq '$($role.Id)'"
if (-not $assigned) {
    New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $sp.Id -RoleDefinitionId $role.Id `
        -DirectoryScopeId '/' | Out-Null
}
Write-Host "    droits accordes : Exchange.ManageAsApp, Administrateur des destinataires Exchange"

Write-Host "5/5 Configuration de l'application..." -ForegroundColor Cyan
$config = [ordered]@{ organization = $organization; app_id = $app.AppId; thumbprint = $cert.Thumbprint
                      expires = $cert.NotAfter.ToString('yyyy-MM-dd') }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $outFile) | Out-Null
[IO.File]::WriteAllText($outFile, ($config | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
Disconnect-MgGraph | Out-Null

Write-Host ""
Write-Host "Termine. Configuration ecrite dans $outFile" -ForegroundColor Green
Write-Host "Microsoft met parfois jusqu'a une heure a appliquer le nouveau role."
Write-Host "Ouvrez ensuite Outils > Boites partagees dans AD Web Interface."
Write-Host "Si le service ne tourne pas sous le compte Systeme local, donnez a son compte"
Write-Host "la lecture de la cle privee du certificat (certlm.msc > Gerer les cles privees)."
