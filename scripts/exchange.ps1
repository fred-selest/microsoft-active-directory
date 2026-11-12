# Boites aux lettres partagees Exchange Online : appele par core/exchange.py.
# Parametres en JSON sur l'entree standard, reponse JSON sur la derniere ligne.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
$req = [Console]::In.ReadToEnd() | ConvertFrom-Json
$out = @{ ok = $true }
$connected = $false

function Get-Shared([string]$identity) {
    # Garde-fou : on ne touche qu'aux boites PARTAGEES, jamais a une boite personnelle.
    $m = Get-EXOMailbox -Identity $identity -Properties RecipientTypeDetails
    if ($m.RecipientTypeDetails -ne 'SharedMailbox') { throw "Cette boite n'est pas une boite partagee : $identity" }
    return $m
}

try {
    Import-Module ExchangeOnlineManagement
    Connect-ExchangeOnline -AppId $req.app_id -CertificateThumbprint $req.thumbprint `
        -Organization $req.organization -ShowBanner:$false
    $connected = $true

    switch ($req.op) {
        'list' {
            $list = New-Object System.Collections.ArrayList
            foreach ($m in @(Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited `
                             -Properties WhenCreated | Sort-Object DisplayName)) {
                [void]$list.Add(@{ name = $m.DisplayName; address = [string]$m.PrimarySmtpAddress
                                   alias = $m.Alias; created = $m.WhenCreated.ToString('yyyy-MM-dd') })
            }
            $out.mailboxes = $list
            $domains = New-Object System.Collections.ArrayList
            foreach ($d in @(Get-AcceptedDomain | Sort-Object @{ Expression = 'Default'; Descending = $true }, DomainName)) {
                [void]$domains.Add([string]$d.DomainName)
            }
            $out.domains = $domains
        }
        'members' {
            $m = Get-Shared $req.mailbox
            $full = New-Object System.Collections.ArrayList
            foreach ($p in @(Get-EXOMailboxPermission -Identity $m.Identity)) {
                if (-not $p.IsInherited -and -not $p.Deny -and $p.User -notlike 'NT AUTHORITY\*' -and
                    ($p.AccessRights -contains 'FullAccess')) { [void]$full.Add([string]$p.User) }
            }
            $sendAs = New-Object System.Collections.ArrayList
            foreach ($p in @(Get-EXORecipientPermission -Identity $m.Identity)) {
                if ($p.Trustee -notlike 'NT AUTHORITY\*' -and ($p.AccessRights -contains 'SendAs')) {
                    [void]$sendAs.Add([string]$p.Trustee)
                }
            }
            $out.full_access = $full
            $out.send_as = $sendAs
        }
        'grant' {
            $m = Get-Shared $req.mailbox
            if ($req.full_access) {
                Add-MailboxPermission -Identity $m.Identity -User $req.user -AccessRights FullAccess `
                    -InheritanceType All -AutoMapping $true -Confirm:$false | Out-Null
            }
            if ($req.send_as) {
                Add-RecipientPermission -Identity $m.Identity -Trustee $req.user -AccessRights SendAs `
                    -Confirm:$false | Out-Null
            }
        }
        'revoke' {
            $m = Get-Shared $req.mailbox
            if ($req.full_access) {
                Remove-MailboxPermission -Identity $m.Identity -User $req.user -AccessRights FullAccess `
                    -InheritanceType All -Confirm:$false
            }
            if ($req.send_as) {
                Remove-RecipientPermission -Identity $m.Identity -Trustee $req.user -AccessRights SendAs `
                    -Confirm:$false
            }
        }
        'create' {
            $m = New-Mailbox -Shared -Name $req.name -DisplayName $req.name -Alias $req.alias `
                -PrimarySmtpAddress $req.address
            $out.address = [string]$m.PrimarySmtpAddress
        }
        'to_shared' {
            # Depart d'un collaborateur : seule une boite d'utilisateur est convertie.
            $m = Get-EXOMailbox -Identity $req.mailbox -Properties RecipientTypeDetails
            if ($m.RecipientTypeDetails -eq 'UserMailbox') {
                Set-Mailbox -Identity $m.Identity -Type Shared
            } elseif ($m.RecipientTypeDetails -ne 'SharedMailbox') {
                throw "Type de boite non pris en charge : $($m.RecipientTypeDetails)"
            }
        }
        default { throw "Operation inconnue : $($req.op)" }
    }
} catch {
    $out = @{ ok = $false; error = $_.Exception.Message }
} finally {
    if ($connected) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
}
[Console]::Out.WriteLine()
[Console]::Out.Write((ConvertTo-Json -InputObject $out -Depth 5 -Compress))
