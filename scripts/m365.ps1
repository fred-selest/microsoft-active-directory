# Etat de Microsoft 365 (licences, comptes, synchronisation) : appele par core/m365.py.
# Lecture seule, par Microsoft Graph, avec le certificat de l'application
# (aucun module PowerShell necessaire). Parametres en JSON sur l'entree
# standard, reponse JSON sur la derniere ligne.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$req = [Console]::In.ReadToEnd() | ConvertFrom-Json
$out = @{ ok = $true }

function ConvertTo-Base64Url([byte[]]$bytes) {
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-GraphToken {
    $cert = Get-Item -Path ("Cert:\LocalMachine\My\" + $req.thumbprint) -ErrorAction SilentlyContinue
    if (-not $cert) { throw "certificate not found : $($req.thumbprint)" }
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if (-not $rsa) { throw "certificate private key not readable : $($req.thumbprint)" }
    $endpoint = "https://login.microsoftonline.com/$($req.organization)/oauth2/v2.0/token"
    $now = [int][Math]::Floor(([DateTime]::UtcNow - (New-Object DateTime 1970, 1, 1)).TotalSeconds)
    $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-Base64Url $cert.GetCertHash()) } | ConvertTo-Json -Compress
    $claims = @{ aud = $endpoint; iss = $req.app_id; sub = $req.app_id; jti = [guid]::NewGuid().ToString()
                 nbf = $now - 60; exp = $now + 540 } | ConvertTo-Json -Compress
    $unsigned = (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($header))) + '.' +
                (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($claims)))
    $signature = $rsa.SignData([Text.Encoding]::ASCII.GetBytes($unsigned),
                               [Security.Cryptography.HashAlgorithmName]::SHA256,
                               [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $body = @{ client_id = $req.app_id; scope = 'https://graph.microsoft.com/.default'
               grant_type = 'client_credentials'
               client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
               client_assertion = $unsigned + '.' + (ConvertTo-Base64Url $signature) }
    return (Invoke-RestMethod -Method Post -Uri $endpoint -Body $body).access_token
}

function Get-GraphAll([string]$url, $headers) {
    $items = New-Object System.Collections.ArrayList
    while ($url) {
        $page = Invoke-RestMethod -Method Get -Uri $url -Headers $headers
        foreach ($item in @($page.value)) { [void]$items.Add($item) }
        $url = $page.'@odata.nextLink'
    }
    return ,$items
}

try {
    $headers = @{ Authorization = 'Bearer ' + (Get-GraphToken) }
    $graph = 'https://graph.microsoft.com/v1.0'

    $org = (Get-GraphAll "$graph/organization?`$select=displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime" $headers)[0]
    $out.organization = @{ name = [string]$org.displayName; sync_enabled = [bool]$org.onPremisesSyncEnabled
                           last_sync = [string]$org.onPremisesLastSyncDateTime }

    $skus = New-Object System.Collections.ArrayList
    foreach ($s in (Get-GraphAll "$graph/subscribedSkus" $headers)) {
        [void]$skus.Add(@{ id = [string]$s.skuId; code = [string]$s.skuPartNumber; status = [string]$s.capabilityStatus
                           total = [int]$s.prepaidUnits.enabled; warning = [int]$s.prepaidUnits.warning
                           suspended = [int]$s.prepaidUnits.suspended; used = [int]$s.consumedUnits })
    }
    $out.skus = $skus

    $users = New-Object System.Collections.ArrayList
    $select = 'id,displayName,userPrincipalName,mail,accountEnabled,userType,onPremisesSyncEnabled,' +
              'onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesImmutableId,assignedLicenses,createdDateTime'
    foreach ($u in (Get-GraphAll "$graph/users?`$select=$select&`$top=999" $headers)) {
        $licenses = New-Object System.Collections.ArrayList
        foreach ($l in @($u.assignedLicenses)) { if ($l.skuId) { [void]$licenses.Add([string]$l.skuId) } }
        [void]$users.Add(@{ name = [string]$u.displayName; upn = [string]$u.userPrincipalName; mail = [string]$u.mail
                            enabled = [bool]$u.accountEnabled; type = [string]$u.userType
                            synced = [bool]$u.onPremisesSyncEnabled; last_sync = [string]$u.onPremisesLastSyncDateTime
                            sam = [string]$u.onPremisesSamAccountName; anchor = [string]$u.onPremisesImmutableId
                            licenses = $licenses; created = [string]$u.createdDateTime })
    }
    $out.users = $users
} catch {
    $detail = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $detail = $detail + ' ' + $_.ErrorDetails.Message }
    $out = @{ ok = $false; error = $detail }
}
[Console]::Out.WriteLine()
[Console]::Out.Write((ConvertTo-Json -InputObject $out -Depth 6 -Compress))
