# Sauvegarde et restauration des strategies de groupe : appele par core/gpo.py.
# Parametres en JSON sur l'entree standard, reponse JSON sur la sortie.
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
$req = [Console]::In.ReadToEnd() | ConvertFrom-Json
$out = @{ ok = $true }
$logonType = @'
using System;
using System.Runtime.InteropServices;
public static class AdwiGpoLogon {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(string user, string domain, string password,
                                        int logonType, int provider, out IntPtr token);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@
$token = [IntPtr]::Zero
$impersonation = $null
try {
    Import-Module GroupPolicy
    if ($req.user) {
        # Session « nouveaux identifiants » : les acces a l'annuaire et a
        # SYSVOL se font sous le compte de l'administrateur connecte.
        if (-not ('AdwiGpoLogon' -as [type])) { Add-Type -TypeDefinition $logonType }
        $user = $req.user; $domain = $null
        if ($user.Contains('\')) { $domain, $user = $user.Split('\', 2) }
        if (-not [AdwiGpoLogon]::LogonUser($user, $domain, $req.password, 9, 3, [ref]$token)) {
            throw "Ouverture de session impossible (code $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
        }
        $impersonation = [System.Security.Principal.WindowsIdentity]::Impersonate($token)
    }
    switch ($req.op) {
        'backup' {
            $list = New-Object System.Collections.ArrayList
            foreach ($b in @(Backup-GPO -All -Path $req.path -Domain $req.domain)) {
                [void]$list.Add(@{ id = $b.Id.ToString(); guid = $b.GpoId.ToString(); name = $b.DisplayName })
            }
            $out.gpos = $list
        }
        'restore' {
            Restore-GPO -BackupId ([guid]$req.backup_id) -Path $req.path -Domain $req.domain | Out-Null
        }
        default { throw "Operation inconnue : $($req.op)" }
    }
} catch {
    $out = @{ ok = $false; error = $_.Exception.Message }
} finally {
    if ($impersonation) { $impersonation.Undo() }
    if ($token -ne [IntPtr]::Zero) { [void][AdwiGpoLogon]::CloseHandle($token) }
}
[Console]::Out.Write((ConvertTo-Json -InputObject $out -Depth 5 -Compress))
