# Droits NTFS des partages : script appele par core/folders.py.
# Parametres en JSON sur l'entree standard, reponse JSON sur la sortie.
# Ne pas executer a la main : voir core/folders.py.
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
$req = [Console]::In.ReadToEnd() | ConvertFrom-Json
$out = @{ ok = $true }
$logonType = @'
using System;
using System.Runtime.InteropServices;
public static class AdwiLogon {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(string user, string domain, string password,
                                        int logonType, int provider, out IntPtr token);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_1 { public string netname; public uint type; public string remark; }
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    static extern int NetShareEnum(string server, int level, out IntPtr buf, int prefmaxlen,
                                   out int entriesread, out int totalentries, ref int resume);
    [DllImport("netapi32.dll")]
    static extern int NetApiBufferFree(IntPtr buf);

    // Partages d'un serveur : nom, type (0 = disque ; bit 0x80000000 = partage
    // administratif comme C$), commentaire.
    public static object[] Shares(string server) {
        IntPtr buf; int read, total, resume = 0;
        int rc = NetShareEnum(server, 1, out buf, -1, out read, out total, ref resume);
        if (rc != 0) { throw new System.ComponentModel.Win32Exception(rc); }
        var list = new System.Collections.Generic.List<object>();
        try {
            int size = Marshal.SizeOf(typeof(SHARE_INFO_1));
            for (int i = 0; i < read; i++) {
                var info = (SHARE_INFO_1)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + i * size), typeof(SHARE_INFO_1));
                list.Add(new object[] { info.netname, (long)info.type, info.remark ?? "" });
            }
        } finally { NetApiBufferFree(buf); }
        return list.ToArray();
    }
}
'@

function Get-Dir([string]$path) {
    $item = Get-Item -LiteralPath $path -Force
    if (-not $item.PSIsContainer) { throw "Ce chemin n'est pas un dossier : $path" }
    return $item
}

function Sid([string]$value) { New-Object System.Security.Principal.SecurityIdentifier($value) }

function New-Rule([string]$sid, [int]$rights, [string]$applies) {
    $inherit = if ($applies -eq 'this') { 0 } else { 3 }
    New-Object System.Security.AccessControl.FileSystemAccessRule(
        (Sid $sid), [System.Security.AccessControl.FileSystemRights]$rights,
        [System.Security.AccessControl.InheritanceFlags]$inherit,
        [System.Security.AccessControl.PropagationFlags]0,
        [System.Security.AccessControl.AccessControlType]::Allow)
}

function Get-Access($dir) {
    return $dir.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
}

function Read-Aces($acl, [bool]$explicitOnly) {
    $bySid = $acl.GetAccessRules($true, -not $explicitOnly, [System.Security.Principal.SecurityIdentifier])
    # Un SID orphelin (compte supprimé) fait échouer toute la traduction en
    # noms : on retombe alors sur les SID.
    try { $byName = $acl.GetAccessRules($true, -not $explicitOnly, [System.Security.Principal.NTAccount]) }
    catch { $byName = @() }
    $list = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $bySid.Count; $i++) {
        $r = $bySid[$i]
        $name = $r.IdentityReference.Value
        if ($byName.Count -eq $bySid.Count) { $name = $byName[$i].IdentityReference.Value }
        [void]$list.Add(@{
            sid = $r.IdentityReference.Value; name = $name
            rights = [int64]([int]$r.FileSystemRights -band 0xFFFFFFFFL)
            type = $r.AccessControlType.ToString(); inherited = $r.IsInherited
            inheritance = [int]$r.InheritanceFlags; propagation = [int]$r.PropagationFlags
        })
    }
    return ,$list
}

$token = [IntPtr]::Zero
$impersonation = $null
try {
    if (-not ('AdwiLogon' -as [type])) { Add-Type -TypeDefinition $logonType }
    if ($req.user) {
        # Session « nouveaux identifiants » (LOGON32_LOGON_NEW_CREDENTIALS = 9,
        # comme runas /netonly) : les accès réseau de ce processus se font sous
        # le compte de l'administrateur connecté. Les connexions SMB sont
        # propres à cette session de logon : elles ne se mélangent pas à
        # celles des autres requêtes et disparaissent avec le processus, même
        # s'il est tué au délai d'expiration.
        $user = $req.user; $domain = $null
        if ($user.Contains('\')) { $domain, $user = $user.Split('\', 2) }
        if (-not [AdwiLogon]::LogonUser($user, $domain, $req.password, 9, 3, [ref]$token)) {
            throw "Ouverture de session impossible (code $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
        }
        $impersonation = [System.Security.Principal.WindowsIdentity]::Impersonate($token)
    }

    switch ($req.op) {
        'acl' {
            $dir = Get-Dir $req.path
            $acl = Get-Access $dir
            $out.aces = Read-Aces $acl $false
            $out.protected = $acl.AreAccessRulesProtected
            try { $out.owner = (Get-Acl -LiteralPath $req.path).Owner } catch { $out.owner = '' }
            $children = New-Object System.Collections.ArrayList
            foreach ($c in @(Get-ChildItem -LiteralPath $req.path -Directory -Force -ErrorAction SilentlyContinue | Sort-Object Name)) {
                [void]$children.Add($c.Name)
            }
            $out.children = $children
        }
        'grant' {
            $dir = Get-Dir $req.path
            $acl = Get-Access $dir
            $acl.AddAccessRule((New-Rule $req.sid ([int]$req.rights) $req.applies))
            $dir.SetAccessControl($acl)
        }
        'revoke' {
            $dir = Get-Dir $req.path
            $acl = Get-Access $dir
            $acl.PurgeAccessRules((Sid $req.sid))
            $dir.SetAccessControl($acl)
        }
        'mkdir' {
            if (Test-Path -LiteralPath $req.path) {
                if (-not $req.allow_existing) { throw "Le dossier existe déjà : $($req.path)" }
                $dir = Get-Dir $req.path
                $out.existed = $true
            } else {
                # API .NET : New-Item -Path interpréterait [ ] comme des jokers.
                [void][System.IO.Directory]::CreateDirectory($req.path)
                $dir = Get-Dir $req.path
                $out.existed = $false
            }
            $acl = Get-Access $dir
            if ($req.protect) {
                # Héritage coupé sans copie : seuls les droits ci-dessous restent.
                $acl.SetAccessRuleProtection($true, $false)
                if ($req.reset) {
                    # Dossier existant (réparation) : les droits explicites déjà
                    # posés pour d'autres comptes sont retirés aussi.
                    foreach ($r in @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
                        $acl.RemoveAccessRuleSpecific($r)
                    }
                }
                foreach ($s in @('S-1-5-32-544', 'S-1-5-18')) {
                    $acl.AddAccessRule((New-Rule $s 0x1F01FF 'all'))
                }
            }
            foreach ($g in @($req.grants)) {
                $acl.AddAccessRule((New-Rule $g.sid ([int]$g.rights) 'all'))
            }
            $dir.SetAccessControl($acl)
        }
        'scan' {
            $wanted = @{}
            foreach ($s in @($req.sids)) { $wanted[$s] = $true }
            $found = New-Object System.Collections.ArrayList
            $errors = New-Object System.Collections.ArrayList
            $count = 0
            $queue = New-Object System.Collections.Queue
            foreach ($r in @($req.roots)) { $queue.Enqueue(@($r, 0)) }
            while ($queue.Count -gt 0 -and $count -lt $req.max_folders) {
                $entry = $queue.Dequeue(); $path = $entry[0]; $level = $entry[1]
                $count++
                try {
                    $acl = Get-Access (Get-Item -LiteralPath $path -Force)
                    # Racine : droits hérités compris ; dessous, seuls les droits
                    # explicites (les hérités viennent du parent déjà listé).
                    foreach ($a in (Read-Aces $acl ($level -gt 0))) {
                        if ($wanted.ContainsKey($a.sid)) { $a.path = $path; [void]$found.Add($a) }
                    }
                } catch { [void]$errors.Add("$path : $($_.Exception.Message)") }
                if ($level -lt $req.depth) {
                    foreach ($c in @(Get-ChildItem -LiteralPath $path -Directory -Force -ErrorAction SilentlyContinue)) {
                        $queue.Enqueue(@($c.FullName, ($level + 1)))
                    }
                }
            }
            $out.found = $found
            $out.errors = $errors
            $out.scanned = $count
            $out.truncated = ($queue.Count -gt 0)
        }
        'shares' {
            $list = New-Object System.Collections.ArrayList
            foreach ($sh in [AdwiLogon]::Shares($req.server)) {
                [void]$list.Add(@{ name = $sh[0]; type = $sh[1]; remark = $sh[2] })
            }
            $out.shares = $list
        }
        'tree' {
            # Tous les droits explicites d'une arborescence (plus ceux, hérités
            # compris, de la racine) : ce qui diffère de l'héritage du parent.
            $folders = New-Object System.Collections.ArrayList
            $errors = New-Object System.Collections.ArrayList
            $count = 0
            $queue = New-Object System.Collections.Queue
            $queue.Enqueue(@($req.path, 0))
            while ($queue.Count -gt 0 -and $count -lt $req.max_folders) {
                $entry = $queue.Dequeue(); $path = $entry[0]; $level = $entry[1]
                $count++
                try {
                    $acl = Get-Access (Get-Item -LiteralPath $path -Force)
                    $aces = Read-Aces $acl ($level -gt 0)
                    if ($level -eq 0 -or $aces.Count -gt 0 -or $acl.AreAccessRulesProtected) {
                        [void]$folders.Add(@{ path = $path; level = $level; aces = $aces;
                                              protected = $acl.AreAccessRulesProtected })
                    }
                } catch { [void]$errors.Add("$path : $($_.Exception.Message)") }
                if ($level -lt $req.depth) {
                    foreach ($c in @(Get-ChildItem -LiteralPath $path -Directory -Force -ErrorAction SilentlyContinue | Sort-Object Name)) {
                        $queue.Enqueue(@($c.FullName, ($level + 1)))
                    }
                }
            }
            $out.folders = $folders
            $out.errors = $errors
            $out.scanned = $count
            $out.truncated = ($queue.Count -gt 0)
        }
        default { throw "Opération inconnue : $($req.op)" }
    }
} catch {
    $out = @{ ok = $false; error = $_.Exception.Message }
} finally {
    if ($impersonation) { $impersonation.Undo() }
    if ($token -ne [IntPtr]::Zero) { [void][AdwiLogon]::CloseHandle($token) }
}
[Console]::Out.Write((ConvertTo-Json -InputObject $out -Depth 6 -Compress))
