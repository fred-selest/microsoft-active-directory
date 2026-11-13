# Etat des sauvegardes de ce serveur : appele par core/resilience.py.
# Lecture seule, sans identifiants : Sauvegarde Windows Server, cliches
# instantanes, logiciels de sauvegarde tiers detectes. Reponse JSON sur la
# derniere ligne.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
$null = [Console]::In.ReadToEnd()
$out = @{ ok = $true; computer = $env:COMPUTERNAME }
$notes = New-Object System.Collections.ArrayList

function ConvertTo-Iso($value) {
    if (-not $value) { return '' }
    $date = [datetime]$value
    if ($date.Year -lt 1990) { return '' }
    return $date.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

try {
    # --- Sauvegarde Windows Server ---
    $wsb = @{ installed = $false; last_success = ''; last_result = 0; next = ''; versions = 0; target = '' }
    try {
        if (Get-Command Get-WBSummary -ErrorAction SilentlyContinue) {
            $wsb.installed = $true
            $s = Get-WBSummary
            $wsb.last_success = ConvertTo-Iso $s.LastSuccessfulBackupTime
            $wsb.last_result = [int]$s.LastBackupResultHR
            $wsb.next = ConvertTo-Iso $s.NextBackupTime
            $wsb.versions = [int]$s.NumberOfVersions
            $wsb.target = [string]$s.LastBackupTarget
        }
    } catch { [void]$notes.Add("Sauvegarde Windows Server : $($_.Exception.Message)") }
    $out.wsb = $wsb

    # --- Cliches instantanes, par volume fixe ---
    $volumes = New-Object System.Collections.ArrayList
    try {
        $shadows = @(Get-CimInstance -ClassName Win32_ShadowCopy)
        foreach ($v in @(Get-CimInstance -ClassName Win32_Volume -Filter 'DriveType = 3' |
                         Where-Object { $_.DriveLetter } | Sort-Object DriveLetter)) {
            $mine = @($shadows | Where-Object { $_.VolumeName -eq $v.DeviceID } | Sort-Object InstallDate)
            $row = @{ letter = [string]$v.DriveLetter; label = [string]$v.Label; size = [long]$v.Capacity
                      free = [long]$v.FreeSpace; copies = $mine.Count; newest = ''; oldest = '' }
            if ($mine.Count) {
                $row.oldest = ConvertTo-Iso $mine[0].InstallDate
                $row.newest = ConvertTo-Iso $mine[$mine.Count - 1].InstallDate
            }
            [void]$volumes.Add($row)
        }
    } catch { [void]$notes.Add("Cliches instantanes : $($_.Exception.Message)") }
    $out.volumes = $volumes

    # --- Autres logiciels de sauvegarde (services installes) ---
    $others = New-Object System.Collections.ArrayList
    try {
        $pattern = 'Veeam|Acronis|Backup Exec|Active Backup|Altaro|Hornetsecurity VM Backup|NAKIVO|UrBackup|Arcserve|Cobian|Synology|Nova ?Backup|Commvault|Datto|MSP360|CloudBerry|Duplicati|Iperius|BackupAssist|Macrium|Rubrik|Cohesity|Carbonite|Azure Recovery|MARS|Uranium'
        foreach ($name in @(Get-Service | Where-Object { $_.DisplayName -match $pattern } |
                            Select-Object -ExpandProperty DisplayName -Unique | Sort-Object)) {
            [void]$others.Add([string]$name)
        }
    } catch { [void]$notes.Add("Services : $($_.Exception.Message)") }
    $out.other_software = $others
    $out.notes = $notes
} catch {
    $out = @{ ok = $false; error = $_.Exception.Message }
}
[Console]::Out.WriteLine()
[Console]::Out.Write((ConvertTo-Json -InputObject $out -Depth 5 -Compress))
