# ensure_service_running.ps1
# Filet de securite post-mise a jour : verifie, apres un delai, que le
# service ADWebInterface tourne reellement et le redemarre sinon.
#
# Contexte (voir routes/api.py::_do_restart) : apres une mise a jour, le
# service se redemarre via WinSW "restart!" (self-restart). Popen() reussit
# des lors que winsw.exe a pu etre lance, meme si le redemarrage echoue
# ensuite en interne (port encore occupe par l'ancien process, verrou de
# fichier, etc.) — et comme il s'agit d'un arret volontaire (pas un crash),
# la regle <onfailure> de WinSW ne se declenche pas pour le rattraper : le
# service reste alors proprement a l'arret, sans aucune alerte.
#
# Ce script est lance en processus detache, independant du service qu'il
# surveille : il continue de tourner meme apres que restart! ait tue le
# process courant.
#
# Usage : powershell -File ensure_service_running.ps1 [-DelaySeconds 45] [-ServiceName ADWebInterface]

param(
    [int]$DelaySeconds = 45,
    [string]$ServiceName = "ADWebInterface"
)

$ErrorActionPreference = "Continue"
$logDir = Join-Path $PSScriptRoot "..\logs"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
$logFile = Join-Path $logDir "ensure_service_running.log"

function Write-Log($message) {
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $message
    Add-Content -Path $logFile -Value $line
}

Write-Log "Demarrage de la verification differee ($DelaySeconds s) pour le service '$ServiceName'"
Start-Sleep -Seconds $DelaySeconds

try {
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
} catch {
    Write-Log "ECHEC : service '$ServiceName' introuvable ($_)"
    exit 1
}

if ($service.Status -eq 'Running') {
    Write-Log "OK : le service tourne deja (redemarrage reussi sans intervention)."
    exit 0
}

Write-Log "ALERTE : le service est '$($service.Status)' au lieu de 'Running' — demarrage explicite."

try {
    Start-Service -Name $ServiceName -ErrorAction Stop
    Start-Sleep -Seconds 5
    $service.Refresh()
    if ($service.Status -eq 'Running') {
        Write-Log "OK : demarrage explicite reussi."
        exit 0
    } else {
        Write-Log "ECHEC : le service est '$($service.Status)' apres Start-Service — intervention manuelle requise."
        exit 1
    }
} catch {
    Write-Log "ECHEC : Start-Service a leve une exception : $_"
    exit 1
}
