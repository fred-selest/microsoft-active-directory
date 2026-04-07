# ==============================================================================
# Installation automatique certificat LDAPS - AD Web Interface
# Executez ce script en PowerShell ADMINISTRATEUR
# ==============================================================================

# Verification des droits admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERREUR: Executez ce script en tant qu'Administrateur!" -ForegroundColor Red
    pause
    exit 1
}


$ErrorActionPreference = 'Stop'
$Domain = (Get-ADDomain).DNSRoot
$DCName = "$env:COMPUTERNAME.$Domain"  
$IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' } | Select-Object -First 1).IPAddress

Write-Host "Creation certificat LDAPS pour: $Domain, $DCName, $IP" -ForegroundColor Yellow

$DnsNames = @($Domain, $DCName, $IP, $env:COMPUTERNAME, "localhost")

$cert = New-SelfSignedCertificate `
    -DnsName $DnsNames `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyExportPolicy Exportable `
    -Provider "Microsoft RSA SChannel Cryptographic Provider" `
    -NotAfter (Get-Date).AddYears(5) `
    -KeyLength 2048 `
    -HashAlgorithm SHA256

Write-Host "SUCCESS: Certificat cree - Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green

# Redemarrer NTDS
Write-Host "Redemarrage du service AD..." -ForegroundColor Yellow
Restart-Service NTDS -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5

# Verifier LDAPS
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect("localhost", 636)
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream())
    $ssl.AuthenticateAsClient($DCName)
    if ($ssl.IsAuthenticated) {
        Write-Host "SUCCESS: LDAPS actif sur port 636!" -ForegroundColor Green
    }
    $tcp.Close()
} catch {
    Write-Host "WARNING: Redemarrage du serveur peut etre necessaire" -ForegroundColor Yellow
}

return @{
    success = $true
    thumbprint = $cert.Thumbprint
    subject = $cert.Subject
    notAfter = $cert.NotAfter.ToString('yyyy-MM-dd')
} | ConvertTo-Json


Write-Host ""
Write-Host "Termine! Reconnectez-vous a l'interface web avec SSL active." -ForegroundColor Green
Read-Host "Appuyez sur Entree pour fermer"
