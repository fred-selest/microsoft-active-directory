# Test LDAPS
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect('192.168.10.252', 636)
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream())
    $ssl.AuthenticateAsClient('SELEST.local', $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
    if ($ssl.IsAuthenticated) {
        Write-Output "SUCCESS: LDAPS works!"
        Write-Output "Remote cert: $($ssl.RemoteCertificate.Subject)"
    }
    $tcp.Close()
} catch {
    Write-Output "ERROR: $_"
}