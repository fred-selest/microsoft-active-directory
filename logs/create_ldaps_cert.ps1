# Create proper LDAPS certificate with Server Authentication EKU
$Domain = 'SELEST.local'
$DCName = 'srvdc2022.SELEST.local'
$IP = '192.168.10.252'

Write-Output "Creating LDAPS certificate for: $Domain, $DCName, $IP"

# DNS names for the certificate
$DnsNames = @($Domain, $DCName, $IP, 'srvdc2022', 'localhost')

# Create certificate with proper EKU for LDAP Server Authentication
$cert = New-SelfSignedCertificate `
    -DnsName $DnsNames `
    -CertStoreLocation 'Cert:\LocalMachine\My' `
    -KeyExportPolicy Exportable `
    -Provider 'Microsoft RSA SChannel Cryptographic Provider' `
    -NotAfter (Get-Date).AddYears(5) `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1') `  # Server Authentication EKU

Write-Output "Certificate created!"
Write-Output "Thumbprint: $($cert.Thumbprint)"
Write-Output "Subject: $($cert.Subject)"

# Restart NTDS to use the new certificate
Write-Output "Restarting AD service..."
Restart-Service NTDS -Force

Write-Output "Done! LDAPS should now work on port 636"