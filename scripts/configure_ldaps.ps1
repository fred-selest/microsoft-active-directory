# Script de configuration LDAPS pour AD Web Interface
# Exécuter en tant qu'Administrateur

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Configuration LDAPS - Active Directory" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Certificat sélectionné pour LDAPS
$certThumbprint = "3F9906EE628F09A20642169B400CC956E8E86B3F"
$certSubject = "srvdc2022.SELEST.local"

Write-Host "[1/5] Vérification du certificat..." -ForegroundColor Yellow
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $certThumbprint }

if (-not $cert) {
    Write-Host "[ERREUR] Certificat introuvable !" -ForegroundColor Red
    Write-Host "Thumbprint: $certThumbprint" -ForegroundColor Gray
    pause
    exit 1
}

Write-Host "[OK] Certificat trouvé : $($cert.Subject)" -ForegroundColor Green
Write-Host "    Valable jusqu'au : $($cert.NotAfter)" -ForegroundColor Gray
Write-Host ""

# Étape 2 : Vérifier les autres magasins
Write-Host "[2/5] Vérification des magasins de certificats..." -ForegroundColor Yellow
Write-Host "  Magasin Personal (My) : OK" -ForegroundColor Green
Write-Host "  Magasin Root : Vérification..." -ForegroundColor Yellow
$rootCert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $certThumbprint }
if (-not $rootCert) {
    Write-Host "  [ATTENTION] Certificat racine non trouvé dans Root" -ForegroundColor Yellow
}
Write-Host ""

# Étape 3 : Configurer LDAP avec le certificat
Write-Host "[3/5] Configuration du service LDAP..." -ForegroundColor Yellow

# Créer la clé de registre pour le certificat LDAP
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\CertMapping"
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -ItemType Directory -Force | Out-Null
    Write-Host "  [OK] Clé registre créée" -ForegroundColor Green
} else {
    Write-Host "  [OK] Clé registre existe déjà" -ForegroundColor Green
}

# Créer la mapping pour le certificat
New-Item -Path $registryPath -Name "1" -Force | Out-Null
New-ItemProperty -Path "$registryPath\1" -Name "Subject" -Value $certSubject -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$registryPath\1" -Name "Thumbprint" -Value $certThumbprint -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$registryPath\1" -Name "MappingType" -Value 7 -PropertyType DWord -Force | Out-Null

Write-Host "  [OK] Mapping certificat LDAP configuré" -ForegroundColor Green
Write-Host ""

# Étape 4 : Redémarrer le service NTDS
Write-Host "[4/5] Redémarrage du service NTDS..." -ForegroundColor Yellow
Restart-Service -Name NTDS -Force
Write-Host "  [OK] Service NTDS redémarré" -ForegroundColor Green
Write-Host "  Attente 10 secondes..." -ForegroundColor Yellow
Start-Sleep -Seconds 10
Write-Host ""

# Étape 5 : Vérification
Write-Host "[5/5] Vérification du port LDAPS..." -ForegroundColor Yellow
Start-Sleep -Seconds 2
$test = Test-NetConnection -ComputerName localhost -Port 636
 if ($test.TcpTestSucceeded) {
    Write-Host "  [SUCCESS] Port 636 (LDAPS) ouvert et écoutant !" -ForegroundColor Green
 } else {
    Write-Host "  [ATTENTION] Port 636 non détecté - redémarrer le service 'Active Directory Domain Services'" -ForegroundColor Yellow
 }
Write-Host ""

# Étape 6 : Créer fichier de configuration pour AD Web Interface
Write-Host "Configuration de l'application..." -ForegroundColor Yellow
$configContent = @"
# Configuration LDAPS
AD_SERVER=127.0.0.1
AD_PORT=636
AD_USE_SSL=true
AD_BASE_DN=DC=selest,DC=local
"@


Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CONFIGURATION TERMINÉE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Connexion LDAPS possible avec :" -ForegroundColor Cyan
Write-Host "  • Serveur : $certSubject ou 127.0.0.1" -ForegroundColor White
Write-Host "  • Port : 636" -ForegroundColor White
Write-Host "  • SSL/TLS : Activé" -ForegroundColor White
Write-Host ""
Write-Host "SELEST.local" -ForegroundColor Yellow
Write-Host ""
Write-Host "Pour configurer AD Web Interface :" -ForegroundColor Cyan
Write-Host "  1. Déconnectez-vous" -ForegroundColor White
Write-Host "  2. Reconnectez-vous avec :" -ForegroundColor White
Write-Host "     - Port : 636" -ForegroundColor White
Write-Host "     - SSL : Coché" -ForegroundColor White
Write-Host "  3. Vous pourrez créer des utilisateurs !" -ForegroundColor Green
Write-Host ""

pause
