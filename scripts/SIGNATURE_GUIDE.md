# 📜 Signature des Scripts PowerShell - AD Web Interface

## 🔍 Pourquoi Signer les Scripts ?

Windows bloque l'exécution des scripts PowerShell non signés pour des raisons de sécurité. La signature Authenticode :

- ✅ Prouve l'authenticité du script
- ✅ Garantit que le script n'a pas été modifié
- ✅ Évite les avertissements Windows SmartScreen
- ✅ Permet l'exécution avec une policy `AllSigned`

---

## 🚀 Signature Automatique (Recommandé)

### Méthode 1 : Script Batch (Plus Simple)

1. **Ouvrir en tant qu'administrateur** :
   - Cliquez droit sur `scripts\sign_all.bat`
   - Sélectionnez "Exécuter en tant qu'administrateur"

2. **Attendre la fin** :
   - Le script crée automatiquement un certificat
   - Signe tous les fichiers `.ps1`
   - Affiche un résumé

3. **Vérifier** :
   ```powershell
   Get-AuthenticodeSignature -FilePath .\scripts\install_standalone.ps1
   ```

### Méthode 2 : PowerShell (Plus de Contrôle)

**Ouvrir PowerShell en tant qu'administrateur :**

```powershell
cd C:\AD-WebInterface\scripts

# Créer le certificat (one-time)
.\sign_scripts.ps1 -CreateCert

# Signer tous les scripts
.\sign_scripts.ps1

# Vérifier les signatures
.\sign_scripts.ps1 -Verify
```

---

## 🔧 Signature Manuelle (Alternative)

### Étape 1 : Créer un Certificat

```powershell
# PowerShell en tant qu'administrateur
$cert = New-SelfSignedCertificate -DnsName "AD Web Interface" `
                                   -CertStoreLocation "Cert:\LocalMachine\My" `
                                   -Type CodeSigningCert `
                                   -KeyUsage DigitalSignature `
                                   -NotAfter (Get-Date).AddYears(2)

# Exporter le certificat public
Export-Certificate -Cert $cert -FilePath "C:\AD-WebInterface\scripts\codesign.cer"

# Importer dans Trusted Root
Import-Certificate -FilePath "C:\AD-WebInterface\scripts\codesign.cer" `
                   -CertStoreLocation "Cert:\LocalMachine\Root"
```

### Étape 2 : Signer les Scripts

```powershell
# Signer un script spécifique
Set-AuthenticodeSignature -FilePath ".\scripts\install_standalone.ps1" `
                          -Certificate $cert `
                          -TimestampServer "http://timestamp.digicert.com"

# Signer tous les scripts
Get-ChildItem .\scripts\*.ps1 | ForEach-Object {
    Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $cert
}
```

### Étape 3 : Vérifier

```powershell
# Vérifier un script
Get-AuthenticodeSignature -FilePath ".\scripts\install_standalone.ps1"

# Devrait afficher : Status : Valid
```

---

## ✅ Vérification des Signatures

### Script Individuel

```powershell
Get-AuthenticodeSignature -FilePath .\scripts\install_standalone.ps1
```

**Résultat attendu :**
```
Status            : Valid
SignerCertificate : [Certificat AD Web Interface]
TimestampServer   : http://timestamp.digicert.com
```

### Tous les Scripts

```powershell
.\scripts\sign_scripts.ps1 -Verify
```

**Résultat attendu :**
```
  [✓ Valide]       scripts\install_standalone.ps1
  [✓ Valide]       scripts\fix_md4.ps1
  ...
  
  Signatures valides : 15
  Signatures invalides : 0
  Scripts non signés : 0
```

---

## 🔐 Gestion des Certificats

### Voir les Certificats de Signature

```powershell
Get-ChildItem -Path Cert:\LocalMachine\My -CodeSigningCert
```

### Supprimer un Certificat Expiré

```powershell
# Trouver l'empreinte du certificat expiré
Get-ChildItem -Path Cert:\LocalMachine\My -CodeSigningCert | 
    Where-Object { $_.NotAfter -lt (Get-Date) }

# Supprimer (remplacer THUMBPRINT)
Remove-Item -Path "Cert:\LocalMachine\My\THUMBPRINT" -Force
```

### Renouveler un Certificat

```powershell
# Supprimer l'ancien certificat
Get-ChildItem -Path Cert:\LocalMachine\My -CodeSigningCert | 
    Where-Object { $_.Subject -like "*AD Web Interface*" } |
    Remove-Item -Force

# Créer un nouveau certificat
.\scripts\sign_scripts.ps1 -CreateCert

# Re-signer tous les scripts
.\scripts\sign_scripts.ps1
```

---

## 🛠️ Résolution des Problèmes

### Problème : "Accès Refusé"

**Solution :** Exécuter PowerShell en tant qu'administrateur

### Problème : "Certificate Not Found"

**Solution :**
```powershell
# Vérifier que le certificat est dans Trusted Root
Get-ChildItem -Path Cert:\LocalMachine\Root | 
    Where-Object { $_.Subject -like "*AD Web Interface*" }

# Si absent, réimporter
Import-Certificate -FilePath ".\scripts\codesign.cer" `
                   -CertStoreLocation "Cert:\LocalMachine\Root"
```

### Problème : "Hash Mismatch"

**Cause :** Le script a été modifié après signature

**Solution :** Re-signer le script
```powershell
Set-AuthenticodeSignature -FilePath ".\scripts\install_standalone.ps1" `
                          -Certificate $cert
```

### Problème : "Timestamp Server Unavailable"

**Solution :** Signer sans timestamp (moins sécurisé)
```powershell
Set-AuthenticodeSignature -FilePath ".\scripts\install_standalone.ps1" `
                          -Certificate $cert `
                          -TimestampServer $null
```

---

## 📋 Checklist de Signature

- [ ] PowerShell ouvert en tant qu'administrateur
- [ ] Certificat créé dans `Cert:\LocalMachine\My`
- [ ] Certificat importé dans `Cert:\LocalMachine\Root`
- [ ] Tous les scripts signés
- [ ] Signatures vérifiées avec `Get-AuthenticodeSignature`
- [ ] Script `install_standalone.ps1` exécutable sans avertissement

---

## 🎯 Prochaines Étapes

Après la signature :

1. **Tester l'installation** :
   ```powershell
   .\scripts\install_standalone.ps1
   ```

2. **Vérifier qu'aucun avertissement n'apparaît**

3. **Déployer en production**

---

## 📚 Références

- [About Code Signing](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/about/about_code_signing)
- [Set-AuthenticodeSignature](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)
- [New-SelfSignedCertificate](https://docs.microsoft.com/en-us/powershell/module/pkiclient/new-selfsignedcertificate)

---

**Dernière mise à jour :** Avril 2026  
**Version :** 1.36.2

