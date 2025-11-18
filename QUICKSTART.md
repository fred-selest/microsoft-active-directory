# 🚀 Guide de Démarrage Rapide - AD Web Manager

## Installation en 3 étapes

### Étape 1 : Vérifier les prérequis
```powershell
# Vérifier que PowerShell 5.1+ est installé
$PSVersionTable.PSVersion

# Vérifier que le module AD est disponible
Get-Module -ListAvailable ActiveDirectory
```

### Étape 2 : Lancer le serveur
```powershell
# Naviguer vers le dossier contenant le script
cd C:\chemin\vers\le\script

# Lancer le serveur (ouvre automatiquement le navigateur)
.\AD-WebManager.ps1
```

### Étape 3 : Se connecter
Dans le navigateur qui s'ouvre automatiquement :
1. **Domaine** : `domain.local` ou `192.168.1.10`
2. **Utilisateur** : `administrateur@domain.local` ou `DOMAIN\admin`
3. **Mot de passe** : Votre mot de passe AD
4. Cliquer sur "Se connecter"

## Premier utilisateur en 5 clics

1. Onglet "➕ Créer un utilisateur"
2. Remplir :
   - Prénom : `Jean`
   - Nom : `Dupont`
3. Cliquer sur "Auto-générer" (génère `jdupont`)
4. Remplir :
   - Mot de passe : `MotDePasse123!`
   - OU : `OU=Users,DC=domain,DC=com`
5. Cliquer sur "Créer l'utilisateur"

✅ Utilisateur créé !

## Recherche et modification rapide

1. Onglet "🔍 Rechercher/Modifier"
2. Taper `jdupont` dans la recherche
3. Cliquer sur "Rechercher"
4. Cliquer sur "Modifier" sur la ligne de Jean Dupont
5. Modifier les informations souhaitées
6. Cliquer sur "Mettre à jour"

## Gérer les groupes en 4 étapes

1. Onglet "👥 Gestion des groupes"
2. Entrer : `jdupont`
3. Cliquer sur "Charger les groupes"
4. Dans "Groupes disponibles" :
   - Rechercher : `Ventes`
   - Sélectionner le groupe
   - Cliquer sur "Ajouter aux groupes sélectionnés"

✅ Jean est maintenant dans le groupe Ventes !

## Export rapide en CSV

1. Onglet "📊 Export/Rapports"
2. Choisir : "Utilisateurs actifs uniquement"
3. Cliquer sur "📥 Exporter en CSV"
4. Choisir l'emplacement de sauvegarde

✅ Liste des utilisateurs actifs exportée !

## Astuces pro 💡

### Astuce 1 : Raccourci auto-génération
Après avoir tapé prénom et nom, appuyez sur `Tab` puis cliquez sur "Auto-générer"

### Astuce 2 : Recherche par partie du nom
Tapez juste "dup" pour trouver tous les Dupont

### Astuce 3 : Sélection multiple de groupes
Maintenez `Ctrl` enfoncé pour sélectionner plusieurs groupes à la fois

### Astuce 4 : Actualisation rapide de l'audit
Raccourci : `F5` dans l'onglet Journal d'audit

### Astuce 5 : Format OU facile à retenir
```
OU=Nom_de_lOU,DC=partie1_domaine,DC=partie2_domaine

Exemple :
Domaine : entreprise.local
OU : Utilisateurs
→ OU=Utilisateurs,DC=entreprise,DC=local
```

## Commandes PowerShell utiles

### Obtenir la liste des OUs
```powershell
Get-ADOrganizationalUnit -Filter * | 
    Select-Object Name, DistinguishedName | 
    Format-Table -AutoSize
```

### Trouver votre domaine
```powershell
(Get-ADDomain).DNSRoot
# Résultat : domain.local
```

### Voir tous les groupes
```powershell
Get-ADGroup -Filter * | 
    Select-Object Name | 
    Sort-Object Name
```

### Tester la connexion AD
```powershell
Test-Connection dc01.domain.local
```

## Résolution des problèmes courants

### ❌ "Le serveur ne démarre pas"
**Solution** : 
```powershell
# Fermer tous les PowerShell, puis relancer en Admin
# Clic droit sur PowerShell > Exécuter en tant qu'administrateur
```

### ❌ "Port 8080 déjà utilisé"
**Solution** : 
```powershell
# Trouver le processus qui utilise le port
netstat -ano | findstr :8080

# Ou changer le port dans le script (ligne 22)
$Port = 9090
```

### ❌ "Session invalide"
**Solution** : 
```
Se déconnecter et se reconnecter
```

### ❌ "Impossible de créer l'utilisateur"
**Vérifications** :
1. L'OU existe-t-elle ? (vérifier avec `Get-ADOrganizationalUnit`)
2. Le login est-il déjà utilisé ?
3. Le mot de passe respecte-t-il la politique ?
4. Avez-vous les droits nécessaires ?

## Interface visuelle

```
┌─────────────────────────────────────────────────────────────┐
│  🔐 AD Manager                         Domaine: domain.local │
│                                         [Déconnexion]        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  [➕ Créer un utilisateur] [🔍 Rechercher/Modifier]          │
│  [👥 Gestion des groupes] [📊 Export/Rapports]               │
│  [📋 Journal d'audit]                                        │
│                                                               │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ╔═══════════════════════════════════════════════════════╗  │
│  ║  Créer un nouvel utilisateur                          ║  │
│  ╚═══════════════════════════════════════════════════════╝  │
│                                                               │
│  Prénom *          [Jean                ]                    │
│  Nom *             [Dupont              ]                    │
│                                                               │
│  Login *           [jdupont             ] [Auto-générer]     │
│  Email             [jdupont@domain.local]                    │
│                                                               │
│  Mot de passe *    [••••••••••••        ]                    │
│  Département       [Commercial          ]                    │
│                                                               │
│  OU *              [OU=Users,DC=domain,DC=com             ]  │
│                                                               │
│  ☑ Activer le compte                                         │
│  ☑ Forcer le changement de mot de passe                      │
│                                                               │
│  [ Créer l'utilisateur ]  [ Effacer ]                        │
│                                                               │
│  ╔═══════════════════════════════════════════════════════╗  │
│  ║ ✓ Utilisateur créé avec succès !                      ║  │
│  ║ Login : jdupont                                        ║  │
│  ║ Nom : Jean Dupont                                      ║  │
│  ╚═══════════════════════════════════════════════════════╝  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Checklist de déploiement

Avant de déployer en production :

- [ ] Module ActiveDirectory installé
- [ ] Compte administrateur AD disponible
- [ ] Port 8080 ouvert dans le firewall
- [ ] Accès réseau au contrôleur de domaine vérifié
- [ ] Script testé sur un utilisateur de test
- [ ] Droits de l'administrateur vérifiés
- [ ] Journal d'audit configuré
- [ ] Documentation distribuée aux administrateurs
- [ ] Plan de sauvegarde en place

## Support et aide

### Documentation complète
Consultez `README-WebManager.md` pour la documentation détaillée.

### Logs
- **Console PowerShell** : Logs en temps réel
- **Fichier audit** : `AD-WebManager-Audit.log`

### Commandes de diagnostic
```powershell
# Version de PowerShell
$PSVersionTable.PSVersion

# Modules chargés
Get-Module

# Test de connexion au DC
Test-Connection -ComputerName dc01.domain.local -Count 2

# Vérifier les ports ouverts
Get-NetTCPConnection -LocalPort 8080
```

## Prochaines étapes

1. ✅ Se connecter à l'interface
2. ✅ Créer un utilisateur de test
3. ✅ Tester la recherche et modification
4. ✅ Gérer les groupes
5. ✅ Exporter un rapport
6. ✅ Consulter le journal d'audit
7. 🎓 Former les autres administrateurs
8. 📝 Adapter la configuration à votre environnement

---

**Besoin d'aide ?**
- Consultez la documentation complète : `README-WebManager.md`
- Vérifiez les logs dans la console PowerShell
- Consultez le journal d'audit : `AD-WebManager-Audit.log`
