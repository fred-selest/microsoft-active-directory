# 🔐 AD Web Manager

Interface web moderne pour la gestion d'Active Directory avec authentification sécurisée.

## ✨ Caractéristiques

### 🎨 Interface Web Moderne
- Design responsive et professionnel
- Interface à onglets intuitive
- Animations fluides
- Thème violet/gradient élégant

### 🔐 Authentification Sécurisée
- Page de connexion avec saisie des identifiants AD
- Support de plusieurs formats d'identifiants :
  - `administrateur@domain.local`
  - `DOMAIN\admin`
  - Format UPN standard
- Token de session sécurisé
- Déconnexion simple

### 📋 Fonctionnalités Complètes
1. **Création d'utilisateurs**
   - Auto-génération du login
   - Auto-génération de l'email
   - Tous les champs standards

2. **Recherche et modification**
   - Recherche en temps réel
   - Tableau de résultats
   - Modification inline
   - Réinitialisation de mot de passe
   - Désactivation de compte

3. **Gestion des groupes**
   - Liste des groupes de l'utilisateur
   - Recherche de groupes
   - Ajout/retrait par glisser-déposer visuel
   - Protection du groupe "Domain Users"

4. **Export et rapports**
   - Export CSV avec filtres
   - Rapports HTML professionnels
   - Filtrage par type d'utilisateur

5. **Journal d'audit**
   - Traçabilité complète
   - Visualisation dans l'interface
   - Export du journal

## 📦 Prérequis

### Système
- Windows Server 2016+ ou Windows 10/11
- PowerShell 5.1 ou supérieur
- Module ActiveDirectory (RSAT)

### Réseau
- Port 8080 disponible (configurable)
- Accès réseau au contrôleur de domaine

### Droits
- Compte administrateur de domaine pour se connecter
- Droits de création/modification d'utilisateurs

## 🚀 Installation et démarrage

### Méthode 1 : Lancement direct
```powershell
# Lancer le serveur
.\AD-WebManager.ps1

# Le navigateur s'ouvrira automatiquement à http://localhost:8080
```

### Méthode 2 : En tant qu'administrateur
```powershell
# Clic droit sur AD-WebManager.ps1
# > Exécuter avec PowerShell
```

### Configuration du port
Pour changer le port (ligne 22 du script) :
```powershell
$Port = 8080  # Modifier ici
```

## 🔑 Connexion

### Page de connexion
Au démarrage, vous verrez une page de connexion élégante demandant :

1. **Nom de domaine ou serveur DC**
   - Exemples valides :
     - `domain.local`
     - `192.168.1.10`
     - `dc01.entreprise.fr`

2. **Compte administrateur**
   - Formats acceptés :
     - `administrateur@domain.local` (UPN)
     - `DOMAIN\admin` (NetBIOS)
     - `admin` (nom simple si domaine unique)

3. **Mot de passe**
   - Mot de passe du compte administrateur

### Après connexion
Une fois connecté, vous accédez au tableau de bord avec :
- Affichage du domaine en haut à droite
- Bouton de déconnexion
- 5 onglets de fonctionnalités

## 📖 Guide d'utilisation

### Créer un utilisateur
1. Onglet "➕ Créer un utilisateur"
2. Remplir les champs (minimum : prénom, nom, login, mot de passe, OU)
3. Utiliser "Auto-générer" pour créer le login automatiquement
4. Cliquer sur "Créer l'utilisateur"

### Rechercher et modifier
1. Onglet "🔍 Rechercher/Modifier"
2. Entrer un terme de recherche
3. Cliquer sur "Rechercher"
4. Cliquer sur "Modifier" dans la ligne souhaitée
5. Modifier les champs et cliquer sur "Mettre à jour"

### Gérer les groupes
1. Onglet "👥 Gestion des groupes"
2. Entrer le login de l'utilisateur
3. Cliquer sur "Charger les groupes"
4. **Pour ajouter :**
   - Rechercher des groupes disponibles
   - Sélectionner les groupes (cliquer pour sélection multiple)
   - Cliquer sur "Ajouter aux groupes sélectionnés"
5. **Pour retirer :**
   - Sélectionner dans la liste des groupes actuels
   - Cliquer sur "Retirer des groupes sélectionnés"

### Exporter des données
1. Onglet "📊 Export/Rapports"
2. Choisir le type d'export
3. Optionnel : spécifier une OU
4. Choisir "📥 Exporter en CSV" ou "📊 Générer rapport HTML"

### Consulter l'audit
1. Onglet "📋 Journal d'audit"
2. Le journal se charge automatiquement
3. Cliquer sur "🔄 Actualiser" pour voir les dernières entrées

## 🎨 Interface utilisateur

### Palette de couleurs
- **Primaire** : Dégradé violet (#667eea → #764ba2)
- **Succès** : Vert (#28a745)
- **Danger** : Rouge (#dc3545)
- **Warning** : Jaune (#ffc107)
- **Info** : Bleu (#17a2b8)

### Design responsive
- S'adapte aux écrans de toutes tailles
- Optimisé pour desktop et tablette
- Interface moderne avec ombres et animations

## 🔒 Sécurité

### Bonnes pratiques
- ✅ Les identifiants sont stockés en mémoire uniquement
- ✅ Session avec token unique
- ✅ Pas de stockage des mots de passe
- ✅ Journal d'audit de toutes les actions
- ✅ Validation des sessions pour chaque requête

### Limitations de sécurité
- ⚠️ Le serveur écoute en HTTP (non HTTPS)
- ⚠️ Accessible uniquement en local (localhost)
- ⚠️ Pour un usage en production, configurez HTTPS

### Pour sécuriser davantage
1. Utiliser HTTPS avec un certificat
2. Restreindre l'accès par firewall
3. Implémenter une authentification multi-facteurs
4. Mettre en place un reverse proxy (IIS, Apache)

## 📊 Journalisation

### Fichier de log
- **Nom** : `AD-WebManager-Audit.log`
- **Emplacement** : Même répertoire que le script
- **Format** : `timestamp | utilisateur | action | détails`

### Actions enregistrées
- CREATE_USER : Création d'utilisateur
- UPDATE_USER : Modification d'utilisateur
- RESET_PASSWORD : Réinitialisation de mot de passe
- DISABLE_ACCOUNT : Désactivation de compte
- ADD_TO_GROUPS : Ajout à des groupes
- REMOVE_FROM_GROUPS : Retrait de groupes
- EXPORT_CSV : Export de données

## 🛠️ Dépannage

### Le serveur ne démarre pas
**Problème** : "L'accès est refusé"
**Solution** : Lancer PowerShell en tant qu'administrateur

### Impossible de se connecter à AD
**Problème** : "Échec de la connexion"
**Solutions** :
- Vérifier le nom de domaine/serveur DC
- Vérifier les identifiants
- Vérifier la connectivité réseau au DC
- Vérifier que le module ActiveDirectory est installé

### Le module ActiveDirectory n'est pas trouvé
**Solution** :
```powershell
# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell
```

### Le port 8080 est déjà utilisé
**Solution** : Modifier le port dans le script (ligne 22) :
```powershell
$Port = 9090  # Ou un autre port disponible
```

### Les modifications ne s'appliquent pas
**Vérifications** :
- Votre compte a-t-il les droits nécessaires ?
- L'OU existe-t-elle ?
- Le format des données est-il correct ?

## 🔧 Configuration avancée

### Modifier l'OU par défaut
Ligne ~374 du script :
```powershell
value="OU=Users,DC=domain,DC=com"
```

### Changer le format du login auto-généré
Modifier la fonction JavaScript `generateLogin()` (ligne ~443) :
```javascript
// Format actuel : p.dupont
const login = firstName.charAt(0).toLowerCase() + lastName.toLowerCase()

// Alternative : prenom.nom
const login = firstName.toLowerCase() + '.' + lastName.toLowerCase()
```

### Activer HTTPS
Nécessite des modifications avancées :
1. Obtenir un certificat SSL
2. Modifier le listener pour utiliser HTTPS
3. Configurer les bindings de certificat

## 📝 Fonctionnalités futures possibles

- [ ] Support HTTPS natif
- [ ] Interface d'administration multi-domaines
- [ ] Gestion des groupes avec arborescence
- [ ] Statistiques et graphiques en temps réel
- [ ] Notifications par email
- [ ] Import CSV en masse
- [ ] Planification d'actions
- [ ] API REST complète
- [ ] Interface mobile native

## 🆘 Support

### Logs du serveur
Les logs sont affichés dans la console PowerShell :
- Requêtes HTTP avec timestamp
- Résultats des connexions
- Erreurs éventuelles

### Debug
Pour activer le mode verbose :
```powershell
$VerbosePreference = "Continue"
.\AD-WebManager.ps1
```

## 📜 Licence

Ce script est fourni "tel quel" sans aucune garantie. Utilisez-le à vos propres risques.

## 👨‍💻 Contribution

Améliorations bienvenues ! Pour contribuer :
1. Fork le projet
2. Créez une branche pour votre fonctionnalité
3. Committez vos changements
4. Pushez vers la branche
5. Ouvrez une Pull Request

## 🎯 Avantages par rapport à l'interface Windows Forms

| Critère | Interface Web | Windows Forms |
|---------|---------------|---------------|
| **Accessibilité** | ✅ N'importe quel navigateur | ❌ Uniquement sur le poste |
| **Multi-utilisateurs** | ✅ Possible (avec configuration) | ❌ Une instance à la fois |
| **Design** | ✅ Moderne et responsive | ⚠️ Style Windows classique |
| **Maintenance** | ✅ Mise à jour centralisée | ❌ Redéploiement nécessaire |
| **Mobile** | ✅ Accessible depuis mobile | ❌ Impossible |
| **Installation** | ✅ Un seul fichier | ✅ Un seul fichier |

## 📞 Contact

Pour toute question ou problème, veuillez ouvrir une issue sur le dépôt GitHub.

---

**Note** : Ce serveur web est conçu pour un usage interne et des environnements de confiance. Pour un usage en production exposé sur Internet, des mesures de sécurité supplémentaires sont nécessaires.
