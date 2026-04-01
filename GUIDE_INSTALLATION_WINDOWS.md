# Guide d'installation — Interface Web Active Directory
## Serveur Windows → accès navigateur pour les utilisateurs

Ce guide permet d'installer l'application en tant que **service Windows** sur le serveur.
Une fois installée, les utilisateurs accèdent à l'interface directement depuis leur navigateur,
sans rien installer sur leur poste.

---

## Ce qu'il faut préparer

| Prérequis | Détail |
|-----------|--------|
| Système | Windows Server 2016 / 2019 / 2022 (ou Windows 10/11) |
| Compte | Administrateur local sur le serveur |
| Réseau | Le serveur doit pouvoir joindre l'AD sur les ports **389** (LDAP) ou **636** (LDAPS) |
| Internet | Requis uniquement lors de l'installation (pour télécharger Python et NSSM) |

---

## Installation en 3 étapes

### Étape 1 — Télécharger l'application

1. Ouvrez un navigateur sur le serveur
2. Allez sur la page GitHub du projet et téléchargez l'archive ZIP (`main.zip`)
3. Décompressez le ZIP dans un dossier permanent, par exemple :
   ```
   C:\AD-Web\microsoft-active-directory\
   ```

> **Important :** choisissez un chemin **sans accent** ni espace pour éviter tout problème.

---

### Étape 2 — Installer le service Windows

1. Ouvrez l'Explorateur Windows et naviguez dans le dossier décompressé
2. Faites un **clic droit** sur `install_service.bat`
3. Sélectionnez **"Exécuter en tant qu'administrateur"**
4. Le script s'occupe automatiquement de :
   - Installer Python si absent
   - Créer l'environnement virtuel et les dépendances
   - Générer un fichier `.env` avec une clé de sécurité unique
   - Télécharger NSSM (gestionnaire de services)
   - Enregistrer l'application comme service Windows avec démarrage automatique
   - Démarrer le service immédiatement

5. À la fin, le script affiche l'adresse réseau, par exemple :
   ```
   Accès réseau : http://192.168.1.50:5000
   ```

> Si une erreur apparaît, consultez la section **Problèmes fréquents** en bas de ce guide.

---

### Étape 3 — Vérifier que ça fonctionne

Ouvrez un navigateur (sur n'importe quel poste du réseau) et saisissez l'adresse affichée :

```
http://192.168.1.50:5000
```

La page de connexion Active Directory doit s'afficher.

---

## Connexion à Active Directory

Sur la page de connexion, renseignez :

| Champ | Valeur |
|-------|--------|
| Serveur AD | Adresse IP ou nom DNS du contrôleur de domaine (ex : `dc01.entreprise.local`) |
| Nom d'utilisateur | Compte AD avec droits de lecture (ex : `administrateur` ou `user@entreprise.local`) |
| Mot de passe | Mot de passe du compte |
| Base DN | Laissez vide → détection automatique (ex : `DC=entreprise,DC=local`) |

Cliquez sur **Se connecter**.

---

## Communiquer l'adresse aux utilisateurs

Une fois le service démarré, communiquez simplement l'URL réseau à vos utilisateurs.
Ils ouvrent leur navigateur habituel (Chrome, Edge, Firefox…) et saisissent :

```
http://NOM-DU-SERVEUR:5000
```

ou

```
http://192.168.x.x:5000
```

Aucune installation n'est requise sur les postes clients.

---

## Gestion du service

Toutes ces commandes sont à exécuter en **invite de commandes Administrateur** :

```bat
REM Démarrer le service
net start ADWebInterface

REM Arrêter le service
net stop ADWebInterface

REM Voir l'état
sc query ADWebInterface

REM Désinstaller le service
uninstall_service.bat   (clic droit → Exécuter en tant qu'administrateur)
```

Le service est également visible dans **services.msc** sous le nom
`Interface Web Active Directory`.

---

## Fichiers de logs

En cas de problème, consultez les fichiers dans le dossier `logs\` de l'application :

| Fichier | Contenu |
|---------|---------|
| `logs\service.log` | Journaux de fonctionnement normal |
| `logs\service_error.log` | Erreurs du service |

---

## Mise à jour de l'application

1. Arrêtez le service : `net stop ADWebInterface`
2. Téléchargez la nouvelle version et décompressez-la dans le même dossier
   (les fichiers `.env` et `data\` ne sont pas écrasés)
3. Redémarrez le service : `net start ADWebInterface`

---

## Problèmes fréquents

### "Droits administrateur requis"
Faites un clic droit sur `install_service.bat` → **Exécuter en tant qu'administrateur**.

### "Impossible de se connecter à AD"
- Vérifiez que le pare-feu Windows autorise le port **389** (ou **636**) sortant
- Testez la connexion : `telnet dc01.entreprise.local 389`
- Essayez l'adresse IP du contrôleur de domaine plutôt que son nom DNS

### Erreur MD4 / NTLM avec Python 3.12
Le script `install_service.bat` configure automatiquement le support NTLM via `openssl_legacy.cnf`.
Si le problème persiste, utilisez `run_legacy.bat` à la place de `run_server.bat`.

### Port 5000 déjà utilisé
Ajoutez la ligne suivante dans le fichier `.env` :
```
AD_WEB_PORT=8080
```
Puis redémarrez le service.

### Le service démarre mais l'interface est inaccessible depuis d'autres postes
La règle de pare-feu est créée automatiquement par `install_service.bat`.
Si elle a été supprimée manuellement, recréez-la :
```bat
netsh advfirewall firewall add rule name="AD Web Interface" dir=in action=allow protocol=TCP localport=5000
```

---

## Architecture résumée

```
┌─────────────────────────────────┐
│      Serveur Windows            │
│  ┌──────────────────────────┐   │
│  │  Service ADWebInterface  │   │
│  │  (Python + Flask)        │   │
│  │  Port 5000               │   │
│  └────────────┬─────────────┘   │
│               │ LDAP/LDAPS      │
│  ┌────────────▼─────────────┐   │
│  │  Contrôleur de domaine   │   │
│  │  Active Directory        │   │
│  └──────────────────────────┘   │
└───────────────┬─────────────────┘
                │ HTTP réseau local
     ┌──────────┴──────────┐
     │   Postes clients    │
     │  (navigateur web)   │
     └─────────────────────┘
```

---

## Sécurité recommandée pour la production

- Activez **LDAPS** (port 636) pour chiffrer les communications avec l'AD
- Placez un **reverse proxy IIS ou nginx** devant l'application avec un certificat SSL,
  afin que les utilisateurs accèdent en `https://`
- Limitez l'accès au port 5000 au réseau interne uniquement (règle de pare-feu)
- Le fichier `.env` contient la `SECRET_KEY` — ne le partagez pas et ne le commitez pas
