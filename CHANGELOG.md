# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [1.20.2] - 2026-03-31

### Corrigé

- **Logo manquant (404)** — remplacement de `logo.png` par `static/icons/icon.svg` dans `templates/base.html`.

### Ajouté

- **Dépendance `pycryptodome`** — ajout de `pycryptodome==3.20.0` dans `requirements.txt` pour le support MD4/NTLM Python 3.12+.

---

## [1.20.1] - 2026-03-31

### Corrigé

- **Route `/api/system-info` manquante** — ajout de l'endpoint API retournant version, plateforme, hostname, version Python, état connexion AD et support MD4.

---

## [1.20.0] - 2026-03-31

### Ajouté

- **Modifier un utilisateur** — nouvelle route `GET/POST /users/<dn>/edit` : modification des attributs personnels et professionnels (prénom, nom, email, téléphone, service, fonction, description), changement de mot de passe optionnel, activation/désactivation du compte.
- **Réinitialiser le mot de passe** — nouvelle route `GET/POST /users/<dn>/reset-password` : formulaire dédié avec confirmation et option « forcer le changement à la prochaine connexion ».
- **Activer / Désactiver un utilisateur** — nouvelle route `POST /users/<dn>/toggle` : bascule `userAccountControl` sans quitter la liste. Bouton contextuel (vert = Activer, orange = Désactiver) dans la liste.
- **Dupliquer un utilisateur** — nouvelle route `GET/POST /users/<dn>/duplicate` : clone les attributs professionnels et copie optionnelle de l'appartenance aux groupes.
- **Comparer deux utilisateurs** — nouvelle route `GET/POST /users/compare` : tableau côte à côte de 14 attributs AD avec mise en évidence des différences.
- **Opérations en masse** — nouvelle route `GET/POST /users/bulk` : activer, désactiver, réinitialiser le mot de passe ou supprimer plusieurs utilisateurs en une seule action (backup automatique avant suppression).
- **Gestion des OUs** — nouveau blueprint `ous_bp` avec trois routes : `POST /ous/create`, `GET/POST /ous/<dn>/edit` (description), `POST /ous/<dn>/delete`. Boutons Créer / Modifier / Supprimer dans la page Structure.
- **Modifier un groupe** — nouvelle route `GET/POST /groups/<dn>/edit` : modification de la description du groupe. Bouton Modifier dans la liste des groupes.
- **Déplacer un ordinateur** — nouvelle route `POST /computers/<dn>/move` : déplace vers une OU cible via modal (déjà présent dans l'interface). `list_computers` fournit maintenant aussi `dNSHostName`, `operatingSystemVersion` et la liste des OUs.
- **Gestion des backups** — deux nouvelles routes dans `tools_bp` : `GET /backups` (liste) et `GET /backups/<filename>` (détail) utilisant `get_backups()` et `get_backup_content()` de `backup.py`.

### Corrigé

- **Erreurs 500 sur tous les menus** — tous les `url_for()` des templates (`users.html`, `groups.html`, `computers.html`, `ous.html`) corrigés pour inclure le préfixe Blueprint (`users.list_users`, `groups.list_groups`, etc.). Routes inexistantes supprimées des templates.
- **`group_detail.html` introuvable** — `routes/groups.py` référençait `group_detail.html` alors que le fichier s'appelle `group_details.html` (avec 's') ; corrigé, la page Membres des groupes fonctionne à nouveau.
- **Templates orphelins** — `user_form.html`, `reset_password.html`, `duplicate_user.html`, `group_form.html`, `compare_users_form.html`, `compare_users.html`, `bulk_operations.html`, `backups.html`, `backup_detail.html` : tous les `url_for()` mis à jour avec les bons endpoints Blueprint.
- **Section « Appartenance aux groupes » cassée dans `user_form.html`** — suppression des références à `add_user_to_group` et `remove_user_from_group` (routes inexistantes) qui levaient une `BuildError`.

---

## [1.19.1] - 2026-03-30

### Corrigé

- **`import os` manquant dans `app.py`** — `os._exit(0)` appelé lors du redémarrage post-mise à jour levait un `NameError` ; `import os` ajouté en tête de fichier.
- **`IP_V4_ONLY` inexistant dans `routes/core.py`** — cette constante n'existe pas dans ldap3 ; remplacée par `IP_V4_PREFERRED` (déjà importée) dans le fallback IPv4.
- **`reset_to_defaults` introuvable dans `routes/admin.py`** — la fonction s'appelle `reset_settings` dans `settings_manager.py` ; l'import corrigé évite un `ImportError` sur la réinitialisation des paramètres.
- **`get_audit_logs(page=, per_page=)` dans `app.py`** — paramètres inexistants dans la signature de la fonction ; remplacés par `limit=50`, supprimant le `TypeError` sur la page `/audit`.

---

## [1.19.0] - 2026-03-30

### Corrigé

- **Backup avant suppression d'utilisateur** — `backup_object(conn, dn)` passait la connexion LDAP à la place du type d'objet et omettait l'argument `attributes`, levant un `TypeError` qui empêchait toute suppression. Les attributs sont désormais récupérés via `conn.search()` avant la suppression, puis `backup_object('user', dn, attributes)` est appelé correctement.
- **run_legacy.bat** — simplification et correction d'erreur de syntaxe
- **install_ad.ps1** — fonctionne désormais dans n'importe quel répertoire

### Ajouté

- **Diagnostic automatique** (`diagnostic.py`, `templates/diagnostic.html`) — système de diagnostic et de dépannage accessible depuis l'interface
- **Support MD4/NTLM Python 3.12+** — scripts `fix_md4.ps1`, `fix_md4_final.ps1` et `configure_service.ps1` pour configurer OpenSSL legacy sur Windows ; initialisation OpenSSL centralisée dans `_openssl_init.py`
- **Installation AD** (`install_ad.ps1`) — script d'installation automatique sur contrôleur de domaine

---

## [1.17.5] - 2026-03-30

### Corrigé

- **Démarrage lent (60+ s) — cause racine** — `app.py` utilisait `FLASK_ENV == 'production'` pour choisir Waitress ; si le `.env` existant contenait `FLASK_ENV=development`, Waitress était ignoré et le serveur Flask avec rechargeur automatique démarrait (60+ s). La détection utilise désormais `not config.DEBUG` (lu depuis `FLASK_DEBUG=false`) — indépendant du `.env` existant. Ajout de `use_reloader=False` sur le chemin Flask.
- **Logs vides** — `logging.basicConfig` avec `StreamHandler(sys.stdout)` échouait silencieusement sous `pythonw.exe` (`sys.stdout is None`) et n'ajoutait aucun handler, y compris le `FileHandler`. Remplacement par une configuration manuelle : `FileHandler` toujours ajouté, `StreamHandler` uniquement si stdout disponible.

---

## [1.17.4] - 2026-03-30

### Corrigé

- **Démarrage lent (60+ s)** — `run_server.bat` et `run_legacy.bat` forcent désormais `FLASK_ENV=production` avant de lancer Python ; Waitress (WSGI) remplace le serveur de développement Flask avec rechargeur automatique → démarrage en ~3 secondes
- **Logs vides** — `run.py` configure `logging.FileHandler` vers `logs/server.log` au démarrage, capturant Flask/Waitress même avec `pythonw.exe` (pas de console)
- **`.env` auto-généré** — valeurs par défaut corrigées : `FLASK_ENV=production`, `FLASK_DEBUG=false`

---

## [1.17.3] - 2026-03-30

### Corrigé

- **Démarrage serveur** (`run_server.bat`, `run_legacy.bat`) — timeout d'attente 30 s → 60 s ; message `[OK]` conditionnel au fait que le serveur ait réellement répondu ; message d'avertissement pointe vers `logs\` au lieu de `logs\server.log`
- **Démarrage service** (`install_service.bat`) — vérification post-démarrage 20 s → 40 s

### Nettoyage

- Suppression des fichiers orphelins jamais utilisés : `api.py`, `smtp_service.py`, `powershell_export.py`, `webhooks.py`, `uninstall.py`
- CI (`ci.yml`) : suppression du job `docker-build` (Dockerfile retiré en v1.17.0)
- `templates/update.html` : liste des modules mise à jour

---

## [1.17.2] - 2026-03-30

### Corrigé

- **Installation NSSM** - Résolution des cas d'échec d'installation sur serveurs sans accès internet direct :
  - Après `winget install NSSM.NSSM`, rafraîchissement du PATH depuis le registre Windows et recherche dans `%PROGRAMFILES%\NSSM\` si `where nssm` ne trouve pas l'exécutable
  - Ajout du CDN Chocolatey comme 4e source de téléchargement (`community.chocolatey.org/api/v2/package/nssm`)
  - Gestion des deux structures d'archive : `nssm-2.24\win64\nssm.exe` (nssm.cc) et `tools\nssm-2.24\win64\nssm.exe` (nupkg Chocolatey)

### Amélioré

- **Package Windows** - NSSM est désormais téléchargé et inclus directement dans le ZIP de release via GitHub Actions, éliminant le besoin de téléchargement lors de l'installation sur le serveur

---

## [1.17.1] - 2026-03-29

### Corrigé

- **Workflow release** - Restructuration en job unique (build + upload + release en une étape) pour éviter l'erreur "immutable release" lors de l'upload des assets

---

## [1.17.0] - 2026-03-29

### Amélioré

- **Détection mots de passe expirants** - `check_password_expiring` traite désormais réellement les entrées LDAP et retourne les utilisateurs dont le mot de passe expire dans la fenêtre configurée
- **Comptes inactifs** - `check_inactive_accounts` inclut maintenant les comptes n'ayant jamais eu de `lastLogonTimestamp` (comptes jamais connectés)
- **Cache thread-safe** - Protection du cache mémoire via `threading.Lock` pour éviter les race conditions sous Waitress/Gunicorn multi-thread
- **Connexion AD** - Court-circuit immédiat sur erreur LDAP 49 (identifiants incorrects) sans essayer les autres méthodes d'authentification
- **Installation Windows** - `install_service.bat` génère automatiquement le `.env` avec `SECRET_KEY` aléatoire et ouvre le port pare-feu Windows

### Sécurité

- **Salt PBKDF2 par déploiement** - Remplacement du salt hardcodé par un salt aléatoire de 32 octets persisté dans `data/crypto_salt.bin`, unique par installation

### Logging

- Remplacement de tous les `except: pass` silencieux par des `logger.warning()` avec traceback pour faciliter le diagnostic en production

### Supprimé

- Fichiers Docker (`Dockerfile`, `docker-compose.yml`, `docker-entrypoint.sh`, `.dockerignore`, `DOCKER.md`, workflow `docker-publish.yml`) — non utilisés en déploiement Windows service
- Wizards d'installation (`install.py`, `install.sh`) — remplacés par `install_service.bat`

### Ajouté

- **`GUIDE_INSTALLATION_WINDOWS.md`** - Guide complet en français pour l'installation sur Windows Server (service automatique, accès navigateur, pare-feu, dépannage)

---

## [1.16.4] - 2025-11-22

### Corrige

- **Recherche utilisateur AD** - Extraction du nom sans domaine, recherche alternative, affichage Base DN

---

## [1.16.3] - 2025-11-22

### Ajouté

- **Debug groupes AD** - Affichage des groupes detectes et du role attribue a la connexion

---

## [1.16.2] - 2025-11-22

### Ameliore

- **Redemarrage silencieux** - Apres mise a jour, le serveur redemarre sans fenetre de console sur Windows

---

## [1.16.1] - 2025-11-22

### Corrige

- **Connexion NTLM** - Extraction du domaine depuis le nom du serveur pour la premiere connexion

---

## [1.16.0] - 2025-11-22

### Ajouté

- **Menus conditionnels** - Les menus sont masques selon les permissions de l'utilisateur
- **Fonction has_permission** - Disponible dans les templates pour verifier les droits

### Corrige

- **Detection groupes AD** - Comparaison insensible a la casse pour les noms de groupes
- **PWA** - Correction manifest.json et service worker (icones manquantes)

---

## [1.15.1] - 2025-11-22

### Corrige

- **CI/CD** - Correction pipeline GitHub Actions (SECRET_KEY, Docker load, security scan)
- **Page mise a jour** - Ajout historique des versions recentes

---

## [1.15.0] - 2025-11-22

### Ajouté

- **Attribution roles basee sur groupes AD** - Les roles (admin, operator, reader) sont automatiquement attribues en fonction des groupes AD de l'utilisateur
  - `RBAC_ADMIN_GROUPS` - Groupes AD donnant le role admin (defaut: Domain Admins)
  - `RBAC_OPERATOR_GROUPS` - Groupes AD donnant le role operator
  - `RBAC_READER_GROUPS` - Groupes AD donnant le role reader
  - Le role par defaut s'applique si aucun groupe ne correspond

---

## [1.14.1] - 2025-11-22

### Corrige

- **Import check_for_updates** - Correction de l'import depuis updater_fast (causait Internal Server Error)

---

## [1.14.0] - 2025-11-22

### Ajouté

- **Option changement mot de passe obligatoire** - Checkbox pour forcer l'utilisateur a changer son mot de passe a la prochaine connexion (cochee par defaut)

---

## [1.13.0] - 2025-11-22

### Ajouté

- CI/CD GitHub Actions : ci.yml, release.yml
- Securite : FORCE_HTTPS, X-Forwarded-Proto, TRUSTED_PROXIES

### Ameliore

- Gestion erreurs API
- Documentation .env.example

### Corrige

- Import PBKDF2HMAC
- Fallback repertoire logs

---

## [1.12.0] - 2025-11-21

### Corrigé

- **Création automatique répertoire logs** - Corrige l'erreur FileNotFoundError au démarrage sur Windows

### Supprimé

- Documentation redondante

---

## [1.11.0] - 2025-11-21

### Sécurité (Majeur)

- Chiffrement des mots de passe en session (AES-128 Fernet)
- Protection injection LDAP
- SECRET_KEY obligatoire en production
- Cookies sécurisés, headers HSTS, RBAC activé par défaut

---

## [1.10.0] - 2025-11-20

### Ajouté
- Corrections téléchargement bloqué sur Windows
- Interface web multi-plateforme améliorée

---

## [1.9.0] et antérieures

Voir l'historique git pour les versions précédentes.
