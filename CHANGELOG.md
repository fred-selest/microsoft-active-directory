# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

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

#### Support Docker
- **Dockerfile** - Image Python 3.11-slim optimisee avec Gunicorn
- **docker-compose.yml** - Orchestration avec volumes persistants
- **docker-entrypoint.sh** - Script d'initialisation container
- **.dockerignore** - Exclusions pour build optimise
- **DOCKER.md** - Documentation complete pour deploiement Docker
- **Endpoint /api/health** - Healthcheck pour Docker/Kubernetes

#### CI/CD GitHub Actions
- **ci.yml** - Tests automatiques Python 3.10/3.11/3.12, lint, scan securite
- **docker-publish.yml** - Build et push vers ghcr.io (multi-arch amd64/arm64)
- **release.yml** - Creation automatique de releases avec packages separes
  - Package Windows (.zip) - sans fichiers Linux
  - Package Linux (.tar.gz) - sans fichiers Windows
  - Instructions Docker dans les notes de release

#### Securite
- **FORCE_HTTPS** - Nouvelle option pour redirection automatique HTTP -> HTTPS
- **Support X-Forwarded-Proto** - Compatible reverse proxy (Nginx, Traefik)
- **TRUSTED_PROXIES** - Configuration des proxys de confiance

### Ameliore

- **Gestion erreurs API** - Les endpoints /api/* retournent toujours du JSON (plus de pages HTML d'erreur)
- **Documentation .env.example** - Ajout options HTTPS et proxys

### Corrige

- **Import PBKDF2HMAC** - Correction du nom de classe dans session_crypto.py
- **Fallback repertoire logs** - Utilise ./logs si permissions insuffisantes sur Windows

### Notes de Deploiement Docker

```bash
# Demarrage rapide
docker-compose up -d

# Ou avec image pre-construite
docker pull ghcr.io/fred-selest/microsoft-active-directory:1.13.0
```

Voir [DOCKER.md](DOCKER.md) pour la documentation complete.

---

## [1.12.0] - 2025-11-21

### Corrigé

- **Création automatique répertoire logs** - Corrige l'erreur FileNotFoundError au démarrage sur Windows

### Supprimé

- **README-WebManager.md** - Documentation redondante (intégrée au README principal)
- **QUICKSTART.md** - Guide rapide redondant

### Nettoyage

- Suppression des fichiers de documentation obsolètes
- Réduction de la taille du dépôt

---

## [1.11.0] - 2025-11-21

### Sécurité (Majeur)

#### Corrections Critiques
- **Chiffrement des mots de passe en session** - Les mots de passe AD sont maintenant chiffrés avec AES-128 (Fernet) avant stockage en session
- **Protection injection LDAP** - Nouvelle fonction `Escape-LDAPFilter` dans les scripts PowerShell
- **SECRET_KEY obligatoire** - L'application refuse de démarrer en production sans SECRET_KEY forte

#### Corrections High
- **Cookies sécurisés** - `SESSION_COOKIE_SECURE=true` par défaut (HTTPS requis)
- **Headers HSTS** - `Strict-Transport-Security` ajouté pour forcer HTTPS
- **RBAC activé** - Contrôle d'accès basé sur les rôles activé par défaut (rôle reader)
- **Retrait ExecutionPolicy Bypass** - Scripts PowerShell respectent les politiques système

#### Corrections Medium
- **Protection XSS** - `innerHTML` remplacé par `textContent` pour les données utilisateur
- **Protection Path Traversal** - Validation des chemins dans backup.py
- **Hachage clés API** - Les clés API sont hashées avec PBKDF2-SHA256 (100k itérations)
- **Headers Permissions-Policy** - Restrictions navigateur (geolocation, camera, etc.)

### Ajouté

- **Nouveau module `session_crypto.py`** - Chiffrement des données sensibles en session
- **Nouveau module `path_security.py`** - Validation et sanitization des chemins
- **Nouveau module `updater_fast.py`** - Mise à jour incrémentale rapide
- **Script `uninstall.py`** - Désinstallateur propre avec options
- **Document `SECURITY.md`** - Audit de sécurité complet et recommandations
- **Script `scripts/upload-releases-to-github.sh`** - Migration releases vers GitHub

### Amélioré

- **Mise à jour incrémentale** - Télécharge uniquement les fichiers modifiés (80-95% plus rapide)
- **Téléchargements parallèles** - 5 workers simultanés pour les mises à jour
- **Cache local** - Évite les re-téléchargements inutiles
- **Versions dépendances fixées** - Passage de `>=` à `==` dans requirements.txt
- **Configuration `.env.example`** - Documentation complète avec avertissements sécurité
- **`.gitignore` renforcé** - Protection des secrets, credentials, API keys

### Changé

- **Rôle par défaut** - Changé de `admin` à `reader` (privilège minimum)
- **DEBUG désactivé** - `FLASK_DEBUG=false` par défaut
- **Releases** - Déplacées vers GitHub Releases (économie ~12 Mo dans le dépôt)

### Supprimé

- Fichiers releases du dépôt (disponibles sur GitHub Releases)

### Notes de Migration

1. **Mettre à jour les dépendances**
   ```bash
   pip install -r requirements.txt
   ```

2. **Générer une SECRET_KEY** (obligatoire en production)
   ```bash
   python -c 'import secrets; print(secrets.token_hex(32))'
   ```

3. **Configurer HTTPS** (requis avec SESSION_COOKIE_SECURE=true)

4. **Configurer PowerShell** (Windows)
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

5. **Anciennes sessions invalides** - Les utilisateurs devront se reconnecter

---

## [1.10.0] - 2025-11-20

### Ajouté
- Corrections téléchargement bloqué sur Windows
- Interface web multi-plateforme améliorée

---

## [1.9.0] et antérieures

Voir l'historique git pour les versions précédentes.
