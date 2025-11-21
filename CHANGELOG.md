# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

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
