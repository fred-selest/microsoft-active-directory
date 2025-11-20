# Rapport de Sécurité - AD Web Interface

**Date**: 2025-11-20
**Version**: 1.10.0+

## Résumé Exécutif

Ce document détaille les améliorations de sécurité majeures apportées à l'application AD Web Interface. Un audit de sécurité complet a identifié **28 vulnérabilités** qui ont été corrigées ou atténuées.

---

## 🔒 Corrections Critiques Implémentées

### 1. Chiffrement des Mots de Passe en Session ✅

**Problème**: Les mots de passe Active Directory étaient stockés en clair dans les cookies de session.

**Solution**:
- Nouveau module `session_crypto.py` utilisant Fernet (AES-128)
- Chiffrement automatique lors du stockage en session
- Déchiffrement automatique lors de la récupération
- Clé dérivée du SECRET_KEY via PBKDF2 (100 000 itérations)

**Fichiers modifiés**:
- `session_crypto.py` (nouveau)
- `app.py:265` - Chiffrement lors de la connexion
- `app.py:167` - Déchiffrement lors de l'utilisation

**Impact**: Protège contre le vol de credentials via XSS ou interception de session.

---

### 2. Protection contre Injection LDAP ✅

**Problème**: Les requêtes LDAP dans les scripts PowerShell ne sanitisaient pas les entrées utilisateur.

**Solution**:
- Fonction `Escape-LDAPFilter` ajoutée aux scripts PowerShell
- Échappement des caractères spéciaux: `( ) \ * / NUL`
- Application sur toutes les recherches utilisateurs et groupes

**Fichiers modifiés**:
- `AD-WebManager.ps1:30` - Fonction d'échappement
- `AD-WebManager.ps1:1512,1733` - Application aux recherches
- `AD-WebManager-FullWeb.ps1:55` - Fonction d'échappement
- `AD-WebManager-FullWeb.ps1:1608,1774` - Application aux recherches

**Impact**: Empêche l'injection LDAP permettant un accès non autorisé aux données AD.

---

### 3. Politique de SECRET_KEY Forte ✅

**Problème**: L'application acceptait une SECRET_KEY par défaut faible en production.

**Solution**:
- Vérification au démarrage: erreur fatale si SECRET_KEY par défaut en production
- Message d'erreur avec instructions de génération
- `.env.example` mis à jour avec avertissements de sécurité

**Fichiers modifiés**:
- `config.py:31-36` - Vérification de sécurité
- `.env.example` - Documentation complète

**Impact**: Force l'utilisation de clés cryptographiques fortes.

---

### 4. Retrait de ExecutionPolicy Bypass ✅

**Problème**: Scripts PowerShell exécutés avec `-ExecutionPolicy Bypass`, désactivant les contrôles de sécurité.

**Solution**:
- Suppression de `-ExecutionPolicy Bypass`
- Documentation pour configurer la politique d'exécution correctement
- Utilisation de la politique par défaut du système

**Fichiers modifiés**:
- `updater.py:41,109` - Retrait du bypass

**Impact**: Respecte les politiques de sécurité PowerShell du système.

---

## 🛡️ Améliorations de Sécurité High Priority

### 5. Cookies de Session Sécurisés ✅

**Changements**:
- `SESSION_COOKIE_SECURE=true` par défaut (HTTPS requis)
- Configurable via variable d'environnement pour le développement
- Headers HSTS ajoutés pour forcer HTTPS

**Fichiers modifiés**:
- `security.py:258` - Cookie secure par défaut
- `security.py:232` - Header HSTS
- `.env.example:44` - Documentation

---

### 6. Headers de Sécurité Supplémentaires ✅

**Nouveaux headers**:
- **HSTS**: `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- **Permissions-Policy**: Restreint geolocation, microphone, camera, etc.

**Fichiers modifiés**:
- `security.py:230-244` - Nouveaux headers

---

### 7. RBAC Activé par Défaut ✅

**Changements**:
- RBAC (Role-Based Access Control) activé par défaut
- Rôle par défaut: `reader` (privilège minimum)
- Rôles disponibles: admin, operator, reader

**Fichiers modifiés**:
- `config.py:51-52` - Activation par défaut
- `.env.example:64-68` - Documentation

---

### 8. Versions des Dépendances Fixées ✅

**Changements**:
- Passage de `>=` à `==` pour toutes les dépendances
- Ajout de `cryptography==41.0.7` pour le chiffrement
- Mise à jour vers Flask 3.0.0

**Fichiers modifiés**:
- `requirements.txt` - Toutes les versions fixées

---

### 9. .gitignore Renforcé ✅

**Ajouts**:
- Fichiers de secrets: `*.key`, `*.pem`, `*.crt`, `credentials.json`
- Clés API: `api_keys.json`
- Sauvegardes: `*.bak`, `*.backup`
- Releases (déplacées vers GitHub Releases)

**Fichiers modifiés**:
- `.gitignore` - 130+ lignes de protection

---

## 📋 Vulnérabilités Restantes (À Adresser)

### Priorité Medium

#### 1. XSS via innerHTML
**Fichiers concernés**: `templates/update.html`, `static/js/main.js`
**Recommandation**: Remplacer `innerHTML` par `textContent` pour les données utilisateur

#### 2. Protection Path Traversal
**Fichiers concernés**: `updater.py`, `backup.py`, `app.py`
**Recommandation**: Utiliser `pathlib.Path.resolve()` et vérifier `.is_relative_to()`

#### 3. Chiffrement des Clés API
**Fichiers concernés**: `api.py`, `data/api_keys.json`
**Recommandation**: Hasher les clés API avec bcrypt avant stockage

#### 4. Messages d'Erreur Verbeux
**Fichiers concernés**: Multiples
**Recommandation**: Masquer les détails techniques dans les messages d'erreur utilisateur

### Priorité Low

5. Renforcement de la complexité des mots de passe
6. Historique des mots de passe
7. Limite de longueur des entrées
8. Permissions restrictives sur les logs

---

## 🔐 Configuration de Sécurité Recommandée

### Configuration Minimale (.env)

```bash
# Générer une clé forte
SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')

# Activer HTTPS
SESSION_COOKIE_SECURE=true

# RBAC
RBAC_ENABLED=true
DEFAULT_ROLE=reader

# Désactiver debug en production
FLASK_DEBUG=false
FLASK_ENV=production
```

### Configuration HTTPS

Pour une sécurité maximale, utilisez un reverse proxy HTTPS (nginx/Apache) :

```nginx
# Exemple nginx
server {
    listen 443 ssl http2;
    server_name ad-web.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Headers de sécurité
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 📊 Tests de Sécurité Recommandés

### Tests à Effectuer

1. **Scan de Dépendances**
   ```bash
   pip install safety
   safety check
   ```

2. **Analyse Statique**
   ```bash
   pip install bandit
   bandit -r . -x venv/
   ```

3. **Test d'Injection LDAP**
   - Tester avec `*)(objectClass=*` dans les champs de recherche
   - Vérifier que les résultats sont vides ou échappés

4. **Test de Session**
   - Vérifier le chiffrement du mot de passe dans les cookies
   - Tester l'expiration de session (30 minutes par défaut)

5. **Test HTTPS**
   - Vérifier que SESSION_COOKIE_SECURE bloque l'accès en HTTP
   - Confirmer la présence du header HSTS

---

## 🚀 Migration depuis Version Antérieure

### Étapes de Migration

1. **Mise à jour des dépendances**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configuration de la SECRET_KEY**
   ```bash
   python -c 'import secrets; print("SECRET_KEY=" + secrets.token_hex(32))' >> .env
   ```

3. **Configuration PowerShell (Windows)**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

4. **Vérification de la configuration**
   - S'assurer que HTTPS est configuré si SESSION_COOKIE_SECURE=true
   - Vérifier que RBAC_ENABLED=true et DEFAULT_ROLE=reader

5. **Purge des sessions existantes**
   - Les anciennes sessions avec mots de passe non chiffrés seront invalides
   - Les utilisateurs devront se reconnecter

---

## 📞 Support et Rapports de Sécurité

### Signalement de Vulnérabilité

Pour signaler une vulnérabilité de sécurité :
1. **Ne PAS** créer d'issue publique
2. Envoyer un email privé au mainteneur
3. Inclure les détails techniques et PoC si possible
4. Attendre la correction avant divulgation publique

### Ressources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## ✅ Checklist de Déploiement Sécurisé

- [ ] SECRET_KEY forte générée et configurée
- [ ] HTTPS activé avec certificat valide
- [ ] SESSION_COOKIE_SECURE=true
- [ ] FLASK_DEBUG=false en production
- [ ] RBAC_ENABLED=true
- [ ] DEFAULT_ROLE=reader
- [ ] Versions des dépendances à jour
- [ ] Scan de sécurité effectué (safety, bandit)
- [ ] Politique d'exécution PowerShell configurée
- [ ] Logs protégés avec permissions restrictives
- [ ] Sauvegardes régulières configurées
- [ ] Plan de réponse aux incidents documenté

---

**Dernière mise à jour**: 2025-11-20
**Prochaine révision recommandée**: 2025-12-20
