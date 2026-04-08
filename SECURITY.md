# 🔐 Sécurité - AD Web Interface

**Dernière mise à jour**: Avril 2026  
**Version**: 1.36.0

## Résumé Exécutif

Ce document détaille les mesures de sécurité implémentées dans l'application AD Web Interface.

---

## 🔒 Protections Implémentées

### 1. Chiffrement des Mots de Passe en Session ✅

**Problème**: Les mots de passe Active Directory étaient stockés en clair dans les sessions.

**Solution**:
- Module `core/session_crypto.py` utilisant Fernet (AES-128)
- Chiffrement automatique lors du stockage en session
- Clé dérivée du SECRET_KEY via PBKDF2 (100 000 itérations)

**Fichiers**:
- `core/session_crypto.py`
- `routes/core.py` - Chiffrement/déchiffrement

---

### 2. Protection contre Injection LDAP ✅

**Solution**:
- Fonction `escape_ldap_filter()` dans `core/security.py`
- Échappement des caractères spéciaux : `( ) \ * / NUL`
- Application sur toutes les recherches LDAP

---

### 3. Protection CSRF ✅

**Solution**:
- Token CSRF généré pour chaque session
- Validation sur toutes les requêtes POST
- Fonction `validate_csrf_token()` dans `core/security.py`

---

### 4. Rate Limiting ✅

**Solution**:
- 5 tentatives de login / 5 minutes
- 10 tentatives d'actions sensibles / 5 minutes
- Blocage temporaire avec notification

---

### 5. Headers de Sécurité HTTP ✅

**Headers implémentés**:
- `Content-Security-Policy`
- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security`
- `Referrer-Policy`
- `Permissions-Policy`

---

### 6. Permissions Granulaires ✅

**Solution**:
- 40 permissions configurables par groupe AD
- Rôles : admin, operator, readonly, custom
- Décorateurs `@require_permission()` sur les routes

---

### 7. Journalisation des Actions ✅

**Solution**:
- Audit complet dans `data/audit_log.csv`
- Historique conservé dans `data/audit_history/`
- Export PDF/CSV disponible

---

### 8. Analyse Automatique des Logs (v1.36) ✅

**Solution**:
- Module `core/log_analyzer.py`
- Détection automatique des erreurs critiques
- Alertes sur : LDAP, auth, permissions, SSL, dépendances
- Corrections automatiques disponibles

---

## 🛡️ Bonnes Pratiques

### Pour les Administrateurs

1. **Changer la SECRET_KEY** par défaut
2. **Activer LDAPS** pour les connexions
3. **Configurer le rate limiting** selon vos besoins
4. **Sauvegarder régulièrement** `data/settings.json` et `data/crypto_salt.bin`
5. **Surveiller les logs** via `/admin/log-analysis`

### Pour les Développeurs

1. **Toujours utiliser** `@require_connection` et `@require_permission`
2. **Valider les tokens CSRF** sur les POST
3. **Échapper les filtres LDAP** avec `escape_ldap_filter()`
4. **Logger les actions** avec `core.audit.log_action()`
5. **Ne jamais stocker** de mots de passe en clair

---

## 📋 Checklist de Sécurité

- [x] Chiffrement des sessions
- [x] Protection CSRF
- [x] Rate limiting
- [x] Headers HTTP sécurisés
- [x] Permissions granulaires
- [x] Audit des actions
- [x] Analyse automatique des logs
- [x] Protection injection LDAP
- [x] Gestion sécurisée des erreurs

---

## 🚨 Signaler une Vulnérabilité

Pour signaler une vulnérabilité de sécurité, merci de contacter :
- Email : [à définir]
- GitHub Issues : https://github.com/fred-selest/microsoft-active-directory/issues

**Ne créez pas d'issue publique pour les vulnérabilités critiques.**

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
