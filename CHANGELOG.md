# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),

## [1.37.7] - 2026-04-09

### Corrigé

- **Dashboard — Accès rapide** : boutons qui débordent du conteneur. Remplacement du `flex` par un `grid` (`auto-fill, minmax(170px, 1fr)`) pour une répartition uniforme quelle que soit la largeur. Sur mobile : 2 colonnes.

---

## [1.37.6] - 2026-04-09

### Corrigé

- **Mise à jour depuis l'interface** : `ImportError` silencieux — `api.py` importait `perform_update_fast` mais la fonction s'appelait `perform_fast_update`. Renommage + alias de compatibilité.
- **Vitesse de mise à jour** : l'updater téléchargeait chaque fichier individuellement (200+ requêtes HTTP). Remplacé par le téléchargement du ZIP complet du dépôt (1 seule requête) puis extraction locale — mise à jour en quelques secondes au lieu de plusieurs minutes.

---

## [1.37.5] - 2026-04-09

### Ajouté

- **🔍 Filtres avancés sur /users/** : dropdown OU, filtre Actifs/Désactivés, bouton Effacer
- **🔍 Filtres avancés sur /computers/** : dropdown OU, filtre Actifs/Désactivés, filtre OS, bouton Effacer

### Corrigé

- **Ordinateurs manquants** : `conn.search()` était limité à 1000 résultats par défaut (limite AD). Remplacement par `paged_search` (pages de 500) pour récupérer tous les objets sans troncature silencieuse. Même correction appliquée aux utilisateurs.

---

et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [1.37.4] - 2026-04-09

### Amélioré

- **🔒 Bouton "Se reconnecter en LDAPS" sur la page de création d'utilisateur** (`templates/create_user.html`, `routes/main.py`)
  - Le bandeau d'avertissement LDAP non chiffré affichait seulement un lien texte
  - Remplacement par un bouton visible qui redirige vers `/connect?suggest_ssl=1`
  - Le formulaire de connexion est automatiquement pré-rempli avec port 636 et SSL coché

---

## [1.37.3] - 2026-04-09

### Corrigé

- **🔌 Fallback LDAP port 389 après échec LDAPS** (`routes/core.py`)
  - Quand LDAPS (636) échouait avec `WinError 10054` (SSL reset), le code retournait immédiatement sans essayer le port 389
  - Login impossible sur tout DC sans certificat LDAPS valide, même si LDAP/389 fonctionnait
  - Correction : seule une erreur d'identifiants incorrects déclenche un retour immédiat ; toute autre erreur (SSL, réseau, timeout) laisse `_try_connection()` essayer toutes les méthodes (NTLM/389, STARTTLS/389, LDAPS/636)

- **🔐 Routes API retournent JSON 401 au lieu de redirect HTML** (`routes/core.py`)
  - Le décorateur `@require_connection` faisait un redirect HTML vers `/connect` pour toutes les requêtes non authentifiées
  - Les appels AJAX (ex: bouton "Installer la mise à jour") recevaient du HTML → erreur JavaScript `Unexpected token '<', "<!DOCTYPE"... is not valid JSON`
  - Correction : retour `{"error": "Non connecté", "redirect": "/connect"}` avec status 401 pour les requêtes `/api/*`, JSON ou `X-Requested-With: XMLHttpRequest`

- **🛡️ Page `/update` protégée par authentification** (`routes/admin_tools.py`)
  - La page de mise à jour était accessible sans être connecté, permettant de déclencher une mise à jour sans session valide
  - Correction : `@require_connection` + `@require_permission('admin')` ajoutés ; `connected=True` corrigé dans le template

### Impact

- Login fonctionne sur tous les DC, même sans LDAPS configuré
- LAPS accessible dès le premier lancement (auto-détection `ms-Mcs-AdmPwd`)
- Mise à jour via l'interface fonctionne correctement pour les admins connectés

---

## [1.37.2] - 2026-04-09

### Corrigé

- **⏱️ Timeout de session : 30 secondes au lieu de 30 minutes** (`app.py`)
  - `PERMANENT_SESSION_LIFETIME` était assigné avec la valeur en minutes (`30`) alors que Flask attend des secondes
  - Les sessions expiraient après 30 secondes, forçant les utilisateurs à se reconnecter en permanence
  - Correction : utilisation de `config.PERMANENT_SESSION_LIFETIME` (déjà calculé en secondes dans `config.py`)

- **🔒 Sécurité : DEFAULT_ROLE=admin dans l'installateur DC** (`scripts/install_ad.ps1`)
  - L'installateur pour contrôleur de domaine générait un `.env` avec `DEFAULT_ROLE=admin`
  - Tout utilisateur AD authentifié obtenait les droits administrateur complets par défaut
  - Correction : `DEFAULT_ROLE=reader` (principe du moindre privilège, cohérent avec `config.py`)

- **🔧 OPENSSL_CONF manquant dans install_standalone.ps1**
  - Le service installé via `install_standalone.ps1` n'héritait pas de `OPENSSL_CONF`
  - NTLM/MD4 non fonctionnel sur Python 3.12+ avec cet installateur
  - Correction : ajout de `AppEnvironmentExtra OPENSSL_CONF` via NSSM si `openssl_legacy.cnf` est présent

- **🔐 Routes API non protégées** (`routes/api.py`)
  - `/api/alerts`, `/api/perform-update`, `/api/errors` et 3 autres routes accessibles sans authentification
  - `/api/perform-update` permettait de redémarrer l'application sans session valide
  - Correction : `@require_connection` (et `@require_permission('admin')` pour les routes critiques) ajoutés

- **📝 Incohérences de configuration** (`.env.example`, `install_service.bat`, `app.py`)
  - `.env.example` proposait `FLASK_DEBUG=true` / `FLASK_ENV=development` en contradiction avec la production
  - `install_service.bat` ne générait pas `SESSION_TIMEOUT=30` dans le `.env`
  - `SESSION_COOKIE_NAME` retourné par `get_secure_session_config()` n'était jamais appliqué à Flask

### Corrigé (mineur)

- `AppName` dans `install_standalone.ps1` harmonisé : `Interface Web Active Directory` (cohérent avec les autres installateurs)
- `VERSION` mis à jour vers `1.37.2`
- Variable morte `_api_keys_store` supprimée de `routes/tools/misc.py`

---

## [1.37.1] - 2026-04-08

### Corrigé

- **🔐 Login inaccessible après installation** (`install_service.bat`, `install_standalone.ps1`)
  - `SESSION_COOKIE_SECURE` était `true` par défaut alors que le service tourne en HTTP (port 5000)
  - Le navigateur rejetait le cookie de session sur HTTP → token CSRF invalide à chaque soumission du formulaire de connexion
  - Correction : `SESSION_COOKIE_SECURE=false` ajouté explicitement dans le `.env` généré par les deux installateurs

- **💥 Installation avortée avec NSSM** (`install_service.bat`)
  - Après l'installation réussie du service via NSSM, le script tombait en chute libre dans le bloc WinSW (`:install_with_winsw`) faute d'un `goto`
  - WinSW étant absent dans ce chemin, le script échouait avec `[ERREUR] Echec de l'installation du service avec WinSW` et quittait sans démarrer le service
  - Correction : ajout de `goto :after_service_install` après le bloc NSSM et du label correspondant après le bloc WinSW

- **📜 Signature Authenticode invalide** (`scripts/install_standalone.ps1`)
  - Le bloc `SIG # Begin signature block` embarqué dans le script était devenu invalide (hash mismatch) suite aux modifications du fichier
  - Windows refusait d'exécuter le script avec les politiques `AllSigned` ou `RemoteSigned`
  - Correction : suppression du bloc de signature invalide ; re-signer avec `scripts/sign_scripts.ps1` si requis par la politique d'exécution

### Testé

- Installation complète validée sur Windows Server 2022 (`srvdc2022`)
- Service `ADWebInterface` démarre en `Automatic` sans erreur
- Token CSRF correctement reçu et validé → connexion AD opérationnelle end-to-end

## [1.36.0] - 2026-04-08

### Ajouté

- **📊 Analyse Automatique des Logs** (`/admin/log-analysis`)
  - Analyse au démarrage de l'application
  - Détection automatique des erreurs critiques
  - Corrections automatiques disponibles
  - Historique des analyses avec export
  - Nouveaux modules : `core/log_analyzer.py`, `core/scripts_manager.py`

- **🛠️ Gestion des Scripts PowerShell** (`/admin/scripts`)
  - Exécution depuis l'interface web
  - Téléchargement des scripts
  - Historique des exécutions
  - 9 scripts disponibles :
    - `fix_md4_final.ps1` - Correctif MD4/NTLM
    - `fix_ntlm.ps1` - Configuration NTLM
    - `fix_ldap_signing.ps1` - LDAP Signing
    - `fix_channel_binding.ps1` - Channel Binding Tokens
    - `fix_smbv1.ps1` - Désactiver SMBv1
    - `install_ad.ps1` - Installation sur DC
    - `configure_service.ps1` - Configuration service
    - `laps_management.ps1` - Gestion LAPS
    - `configure_ldaps.ps1` - Configuration LDAPS

- **📁 Page /ous/ Enrichie**
  - Statistiques globales (OUs, users, groups, computers)
  - Barre de recherche textuelle
  - Filtres par type d'objet (avec users, groups, computers, vides)
  - Badges cliquables vers users/groups/computers
  - Export CSV des données
  - Confirmation renforcée pour suppression

- **🔧 Page /diagnostic/ Améliorée**
  - 19 tests au lieu de 8
  - Informations système détaillées (plateforme, Python, RAM, disque)
  - Export du rapport en TXT
  - Section avertissements dédiée
  - Nouveaux checks : DNS, Internet, logs, configuration

- **Documentation**
  - 9 fichiers README créés (core, routes, templates, static, scripts, data, nssm, tests, password_audit)
  - QWEN.md mis à jour
  - SCRIPTS_MANAGER.md créé

### Corrigé

- **Page /tools/expiring/**
  - Format de date français (DD/MM/YYYY)
  - Exclusion des comptes système (krbtgt, Invité, DefaultAccount)
  - Exclusion des comptes ordinateurs (se terminant par $)
  - Affichage "Aucune" pour les comptes sans expiration
  - Tri des résultats par date

- **Gestion des erreurs LDAP**
  - Meilleure gestion des erreurs de connexion
  - Logs détaillés pour débogage

- **Audit des mots de passe**
  - Exclusion des comptes système dans les rapports
  - Correction des dates 1601 (valeurs AD vides)

### Tests

- **27 tests unitaires** pour `scripts_manager`
- **Couverture des API** scripts
- **Tous les tests passent** ✅

### Statistiques

- **47 fichiers** modifiés/créés
- **+9224 lignes** ajoutées
- **-176 lignes** supprimées

## [1.35.0] - 2026-04-07

### Ajouté

- **📧 Configuration SMTP** — Page Admin → Configuration SMTP avec :
  - Serveur, port, TLS, authentification
  - Email d'expédition et nom d'expéditeur
  - Test d'envoi d'email en direct
- **🔍 Audit sécurité amélioré** — Exclusion des groupes système Windows :
  - 80+ groupes système exclus (Domain Computers, Administrators, etc.)
  - Groupes French/English supportés
  - Patterns SID et BUILTIN exclus automatiquement

### Corrigé

- **Audit sécurité - faux positifs** — Groupes système incorrectement listés comme "vides" :
  - `Ordinateurs du domaine` (Domain Computers) — membres implicites
  - `WseManagedGroups` — Windows Server Essentials
  - `DnsUpdateProxy` — DNS dynamique
  - `Contrôleurs de domaine en lecture seule` — RODC
  - `Contrôleurs de domaine clonables` — Cloneable DC
  - `Administrateurs clés` — Key Admins (FR)
  - +70 autres groupes système exclus

### Modifié

- **`settings_manager.py`** — Section `smtp` ajoutée aux DEFAULT_SETTINGS
- **`routes/admin.py`** — Routes `/save/smtp` et `/test/smtp` ajoutées
- **`templates/admin.html`** — Section Configuration SMTP avec formulaire et test
- **`security_audit.py`** — Fonction `check_empty_security_groups()` refactorisée :
  - Liste EXCLUDED_GROUPS étendue (80+ groupes)
  - Liste EXCLUDED_PATTERNS pour SID et groupes générés
  - Logging détaillé pour débogage
- **`app.py`** — TEMPLATES_AUTO_RELOAD activé même en production (dev friendly)

## [1.33.0] - 2026-04-05

### Ajouté

- **Logging détaillé toggle_user** — Traces complètes pour débogage (DN, action, UAC, résultat)

### Corrigé

- **Activation/désactivation utilisateurs** — Route `/users/toggle` corrigée :
  - DN passé comme champ caché (plus dans l'URL)
  - Bouton avec soumission JavaScript explicite
  - Encodage URL simplifié
- **Création utilisateur** — OU de destination par défaut utilise `base_dn` de la session
- **Template users.html** — Fonction `showMoveUserModal` → `showMoveModal` (cohérence)
- **Template users.html** — Boutons toggle avec IDs uniques pour soumission fiable

### Modifié

- **`routes/users.py`** — Route `toggle_user()` refactorisée :
  - URL: `/users/toggle` (au lieu de `/users/<path:dn>/toggle`)
  - DN récupéré depuis `request.form.get('dn')`
  - Logging détaillé ajouté
- **`templates/users.html`** — Formulaire toggle simplifié :
  - `<input type="hidden" name="dn" value="{{ user.dn }}">`
  - Bouton `type="button"` avec `onclick="form.submit()"`
- **`routes/users.py`** — Fonction `create_user()` :
  - Gestion correcte de l'OU par défaut
  - Utilise `session.get('ad_base_dn')` si aucune OU spécifiée

## [1.32.0] - 2026-04-04

### Ajouté

- **🔐 Rate Limiting renforcé** — Protection anti-brute force sur login (5 tentatives/5min) et actions sensibles (10 tentatives/5min)
- **Pages de confirmation** — `/login-success` et `/logged-out` remplacent les redirections 302
- **Page de limitation** — Template `rate_limited.html` avec compte à rebours et informations de sécurité
- **Session permanente** — La session persiste après fermeture du navigateur (configurable via `SESSION_TIMEOUT`)
- **Restauration objet AD** — Fonction `restore_deleted_object()` pour restaurer depuis la corbeille AD
- **Déblocage massif** — Fonction `bulk_unlock_accounts()` améliorée avec support `unlock_all`
- **Feature Flags** — Activation de `FEATURE_RECYCLE_BIN_ENABLED` et `FEATURE_LOCKED_ACCOUNTS_ENABLED`
- **Logging amélioré** — Audit des actions de déblocage et restauration avec détails utilisateurs
- **CSS pages** — Styles complets pour `/connect`, `/laps`, et topbar

### Corrigé

- **Rôle admin non attribué** — Correction de `get_user_role_from_groups()` pour vérifier les groupes AD
- **Encodage UTF-8** — Fonction `decode_ldap_value()` améliorée pour caractères spéciaux (latin-1, cp1252)
- **Bug déconnexion** — Conversion correcte de `_login_time` (string ISO → datetime)
- **Bug rate limiting** — Correction unpacking `check_rate_limit()` (3 valeurs retournées)
- **Affichage utilisateur** — Topbar avec avatar circulaire et nom complet (ex: `SELEST\admin`)

### Modifié

- **`security.py`** — Refonte complète du rate limiting avec `record_attempt()`, `get_rate_limit_status()`, décorateurs spécialisés
- **`routes/core.py`** — Fonction `get_user_role_from_groups()` corrigée + logging détaillé
- **`routes/tools.py`** — Fonctions `restore_deleted_object()` et `bulk_unlock_accounts()` implémentées + rate limiting
- **`app.py`** — Routes `/connect` et `/disconnect` avec pages dédiées + session permanente
- **`templates/connect.html`** — CSS complet avec support mode sombre
- **`templates/laps.html`** — CSS amélioré + JavaScript avec feedback visuel
- **`templates/partials/_topbar.html`** — Avatar circulaire + CSS inline
- **`.env`** — Feature flags activés + groupes admin étendus

### Sécurité

- **Rate limiting** — 5 tentatives maximum pour login, 10 pour actions sensibles
- **Temps de blocage** — 5 minutes après dépassement du seuil
- **API rate limiting** — 100 requêtes/minute pour endpoints API
- **Nettoyage automatique** — Purge des tentatives après 15 minutes

## [1.23.0] - 2026-04-02

### Ajouté

- **🔔 Système d'alertes complet** — Page `/alerts` avec détection automatique des comptes expirants, mots de passe expirant, et comptes inactifs
- **API des alertes** — Routes `/api/alerts`, `/api/alerts/<id>/acknowledge`, `/api/alerts/<id>/delete`, `/api/alerts/check`
- **Module `alerts.py` enrichi** — Fonction `run_full_alert_check()` pour vérification automatique
- **Template `alerts.html`** — Interface complète avec filtres, statistiques, acquittement et export JSON
- **🔐 Case "Changer MDP à prochaine connexion"** — Dans `/users/create`, force `pwdLastSet=0` pour obligation de changement
- **🎨 Personnalisation avancée** — Logo, couleurs, police, CSS personnalisé via Admin → Paramètres
- **Module `settings_manager.py`** — Section `branding` avec couleurs, polices, rayon des bordures
- **Template `GUIDE_PERSONNALISATION.md`** — Guide complet de personnalisation avec exemples
- **🧰 Scripts PowerShell de correction** — `fix_smbv1.ps1`, `fix_ntlm.ps1`, `fix_ldap_signing.ps1`, `fix_channel_binding.ps1`
- **API `/api/fix-protocol`** — Endpoint pour appliquer les corrections de protocoles
- **🔍 Détection automatique des protocoles** — SMBv1, NTLM/LM, LDAP Signing, Channel Binding via PowerShell
- **📊 Tests visuels automatisés** — Scripts `test_full.py`, `test_debug.py` avec captures d'écran Chromium
- **Affichage des erreurs** — Page `/errors` et API `/api/errors` pour consultation des logs

### Corrigé

- **Overflow horizontal (+280px)** — Correction du sidebar avec `overflow-x: hidden` et ajustement du `margin-left`
- **Boutons empilés verticalement** — Header-actions en flexbox avec wrap responsive
- **Politique MDP valeurs vides** — Gestion correcte des valeurs timedelta/FILETIME dans `routes/tools.py`
- **Template LAPS erreur syntaxe** — Correction des balises `{% endif %}` en double
- **Routes `/admin/` et `/password-audit`** — Correction des `url_for()` incorrects
- **Fonctions JavaScript manquantes** — Ajout de `showLoading()`, `hideLoading()` dans password_audit.html
- **Erreur `ACTIONS['OTHER']`** — Ajout dans `audit.py`
- **Import `request` manquant** — Ajout dans `debug_utils.py`
- **Template `debug/dashboard.html`** — Conversion des objets Rule Flask en JSON sérialisable

### Modifié

- **`routes/core.py`** — Nouvelles fonctions `get_user_permissions()`, `has_permission()`, `require_permission()` pour autorisations granulaires
- **`password_audit.py`** — Fonctions de détection `check_smbv1_status()`, `check_ntlm_level()`, `check_ldap_signing()`, `check_channel_binding()`
- **`app.py`** — Routes des alertes, injection `branding` dans le contexte, error handlers 404/500
- **`templates/base.html`** — Support du logo personnalisé, CSS personnalisé injecté, variables CSS pour couleurs
- **`templates/password_audit.html`** — Interface de correction des protocoles avec boutons "Appliquer la correction"
- **`templates/password_policy.html`** — Affichage amélioré avec valeurs par défaut et indicateurs visuels
- **`templates/laps.html`** — Gestion gracieuse de l'absence du schéma LAPS
- **`static/css/responsive.css`** — Corrections complètes pour overflow, tableaux, cartes, flexbox
- **`static/css/optimizations.css`** — Sidebar avec `overflow-x: hidden`, main-content responsive
- **`routes/users.py`** — Support de `must_change_password` dans `create_user()`
- **`.env.example`** — Section "PERSONNALISATION" ajoutée

### Technique

- **Nouveaux fichiers** : 
  - `templates/alerts.html`, `templates/error.html`, `templates/errors.html`
  - `scripts/fix_smbv1.ps1`, `scripts/fix_ntlm.ps1`, `scripts/fix_ldap_signing.ps1`, `scripts/fix_channel_binding.ps1`
  - `test_full.py`, `test_debug.py`, `test_visual.py`, `test_responsive.py`
  - `GUIDE_PERSONNALISATION.md`, `GUIDE_TEST_RESPONSIVE.md`
  - `static/js/display-debugger.js`
- **Fichiers modifiés** : +20 fichiers Python, templates, CSS, scripts
- **Total** : +2500 lignes ajoutées, -200 supprimées

### Sécurité

- **Autorisations granulaires par groupe AD** — Configuration via `AD_GROUP_PERMISSIONS` dans `routes/core.py`
- **Détection et correction des protocoles obsolètes** — SMBv1, NTLMv1, LM, LDAP Signing, Channel Binding
- **Scripts de durcissement** — PowerShell avec validation, rollback et logging
- **Audit des mots de passe enrichi** — Score 0-100, recommandations ANSSI, détection FGPP

### Tests

- **8 pages testées automatiquement** — Dashboard, Users, Groups, Computers, OUs, Password Policy, Password Audit, Admin
- **Overflow horizontal vérifié** — Passage de +280px à 0px sur toutes les pages
- **Aucun élément coupé** — Vérification automatique des headers, boutons, stat cards
- **Aucune erreur JavaScript** — Validation console browser

## [1.22.0] - 2026-04-01

### Ajouté

- **Système de Feature Flags** — 50+ variables d'environnement pour activer/désactiver chaque fonctionnalité individuellement (`FEATURE_XXX_ENABLED` dans `.env`).
- **Module `features.py`** — Utilitaires `is_feature_enabled()`, `require_feature()`, `get_enabled_features()` pour gestion modulaire des fonctionnalités.
- **Page `feature_disabled.html`** — Template d'erreur 503 pour fonctionnalités désactivées, avec instructions pour administrateurs.
- **Menu de navigation conditionnel** — `base.html` affiche/masque les éléments selon les feature flags et permissions RBAC.
- **Page d'administration redesignée** — `admin.html` avec cartes organisées par catégorie (Configuration, Surveillance, Fonctionnalités avancées).
- **Documentation `MODULARITE.md`** — Guide complet des feature flags avec exemples de configuration et bonnes pratiques.

### Corrigé

- **Erreur 500 sur `/recycle-bin`** — Route `tools.restore_deleted_object` manquante ajoutée (placeholder avec message d'avertissement).
- **Erreur 500 sur `/locked-accounts`** — Route `tools.bulk_unlock_accounts` ajoutée avec implémentation complète du déblocage en masse.
- **Erreur `export_expiring_pdf`** — Route `tools.export_expiring_pdf` ajoutée (placeholder).
- **Templates avec routes incorrectes** — Correction des `url_for()` dans `recycle_bin.html` et `locked_accounts.html` (préfixe `tools.`).
- **Erreur JavaScript `searchInput` déjà déclaré** — Variable renommée en `userSearchInput` dans `users.html` et encapsulée dans une IIFE.
- **Meta tag déprécié** — Ajout de `<meta name="mobile-web-app-capable">` pour remplacer l'ancien tag Apple.
- **Favicon 404** — Ajout des liens favicon dans `base.html` pointant vers `icon.svg`.
- **CSP bloquant Chart.js** — Mise à jour de Content-Security-Policy pour autoriser `https://cdn.jsdelivr.net` pour les scripts, styles et connexions.
- **Service Worker** — Suppression de la mise en cache de Chart.js (géré par le CDN), mise à jour version cache v1.22.0.

### Modifié

- **`config.py`** — +50 variables FEATURE_XXX_ENABLED pour modularité complète.
- **`app.py`** — Injection `is_feature_enabled` dans le contexte template, import du module `features`.
- **`routes/tools.py`** — 3 routes manquantes ajoutées (restore_deleted_object, bulk_unlock_accounts, export_expiring_pdf).
- **`templates/base.html`** — Menu de navigation entièrement conditionnel selon feature flags.
- **`templates/admin.html`** — Redesign complet avec cartes et section fonctionnalités désactivées.
- **`.env.example`** — Section "FEATURE FLAGS - MODULARITÉ" ajoutée avec toutes les options documentées.
- **`VERSION`** — Passage de 1.21.0 à 1.22.0.

### Technique

- **Nouveaux fichiers** : `features.py`, `templates/feature_disabled.html`, `MODULARITE.md`, `RESUME_CHANGEMENTS.md`, `PUSH_GITHUB_INSTRUCTIONS.md`, `commit_github.bat`
- **Fichiers modifiés** : `config.py`, `app.py`, `routes/tools.py`, `templates/base.html`, `templates/admin.html`, `templates/recycle_bin.html`, `templates/locked_accounts.html`, `.env.example`, `VERSION`
- **Total** : +850 lignes ajoutées, -50 supprimées

### Tests

- **14/14 tests automatisés passés** — Tous les tests unitaires et d'intégration vérifiés.
- **100% des pages fonctionnelles** — Dashboard, Users, Groups, Computers, OUs, LAPS, BitLocker, Recycle Bin, Locked Accounts, Audit, Admin, Password Policy.

### Notes de migration

**BREAKING CHANGE** : Les nouvelles variables `FEATURE_XXX_ENABLED` sont ajoutées dans `.env`. Par défaut, toutes les fonctionnalités sont **ACTIVÉES** pour rétrocompatibilité.

Pour désactiver des fonctionnalités non implémentées :
```ini
FEATURE_RECYCLE_BIN_ENABLED=false
FEATURE_LOCKED_ACCOUNTS_ENABLED=false
```

---

## [1.21.0] - 2026-03-31

### Ajouté

- **Accessibilité (a11y)** — Navigation clavier complète, attributs ARIA (role, aria-label, aria-expanded), skip link "Aller au contenu principal", focus visible avec outline jaune, support `prefers-reduced-motion`.
- **Mode sombre amélioré** — Variables CSS pour couleurs cohérentes, contrastes améliorés (WCAG AA), tous les éléments stylisés (tables, formulaires, alerts, badges, modals), borders et ombres adaptés.
- **Animations CSS** — Transitions 0.3s, effets hover (boutons et cartes avec translateY + shadow), loading spinner avec overlay, animations keyframes (fadeIn, slideIn, shake, pulse, spin).
- **Audit de sécurité des mots de passe** — Nouveau module `password_audit.py` avec analyse complète : détection des comptes "Le mot de passe n'expire jamais", mots de passe trop anciens (> 90 jours), politique de mot de passe du domaine, recommandations personnalisées, score de sécurité global.
- **Page Dashboard Audit MDP** — Template `password_audit.html` avec score visuel, statistiques, tableaux des comptes problématiques, recommandations actionnables.
- **API /api/password-audit** — Endpoint JSON retournant le rapport d'audit complet.
- **Menu "Audit MDP"** — Lien ajouté dans le menu "Plus" (réservé aux admins).

### Corrigé

- **Menus défaillants** — Structure HTML corrigée avec `role="menubar"`, dropdowns avec gestion aria-expanded dynamique, fermeture automatique des autres dropdowns, icônes flèches (▼/▲) dynamiques, gestion clavier (Entrée/Espace/Échap).

### Modifié

- **base.html** — Attributs ARIA ajoutés, skip link, loading overlay, menu "Audit MDP".
- **style.css** — +550 lignes (a11y, dark mode, animations, responsive).
- **main.js** — Fonctions `initMobileMenu()`, `initMobileDropdowns()`, `showLoading()`, `hideLoading()`.
- **routes/tools.py** — Route `/tools/password-audit` ajoutée.
- **app.py** — Endpoint `/api/password-audit` ajouté.

### Technique

- **Nouveau fichier** : `password_audit.py` (module d'audit)
- **Nouveau template** : `templates/password_audit.html` (dashboard)
- **Total** : +1687 lignes ajoutées, -63 supprimées

---

## [1.20.2] - 2026-03-31

### Corrigé

- **MD4/NTLM non supporté (Python 3.12+ / OpenSSL 3.0)** — `_openssl_init.py` injecte maintenant un monkey-patch `hashlib.new` via `pycryptodome` quand MD4 n'est pas disponible nativement. Ajout de `pycryptodome==3.20.0` dans `requirements.txt`.
- **`/api/system-info` introuvable (404)** — route créée dans `app.py`, retourne version, plateforme, hostname, version Python, statut connexion AD et `md4_support`.
- **`logo.png` introuvable (404)** — `base.html` référençait `static/images/logo.png` inexistant ; remplacé par `static/icons/icon.svg` déjà présent.

---

## [1.20.1] - 2026-03-31

### Corrigé

- **Connexion impossible sans auto-détection du serveur** — quand `detect_ad_config()` ne trouvait pas l'adresse du contrôleur de domaine (DNS SRV absent, hors domaine), le champ `server` était un `<input hidden>` avec `value=""`. La soumission du formulaire envoyait `server=""` → `get_ad_connection()` retournait "Non connecté" sans même tenter la connexion LDAP. Corrections : `app.py` appelle maintenant `detect_ad_config()` sur le GET et passe `server`, `port`, `base_dn`, `use_ssl`, `auto_detected` au template ; `connect.html` affiche le champ serveur directement dans le formulaire principal quand `auto_detected=False`.

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
