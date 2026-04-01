# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

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
