# Changelog

Toutes les modifications notables de ce projet sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).
Historique complet : `git log`. Détails et captures d'écran : `README.md`.

## v1.49.1

- fix: recherche paginée AD — les listes d'utilisateurs/ordinateurs/groupes
  étaient tronquées à 1000 objets (limite LDAP par défaut non gérée par
  pagination).

## v1.49.0 — Durcissement en profondeur & ergonomie

### Sécurité
- Sessions côté serveur : les données de session (dont le mot de passe AD
  chiffré) ne voyagent plus dans le cookie navigateur, seulement un
  identifiant opaque signé (`data/sessions/`).
- Protection CSRF globale : toute requête mutative est validée de façon
  centralisée, jeton injecté automatiquement côté client.
- Transport chiffré préféré : LDAPS puis STARTTLS tentés avant tout LDAP en
  clair. Option `AD_ALLOW_INSECURE_LDAP=false` pour interdire le LDAP non
  chiffré.

### Ergonomie
- Filtres sur la page Ordinateurs (nom, système d'exploitation, unité
  d'organisation).

### Qualité
- Empreintes SHA256 sur les paquets de release.
- Suppression de templates orphelins.

## v1.48.0 — Correction des protocoles hérités

- Bouton « corriger le protocole » sur la page Audit des mots de passe
  câblé à l'endpoint `/api/fix-protocol`, qui exécute le script PowerShell
  de durcissement correspondant (SMBv1, NTLM/LM, LDAP Signing, Channel
  Binding) sur le contrôleur de domaine, réservé à `system:execute_script`.

## v1.47.1 — QA : pages & interactivité

- 4 pages corrigées qui plantaient en erreur 500 (Documentation API,
  Favoris, Rapport d'audit des mots de passe, Modèles utilisateurs).
- Historique d'audit des mots de passe : contenu dynamique réparé (URL API
  sans le préfixe `/tools`).
- Tests de non-régression ajoutés.

## v1.47.0 — Durcissement sécurité & robustesse

- Validation du certificat LDAPS en option (`AD_TLS_VERIFY=true` +
  `AD_CA_BUNDLE`).
- Injections LDAP résiduelles corrigées (`security_audit`, `ous`, `groups`,
  `users`, `password_audit`).
- XSS stocké via CSS personnalisé neutralisé.
- Comparaison du jeton CSRF à temps constant (`hmac.compare_digest`).
- Path traversal : vérification hiérarchique réelle des chemins.
- HSTS émis seulement sur une connexion réellement HTTPS.
- Rate limiter protégé par verrou (accès concurrents Waitress) et corrigé
  (plus d'erreur 500 sur 404 sous scan).

## v1.46.1 — Correctif de redémarrage post-mise à jour

- Le service ne redémarrait pas après une mise à jour (WinSW `restart`
  tuait le process avant la phase de démarrage). Corrigé via la variante
  `restart!` + sortie en code non nul en secours.

## v1.46.0 — Correctifs de sécurité RBAC (C1) et hygiène dépôt (C2)

- Élévation de privilège corrigée : le contrôle de permissions accordait
  l'accès dès qu'une permission quelconque était détenue. Bascule sur le
  contrôle par inclusion de la permission exacte.
- 84 protections de routes basculées d'alias larges (`admin`, `write`,
  `delete`) vers des permissions granulaires (`users:delete`,
  `system:execute_script`, `tools:laps`…).
- Données du domaine retirées du suivi git (historique d'audit, fichier de
  permissions), garde-fou CI ajouté.
- Suite de non-régression du contrôle d'accès (`tests/test_permissions_c1.py`).

## v1.44.6

- Bouton GPO LAPS sur `/tools/laps` quand le schéma est présent mais aucun
  mot de passe encore généré.
- Diagnostic LAPS : présence du schéma testée, avertissement si la GPO
  n'est pas déployée.

## v1.44.0

- Corrections critiques : `change_expired_password()` utilisait `base_dn`
  au lieu du DN utilisateur ; fuites de connexions LDAP dans plusieurs
  routes (`conn.unbind()` déplacé en `finally`).
- Injection PowerShell dans `laps.py` corrigée (échappement des caractères
  spéciaux).
- `size_limit` ajouté sur plusieurs recherches LDAP (alertes, dashboard).

## v1.43.0

- Mise à jour par ZIP (v4.0) : 1 seule requête HTTP, extraction
  différentielle SHA256, backup parallèle + rollback automatique.
- Recherche AJAX groupes ↔ utilisateurs, protection des groupes système
  (Builtin, Domain Admins…).
- Gestion OU + groupes dans l'édition utilisateur.
- Correctifs : `entry.distinguishedName` → `entry.entry_dn` (13 fichiers),
  71 groupes affichés au lieu de 1, détection mot de passe expiré.

## v1.39.0

- 7 bugs critiques corrigés : syntaxe LDAP `lockoutTime`, itérateur invalide
  dans la boucle groupes, race condition sur `_update_progress` (verrou
  ajouté), XSS dans l'export PDF, erreur silencieuse sur `fix_type` inconnu.

## v1.38.0

- Autocomplete AD en temps réel sur les permissions (groupes, utilisateurs,
  OUs).
- Mise à jour différentielle (SHA GitHub), backup automatique + rollback,
  watchdog en arrière-plan, barre de progression réelle.
- Mise à jour via WinSW restart (remplace `os.execl`).

## v1.37.1 – v1.37.10

- Corrections de l'installateur (NSSM/WinSW, signature Authenticode,
  `OPENSSL_CONF`), du login (`SESSION_COOKIE_SECURE`, `SESSION_COOKIE_NAME`,
  timeout session 30s→30min), du fallback LDAP/389, de l'API `/api/perform-update`
  (JSON au lieu de HTML en cas d'erreur).
- Système de mise à jour v2.0 : téléchargement parallèle (ThreadPoolExecutor),
  cache GitHub 5 minutes.
- Filtres avancés sur `/users/` et `/computers/` (OU, statut, OS).
- Pagination des recherches LDAP (`paged_search`) pour dépasser la limite de
  1000 résultats.

## v1.36.0

- Analyse automatique des logs au démarrage, détection d'erreurs critiques,
  corrections automatiques.
- Gestion des scripts PowerShell depuis l'interface web (9 scripts).
- Page `/ous/` enrichie : statistiques, recherche, filtres.
