# Changelog

Toutes les modifications notables de ce projet sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).
Historique complet : `git log`. Détails et captures d'écran : `README.md`.

## [1.51.3] - 2026-09-22 — Traversée de répertoire (historique d'audit, rapports)

Trouvé en envoyant à chaque route des entrées inattendues (identifiants
longs ou mal formés, paramètres non numériques, corps invalides).

### Sécurité
- **Lecture et suppression de fichiers hors de l'historique d'audit.**
  L'identifiant d'un audit mot de passe servait directement de nom de
  fichier. Via la comparaison d'audits (paramètres `audit_1`/`audit_2`),
  une valeur comme `../../core/data/settings` faisait lire n'importe quel
  fichier `.json` de l'application ; via la suppression d'un audit, sous
  Windows, `..\..\…` permettait d'en **supprimer** un (réglages,
  permissions…). Accessible à toute personne disposant de la permission
  d'audit des mots de passe. Seuls les identifiants au format généré
  (`AAAAMMJJ_HHMMSS`) sont désormais acceptés, avec un contrôle de chemin
  en plus.
- Même validation pour les rapports d'analyse des logs, dont un
  identifiant trop long provoquait aussi une erreur 500.

## [1.51.2] - 2026-09-22 — Injection PowerShell (LAPS), déverrouillage, corbeille

Trouvés en exécutant toutes les actions (POST) de l'application contre un
annuaire AD simulé.

### Sécurité
- **Injection de commandes PowerShell dans le rafraîchissement LAPS forcé.**
  Le nom d'ordinateur saisi dans le formulaire était inséré tel quel dans un
  script PowerShell exécuté sur le contrôleur de domaine : un nom comme
  `x"; commande; "` ou `$(commande)` exécutait n'importe quelle commande avec
  les droits du service. Accessible à toute personne disposant de la
  permission LAPS. Le nom est désormais strictement validé (lettres,
  chiffres, tirets, points) et transmis encodé, comme dans les autres
  scripts. Même correction pour l'affichage du domaine dans le script de
  configuration LDAPS.

### Corrections
- **Déverrouillage de comptes impossible** depuis la page « Comptes
  verrouillés », en individuel comme en groupé : l'appel LDAP était mal
  formé (liste au lieu d'un dictionnaire, rejetée par la bibliothèque avant
  tout envoi) et la valeur envoyée n'était pas au bon format. Aucun compte
  n'a jamais pu être déverrouillé depuis l'interface.
- **Restauration depuis la corbeille AD impossible.** L'application tentait
  un simple renommage de l'objet supprimé, ce qu'Active Directory refuse,
  avec un nom mal construit. Elle applique maintenant la procédure
  documentée par Microsoft (modification de `isDeleted` et
  `distinguishedName` avec le contrôle « Show Deleted »). Une erreur LDAP
  pendant la restauration ne provoque plus d'erreur 500.
- **Corbeille** : les ordinateurs supprimés apparaissaient comme
  « Utilisateur », et les noms gardaient le suffixe technique `DEL:<guid>`.

## [1.51.1] - 2026-09-22 — Aide clavier, nettoyage des CSS

### Corrections
- **Aide des raccourcis clavier (touche « ? ») affichée en bas de page** au
  lieu d'une fenêtre en surimpression, sur toutes les pages qui ne stylent
  pas elles-mêmes les modales (tableau de bord notamment) : il fallait
  faire défiler toute la page pour la voir et la fermer. Style dédié
  ajouté ; les modales propres à chaque page ne sont pas modifiées.
  Vérifié dans Chromium en mode clair et sombre, fermeture par le bouton
  et par Échap.

### Nettoyage
- **`static/css/old/` supprimé** (4 feuilles de style, 72 Ko) : aucune page
  ni aucun script ne les chargeait.
- **`static/README.md`** : arborescence, manifeste PWA, service worker et
  icônes décrits d'après les fichiers réels (il documentait des icônes PNG
  et un service worker « cache first » qui n'existent pas).

## [1.51.0] - 2026-09-22 — Content-Security-Policy stricte

### Sécurité
- **CSP stricte pour les scripts** (constat M9 de l'audit). La politique
  autorisait `'unsafe-inline'` : n'importe quel script injecté dans une page
  (via un `innerHTML`, un attribut `onclick`…) pouvait s'exécuter, ce qui
  rendait la CSP quasi inutile contre le XSS. Désormais, seuls les scripts
  de l'application et ceux portant le **nonce** de la requête (renouvelé à
  chaque page) s'exécutent. S'y ajoutent `object-src 'none'`,
  `base-uri 'self'` et `form-action 'self'`.
- **Plus aucune ressource externe** : chart.js (4.4.4, fichier vérifié
  identique au paquet npm officiel) est servi depuis `static/vendor/`. Les
  graphiques ne dépendent plus d'un accès Internet depuis le contrôleur de
  domaine.
- **Fin d'injections possibles dans les attributs `onclick`.** Des appels
  comme `onclick="showMoveModal('{{ user.dn }}')"` étaient vulnérables : dans
  un attribut HTML, le navigateur décode `&#39;` en apostrophe **avant**
  d'exécuter le JavaScript, si bien qu'un nom ou un DN contenant une
  apostrophe pouvait injecter du code. Les 114 gestionnaires `on*="…"` sont
  remplacés par une délégation d'événements (`static/js/actions.js`) dont
  les arguments passent en JSON échappé.
- **Nouveau réglage `CSP_MODE`** : `strict` (défaut), `report-only`
  (ancienne politique appliquée, violations de la politique stricte
  journalisées sous « CSP violation ») ou `legacy` (échappatoire). Si une
  page ne réagit plus à un clic, passer temporairement en `report-only` et
  signaler la page concernée.

### Corrections
- **Page Mise à jour inutilisable depuis la publication de la v1.50.3.**
  Les notes de version GitHub étaient insérées sans échappement : la mention
  littérale « `<style>` » dans les notes de la v1.50.3 ouvrait une vraie
  balise, et toute la suite de la page devenait du CSS — scripts compris,
  dont le bouton de mise à jour. Les notes sont maintenant affichées comme
  du texte. Cela ferme aussi une injection HTML possible depuis le contenu
  d'une release.
- **Scripts exécutés deux fois** sur les pages Utilisateurs, Ordinateurs,
  BitLocker, Comptes verrouillés et Détail d'un groupe : le bloc de script
  était imbriqué dans le contenu et donc rendu deux fois. Sur le détail d'un
  groupe, cela provoquait une erreur JavaScript (recherche de membres
  inopérante).
- **Feuilles de style dupliquées** sur 11 pages (Connexion, Journal d'audit,
  Corbeille, Sauvegardes, Modèles, Nouveau groupe, Expirations, Favoris,
  Documentation API, Réinitialisation du mot de passe, Détail d'une
  sauvegarde) : même défaut d'imbrication, pour le bloc CSS. Rendu vérifié
  identique dans Chromium, sauf sur la page de réinitialisation du mot de
  passe : sa classe `.user-info` entrait en collision avec celle de la barre
  supérieure, dont le badge utilisateur prenait le fond bleu de l'encadré de
  la page. Classe renommée.
- Tableau de bord debug : polices Google retirées (déjà bloquées par la CSP).

### Vérification
Crawl de toutes les pages dans Chromium avec la CSP stricte, sur un
annuaire AD simulé : aucune violation, aucune erreur JavaScript. Parcours
cliqués : modales, confirmations de suppression, sélection multiple,
onglets, filtres, boutons générés dynamiquement, panneau des notes de
version, messages flash.

## [1.50.4] - 2026-09-22 — Nettoyage des templates

### Nettoyage
- **24 templates jamais affichés supprimés.** Aucune route ne les rendait et
  aucun autre template ne les incluait : `404.html`, `500.html` (les erreurs
  passent par `error.html`), `advanced_search.html`, `alerts_page.html`,
  `bulk_operations.html`, `compare_users.html`, `compare_users_form.html`,
  `duplicate_user.html`, `global_search.html`, `history.html`,
  `import_users.html`, `laps_computer_permissions.html`,
  `laps_create_admin.html`, `laps_dashboard.html`, `laps_extend_schema.html`,
  `laps_gpo.html`, `laps_install.html`, `laps_read_permissions.html`,
  `login_history.html`, `maintenance.html`, `nested_groups.html`,
  `search.html`, `tree.html`, `user_form.html`. Plusieurs contenaient des
  liens vers des routes inexistantes (`laps_management.*`,
  `users.global_search`, `api_acknowledge_alert`…) qui auraient provoqué une
  erreur 500 si quelqu'un les avait branchés tels quels. Aucun changement
  visible : aucune page de l'application ne les utilisait.
- **Nouveau test** : tout template doit être rendu par une route ou inclus
  par un autre template, sinon la CI échoue.
- **`templates/README.md` réécrit** d'après les fichiers réels : il
  documentait une trentaine de templates inexistants (dont des partials
  `_navbar`, `_footer`, `_pagination`) et en omettait 18.

## [1.50.3] - 2026-09-22 — Mot de passe expiré, menu, configuration par défaut

### Corrections
- **Parcours « mot de passe expiré » : cassé de bout en bout, désormais
  fonctionnel.** Quatre défauts cumulés :
  - le code AD `532` (mot de passe expiré) n'était pas détecté, seul `773`
    l'était — et par une recherche trop large (`'773' in msg`) qui pouvait
    aussi matcher un identifiant `DSID-…` sur un simple mauvais mot de passe ;
  - sur le chemin de connexion par défaut (port 389), l'information
    « mot de passe expiré » était noyée dans le message d'erreur générique :
    la redirection vers la page de changement n'avait jamais lieu ;
  - la page de changement (`change_password.html`) n'existait pas : erreur 500 ;
  - le changement tentait un bind LDAP avec le mot de passe expiré — ce
    qu'Active Directory refuse toujours — puis forçait `pwdLastSet=0`, ce qui
    aurait ré-expiré immédiatement le nouveau mot de passe.

  Le changement passe maintenant par `NetUserChangePassword` (API Windows),
  le mécanisme utilisé par Windows lui-même : pas de bind préalable,
  vérification de l'ancien mot de passe, stratégie du domaine appliquée
  (longueur, complexité, historique). Hors Windows, un message explicite
  invite à changer le mot de passe depuis un poste du domaine.
- **Une entrée de menu invalide faisait tomber toute l'application.**
  L'entrée « Recherche » pointait vers une page inexistante ; désactivée par
  défaut, elle restait activable depuis Administration → Menu, ce qui
  provoquait une erreur 500 sur **toutes** les pages — y compris la page
  d'erreur et la page d'administration qui aurait permis d'annuler le
  réglage. Les entrées de menu pointant vers une page inconnue sont
  désormais ignorées (avec un avertissement dans les logs), et l'entrée
  morte est retirée des valeurs par défaut.
- Mode debug : la redirection des non-administrateurs visait une route
  inexistante.

### Sécurité
- **Configuration par défaut : production** (constat F1 de l'audit). Sans
  `FLASK_ENV`, l'application démarrait en mode développement : traces
  d'exception affichées et outils `/_debug` actifs. Le service Windows ne
  définit pas cette variable ; un `.env` incomplet suffisait donc à exposer
  ces informations. ⚠️ Pour un poste de développement lancé avec
  `python app.py`, définir désormais `FLASK_ENV=development` (inchangé avec
  `python manage.py`).
- **CSS personnalisé** : le filtre anti-XSS supprimait les motifs dangereux
  en une seule passe, contournable par imbrication
  (`javajavascript:script:` redevenait `javascript:`). Suppression répétée
  jusqu'à stabilité. Le caractère `>` (sélecteur enfant CSS, sans risque
  dans un bloc `<style>`) n'est plus retiré à tort.

### Journalisation
- Refus de permission journalisés en `debug` et non plus en `info` (liste
  des groupes AD à chaque contrôle — volumineux et sensible, constat F6).
- Erreurs 404 journalisées en `warning` avec le chemin demandé, au lieu de
  `error` qui noyait les vraies erreurs dans l'analyseur de logs (constat F7).

## [1.50.2] - 2026-08-12 — Revue de la v1.50 : garde-fou CI, clé API, ProxyFix

Issue d'une revue critique complète des livraisons v1.50.0 et v1.50.1.

### Sécurité
- **Le garde-fou d'intégration continue « aucun fichier sensible versionné »
  ne vérifiait rien.** Sa commande combinait `grep -E` et `-P`, deux options
  mutuellement exclusives : grep sortait en erreur, l'erreur était avalée, et
  le contrôle passait systématiquement au vert **même avec des fichiers
  interdits versionnés**. En place depuis la v1.46.0 en réponse à une fuite de
  données de domaine, il n'a donc jamais rien protégé — ce qui explique
  comment `core/data/settings.json` et `core/data/crypto_salt.bin` sont restés
  versionnés jusqu'à la v1.50.0. Corrigé, et doublé d'un auto-test qui échoue
  si le contrôle cesse de détecter un chemin interdit.
- **Clé API : fin d'une fuite sur disque introduite en v1.50.1.** La clé brute
  transitait par un message flash, or les sessions sont côté serveur depuis la
  v1.49.0 : elle était donc écrite en clair dans `data/sessions/`. Elle est de
  nouveau affichée uniquement dans le corps de la réponse, et disparaît au
  rechargement de la page.
- **`TRUSTED_PROXY_HOPS` découplé de `TRUSTED_PROXIES`.** Le nombre de sauts
  était déduit du nombre d'adresses listées ; or un même proxy peut y figurer
  sous plusieurs adresses (IPv4, IPv6, plage CIDR). Faire confiance à plus
  d'en-têtes `X-Forwarded-For` qu'il n'en existe réellement permet à un client
  d'usurper son adresse IP. Seule `TRUSTED_PROXY_HOPS` pilote désormais
  ProxyFix ; une valeur invalide vaut 0 au lieu d'empêcher le démarrage.

### Corrections
- **Création de compte avec une virgule dans le nom.** C'est ici que se
  trouvait réellement le défaut d'échappement de DN : `routes/users/create.py`
  interpolait le CN brut dans le DN. Un nom comme « O'Brien, John » produisait
  un DN rejeté comme invalide — la création échouait. Le CN est désormais
  échappé (RFC 4514) dans le DN, tout en gardant sa valeur littérale dans les
  attributs `cn`/`displayName`.
- **`/api/alerts` tronquait la liste à 50 alertes** sans le signaler (limite
  par défaut héritée). Limite explicite, paramétrable, et total renvoyé.
- **Modèles utilisateur : écriture atomique.** Une coupure en pleine
  sauvegarde laissait un JSON tronqué, silencieusement interprété comme
  « aucun modèle » — perte de la totalité des modèles.

### Rectifications des notes de version précédentes
- **v1.50.0** annonçait l'échappement de DN comme corrigeant les créations de
  comptes. En réalité, seule une fonction utilitaire **sans aucun appelant**
  avait été corrigée : aucun comportement utilisateur ne changeait. Le défaut
  réel est corrigé dans la présente version (voir ci-dessus).
- **v1.50.1** présentait le filet de sécurité de redémarrage comme la réponse
  à l'incident de production. L'incident est en fait entièrement expliqué par
  la mise à jour depuis la **v1.45** : c'est le code de la v1.45 qui a piloté
  la mise à jour, avec son mécanisme de redémarrage défectueux, corrigé
  seulement à partir de la v1.46.1 — cas déjà documenté à l'époque. Ni la
  v1.50.0 ni la mise à jour des dépendances n'y sont pour quelque chose. Le
  filet de sécurité reste utile et est conservé.

## [1.50.1] - 2026-08-11 — Corrections critiques post-v1.50.0

Trouvés par un crawl exhaustif de toutes les pages et actions (GET + POST)
contre un annuaire AD factice, en réaction à un incident production après
la mise à jour vers la v1.50.0.

### Corrections
- **OUs cassées** : 9 occurrences de `url_for('ous')` (endpoint inexistant)
  faisaient planter en 500 toute redirection d'erreur ou de succès du
  blueprint OUs — création, édition, suppression étaient inutilisables.
- **Activation/désactivation de compte cassée** : un import local de
  `url_for` dans `toggle_user_status()` rendait la fonction locale à toute
  la portée, provoquant un crash sur le chemin nominal (succès).
- **`/api/alerts`** : appelait une fonction inexistante (`get_all_alerts`) ;
  acquitter une alerte ou lancer une vérification plantait aussi (arguments
  manquants).
- **`/api/security-fix`** : importait une fonction inexistante au lieu de
  distribuer vers les 5 correctifs de sécurité réellement disponibles.
- **Téléchargement de script PowerShell** : plantait systématiquement
  (bytes bruts passés à `send_file` au lieu d'un flux).
- **Génération/révocation de clé API** : plantait au lieu de rediriger ; la
  nouvelle clé n'était de toute façon jamais affichée — corrigé.
- **`/_debug/all-pages` et `/_debug/test/<page>`** : plantaient (port HTTP
  absent du Host, endpoints non qualifiés par blueprint).
- **Erreurs HTTP mal classées** : toute exception HTTP sans gestionnaire
  dédié (403, 405...) était requalifiée en 500 générique — une mauvaise
  méthode HTTP retournait 500 au lieu de 405, par exemple.

### Fiabilité du redémarrage post-mise à jour
- Ajout d'un filet de sécurité (`scripts/ensure_service_running.ps1`) :
  après une mise à jour, un processus détaché vérifie après 45s que le
  service Windows a réellement redémarré et le relance explicitement
  sinon. Le mécanisme existant (WinSW `restart!`) peut échouer en interne
  sans lever d'exception Python, et comme il s'agit d'un arrêt volontaire,
  la règle `<onfailure>` du service ne se déclenche pas pour le rattraper.

## [1.50.0] - 2026-08-11 — CI réelle, durcissement sécurité, favoris & modèles

### Sécurité
- **Dépendances mises à jour** (cryptography, flask, Werkzeug, requests,
  waitress) : les versions figées depuis fin 2025 accusaient plusieurs CVE
  corrigées depuis. Suppression aussi du `--upgrade` de l'auto-updater, qui
  n'apportait rien sur un `requirements.txt` déjà épinglé.
- **Échappement des composants DN** (`sanitize_dn_component`) : les
  caractères spéciaux sont échappés (RFC 4514) au lieu d'être supprimés.
  ⚠️ *Rectifié en v1.50.2 : cette fonction n'avait alors aucun appelant,
  ce changement n'avait donc aucun effet visible. Le défaut réel, dans la
  création de compte, est corrigé en v1.50.2.*
- **Rate limiting derrière un reverse proxy** : `ProxyFix` peut être activé
  explicitement (`TRUSTED_PROXY_HOPS`) pour que le rate limiting et les
  journaux utilisent la vraie IP cliente plutôt que celle du proxy.
  Désactivé par défaut pour ne pas introduire de risque d'usurpation sur
  les déploiements sans proxy.
- **Bandeau d'avertissement** sur la page de connexion quand la validation
  du certificat LDAPS (`AD_TLS_VERIFY`) est désactivée.
- **Fichiers sensibles retirés du suivi git** : `core/data/settings.json`
  et `core/data/crypto_salt.bin` étaient suivis sans être couverts par les
  garde-fous existants (qui ne couvraient que `data/` à la racine).

### Fonctionnalités
- **Favoris** : ajouter/retirer un utilisateur, groupe, ordinateur ou OU
  aux favoris fonctionne réellement (persisté en session).
- **Modèles utilisateur** : création, édition et suppression de modèles
  d'attributs par défaut sont maintenant persistées.

### Fiabilité / CI
- La CI exécute désormais réellement la suite de tests (elle installait
  `pytest` sans jamais l'invoquer).
- 22 `except:` nus remplacés par `except Exception:` (ils avalaient même
  `KeyboardInterrupt`/`SystemExit`).
- Plusieurs bugs latents corrigés (imports/variables manquants faisant
  échouer silencieusement des fonctions de diagnostic, de mise à jour et
  d'affichage des groupes, masqués par une gestion d'erreurs trop large).

### Documentation
- `tests/README.md` réécrit pour refléter les fichiers de tests réellement
  présents.
- Ce fichier `CHANGELOG.md` existe désormais (le lien du README pointait
  vers un fichier absent).

## [1.49.1]

- fix: recherche paginée AD — les listes d'utilisateurs/ordinateurs/groupes
  étaient tronquées à 1000 objets (limite LDAP par défaut non gérée par
  pagination).

## [1.49.0] — Durcissement en profondeur & ergonomie

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

## [1.48.0] — Correction des protocoles hérités

- Bouton « corriger le protocole » sur la page Audit des mots de passe
  câblé à l'endpoint `/api/fix-protocol`, qui exécute le script PowerShell
  de durcissement correspondant (SMBv1, NTLM/LM, LDAP Signing, Channel
  Binding) sur le contrôleur de domaine, réservé à `system:execute_script`.

## [1.47.1] — QA : pages & interactivité

- 4 pages corrigées qui plantaient en erreur 500 (Documentation API,
  Favoris, Rapport d'audit des mots de passe, Modèles utilisateurs).
- Historique d'audit des mots de passe : contenu dynamique réparé (URL API
  sans le préfixe `/tools`).
- Tests de non-régression ajoutés.

## [1.47.0] — Durcissement sécurité & robustesse

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

## [1.46.1] — Correctif de redémarrage post-mise à jour

- Le service ne redémarrait pas après une mise à jour (WinSW `restart`
  tuait le process avant la phase de démarrage). Corrigé via la variante
  `restart!` + sortie en code non nul en secours.

## [1.46.0] — Correctifs de sécurité RBAC (C1) et hygiène dépôt (C2)

- Élévation de privilège corrigée : le contrôle de permissions accordait
  l'accès dès qu'une permission quelconque était détenue. Bascule sur le
  contrôle par inclusion de la permission exacte.
- 84 protections de routes basculées d'alias larges (`admin`, `write`,
  `delete`) vers des permissions granulaires (`users:delete`,
  `system:execute_script`, `tools:laps`…).
- Données du domaine retirées du suivi git (historique d'audit, fichier de
  permissions), garde-fou CI ajouté.
- Suite de non-régression du contrôle d'accès (`tests/test_permissions_c1.py`).

## [1.44.6]

- Bouton GPO LAPS sur `/tools/laps` quand le schéma est présent mais aucun
  mot de passe encore généré.
- Diagnostic LAPS : présence du schéma testée, avertissement si la GPO
  n'est pas déployée.

## [1.44.0]

- Corrections critiques : `change_expired_password()` utilisait `base_dn`
  au lieu du DN utilisateur ; fuites de connexions LDAP dans plusieurs
  routes (`conn.unbind()` déplacé en `finally`).
- Injection PowerShell dans `laps.py` corrigée (échappement des caractères
  spéciaux).
- `size_limit` ajouté sur plusieurs recherches LDAP (alertes, dashboard).

## [1.43.0]

- Mise à jour par ZIP (v4.0) : 1 seule requête HTTP, extraction
  différentielle SHA256, backup parallèle + rollback automatique.
- Recherche AJAX groupes ↔ utilisateurs, protection des groupes système
  (Builtin, Domain Admins…).
- Gestion OU + groupes dans l'édition utilisateur.
- Correctifs : `entry.distinguishedName` → `entry.entry_dn` (13 fichiers),
  71 groupes affichés au lieu de 1, détection mot de passe expiré.

## [1.39.0]

- 7 bugs critiques corrigés : syntaxe LDAP `lockoutTime`, itérateur invalide
  dans la boucle groupes, race condition sur `_update_progress` (verrou
  ajouté), XSS dans l'export PDF, erreur silencieuse sur `fix_type` inconnu.

## [1.38.0]

- Autocomplete AD en temps réel sur les permissions (groupes, utilisateurs,
  OUs).
- Mise à jour différentielle (SHA GitHub), backup automatique + rollback,
  watchdog en arrière-plan, barre de progression réelle.
- Mise à jour via WinSW restart (remplace `os.execl`).

## [1.37.1] – [1.37.10]

- Corrections de l'installateur (NSSM/WinSW, signature Authenticode,
  `OPENSSL_CONF`), du login (`SESSION_COOKIE_SECURE`, `SESSION_COOKIE_NAME`,
  timeout session 30s→30min), du fallback LDAP/389, de l'API `/api/perform-update`
  (JSON au lieu de HTML en cas d'erreur).
- Système de mise à jour v2.0 : téléchargement parallèle (ThreadPoolExecutor),
  cache GitHub 5 minutes.
- Filtres avancés sur `/users/` et `/computers/` (OU, statut, OS).
- Pagination des recherches LDAP (`paged_search`) pour dépasser la limite de
  1000 résultats.

## [1.36.0]

- Analyse automatique des logs au démarrage, détection d'erreurs critiques,
  corrections automatiques.
- Gestion des scripts PowerShell depuis l'interface web (9 scripts).
- Page `/ous/` enrichie : statistiques, recherche, filtres.
