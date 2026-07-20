# Migration — correctif du contrôle d'accès (C1)

**Concerne :** toute installation antérieure à ce correctif dont le fichier
`data/permissions.json` contient des entrées personnalisées.

## Ce qui change

Avant, une permission suffisait pour tout. Le contrôle d'accès accordait
l'autorisation dès qu'il existait **une intersection** entre les permissions
détenues et les permissions requises ; comme les routes d'administration
exigeaient l'alias `admin`, traduit en la totalité des permissions, détenir
`users:read` ouvrait l'accès aux 64 routes d'administration — dont l'exécution
de scripts PowerShell sur le contrôleur de domaine.

Désormais le contrôle se fait par **inclusion** : la permission demandée doit
figurer explicitement dans celles de l'utilisateur.

## Conséquence attendue

**Des utilisateurs vont perdre des accès dont ils disposaient — c'est l'objet
du correctif, pas un effet de bord.** Ils ne détenaient ces accès qu'à cause du
défaut.

Exemple, tiré d'une configuration réelle : un groupe d'équipe support portant
10 permissions de gestion d'utilisateurs et d'ordinateurs — et aucune
permission d'administration — disposait de fait de l'administration complète.
Après migration, il ne conserve que ses 10 permissions déclarées.

Les membres de **Administrateurs du domaine** / **Administrateurs de
l'entreprise** ne sont pas affectés : ils conservent l'accès complet, via les
rôles prédéfinis et via le filet de sécurité qui empêche un verrouillage total
en cas de configuration erronée.

## À faire après mise à jour

1. Ouvrir **Administration → Permissions**.
2. Pour chaque groupe listé, vérifier que les permissions cochées correspondent
   à ce dont l'équipe a réellement besoin — et non à ce dont elle disposait.
3. Attribuer explicitement les nouvelles permissions si nécessaire :

| Permission | Donne accès à | Remarque |
|---|---|---|
| `system:execute_script` | Exécution de scripts PowerShell sur le DC | **La plus sensible de l'application** |
| `system:update` | Déclenchement d'une mise à jour | Exécute du code téléchargé |
| `system:configure_ldaps` | Configuration LDAPS / LAPS du domaine | Modifie le domaine |
| `admin:permissions` | Gestion des permissions | Méta : permet de s'accorder le reste |
| `tools:laps` | Mots de passe administrateur locaux | Équivaut à l'admin local des postes |
| `tools:bitlocker` | Clés de récupération BitLocker | Déchiffrement des disques |
| `tools:recycle_bin` | Corbeille AD, restauration d'objets | |
| `tools:unlock_accounts` | Déverrouillage de comptes | Séparé de la simple consultation |
| `admin:api_keys` | Génération / révocation de clés API | |
| `admin:log_analysis` | Analyse des logs | |

Les sept premières sont marquées sensibles (`SENSITIVE_PERMISSIONS`) : elles
donnent, directement ou indirectement, un contrôle complet du domaine.
À réserver aux administrateurs.

## Si un utilisateur signale une perte d'accès

C'est le comportement attendu. Vérifier la permission granulaire précise que
la page requiert (`@require_permission('...')` sur la route concernée) et
l'accorder délibérément — plutôt que de rétablir un accès large.

Les refus sont tracés :

```
Permission 'tools:laps' refusée à DOMAINE\jdupont (groupes=['Equipe-Support'])
```

## Ne pas faire

Ne pas réintroduire d'alias à large périmètre (`admin`, `write`, `delete`) dans
les gardes de routes : c'est précisément le motif qui rendait la faille
exploitable. Le test `tests/test_permissions_c1.py::test_aucun_alias_legacy_dans_les_gardes`
échoue si l'un d'eux réapparaît.
