# 🧩 Système de Feature Flags - AD Web Interface

## Vue d'ensemble

L'application intègre un système complet de **feature flags** permettant d'activer ou désactiver individuellement chaque fonctionnalité. Cela offre une modularité totale et permet d'adapter l'application aux besoins spécifiques de chaque déploiement.

---

## 📋 Fonctionnalités disponibles

### Gestion des utilisateurs
| Feature | Variable d'environnement | Défaut | Description |
|---------|-------------------------|--------|-------------|
| Utilisateurs | `FEATURE_USERS_ENABLED` | `true` | Page de liste des utilisateurs |
| Créer utilisateur | `FEATURE_CREATE_USER_ENABLED` | `true` | Formulaire de création |
| Modifier utilisateur | `FEATURE_EDIT_USER_ENABLED` | `true` | Formulaire d'édition |
| Supprimer utilisateur | `FEATURE_DELETE_USER_ENABLED` | `true` | Bouton de suppression |
| Importer utilisateurs | `FEATURE_IMPORT_USERS_ENABLED` | `true` | Import depuis CSV |
| Exporter utilisateurs | `FEATURE_EXPORT_USERS_ENABLED` | `true` | Export vers CSV/Excel |

### Gestion des groupes
| Feature | Variable d'environnement | Défaut | Description |
|---------|-------------------------|--------|-------------|
| Groupes | `FEATURE_GROUPS_ENABLED` | `true` | Page de liste des groupes |
| Créer groupe | `FEATURE_CREATE_GROUP_ENABLED` | `true` | Formulaire de création |
| Modifier groupe | `FEATURE_EDIT_GROUP_ENABLED` | `true` | Formulaire d'édition |
| Supprimer groupe | `FEATURE_DELETE_GROUP_ENABLED` | `true` | Bouton de suppression |

### Gestion des ordinateurs
| Feature | Variable d'environnement | Défaut | Description |
|---------|-------------------------|--------|-------------|
| Ordinateurs | `FEATURE_COMPUTERS_ENABLED` | `true` | Page de liste des ordinateurs |
| LAPS | `FEATURE_LAPS_ENABLED` | `true` | Mots de passe LAPS |
| BitLocker | `FEATURE_BITLOCKER_ENABLED` | `true` | Clés de récupération BitLocker |

### Gestion des OUs
| Feature | Variable d'environnement | Défaut | Description |
|---------|-------------------------|--------|-------------|
| OUs | `FEATURE_OUS_ENABLED` | `true` | Unités d'organisation |

### Outils avancés
| Feature | Variable d'environnement | Défaut | Description |
|---------|-------------------------|--------|-------------|
| Corbeille AD | `FEATURE_RECYCLE_BIN_ENABLED` | `false` | Objets supprimés (⚠️ Non implémenté) |
| Comptes verrouillés | `FEATURE_LOCKED_ACCOUNTS_ENABLED` | `false` | Gestion des lockouts (⚠️ Non implémenté) |
| Comptes expirants | `FEATURE_EXPIRING_ACCOUNTS_ENABLED` | `true` | Alertes d'expiration |
| Politique MDP | `FEATURE_PASSWORD_POLICY_ENABLED` | `true` | Politique de mots de passe |
| Audit MDP | `FEATURE_PASSWORD_AUDIT_ENABLED` | `true` | Analyse de sécurité MDP |

### Administration
| Feature | Variable d'environnement | Défaut | Description |
|---------|-------------------------|--------|-------------|
| Journal d'audit | `FEATURE_AUDIT_LOGS_ENABLED` | `true` | Logs d'activité |
| Sauvegardes | `FEATURE_BACKUPS_ENABLED` | `true` | Backups d'objets AD |
| Diagnostic | `FEATURE_DIAGNOSTIC_ENABLED` | `true` | Outil de diagnostic |
| API Docs | `FEATURE_API_DOCS_ENABLED` | `true` | Documentation API |
| Paramètres | `FEATURE_SETTINGS_ENABLED` | `true` | Configuration de l'app |

### Fonctionnalités utilisateur
| Feature | Variable d'environnement | Défaut | Description |
|---------|-------------------------|--------|-------------|
| Favoris | `FEATURE_FAVORITES_ENABLED` | `true` | Pages favorites |
| Modèles | `FEATURE_TEMPLATES_ENABLED` | `true` | Templates utilisateurs |
| Mode sombre | `FEATURE_DARK_MODE_ENABLED` | `true` | Thème sombre/clair |
| Multi-langue | `FEATURE_LANGUAGE_SWITCH_ENABLED` | `false` | Français/Anglais |

### Système
| Feature | Variable d'environnement | Défaut | Description |
|---------|-------------------------|--------|-------------|
| Mises à jour | `FEATURE_UPDATE_CHECK_ENABLED` | `true` | Vérification auto |
| PWA | `FEATURE_PWA_ENABLED` | `true` | Progressive Web App |

---

## ⚙️ Configuration

### Fichier `.env`

Copiez le fichier `.env.example` vers `.env` et personnalisez :

```ini
# Exemple de configuration modulaire
FEATURE_USERS_ENABLED=true
FEATURE_GROUPS_ENABLED=true
FEATURE_COMPUTERS_ENABLED=true
FEATURE_OUS_ENABLED=true

# Désactiver les fonctionnalités non implémentées
FEATURE_RECYCLE_BIN_ENABLED=false
FEATURE_LOCKED_ACCOUNTS_ENABLED=false

# Personnalisation
FEATURE_DARK_MODE_ENABLED=true
FEATURE_LANGUAGE_SWITCH_ENABLED=false
```

### Utilisation dans les templates

Les feature flags sont accessibles via `config.FEATURE_<NOM>_ENABLED` :

```jinja2
{% if config.FEATURE_LAPS_ENABLED %}
    <a href="{{ url_for('tools.laps_passwords') }}">LAPS</a>
{% endif %}
```

### Utilisation dans les routes

Utilisez le décorateur `@require_feature` :

```python
from features import require_feature

@tools_bp.route('/laps')
@require_feature('laps')
def laps_passwords():
    # ...
```

---

## 🚧 Fonctionnalités non implémentées

Certaines fonctionnalités sont désactivées par défaut car non encore implémentées :

### Corbeille AD (`FEATURE_RECYCLE_BIN_ENABLED`)
- **Statut** : Partiellement implémenté
- **Problème** : La restauration d'objets nécessite des opérations LDAP spéciales
- **Workaround** : Utiliser les outils AD natifs

### Comptes verrouillés (`FEATURE_LOCKED_ACCOUNTS_ENABLED`)
- **Statut** : Partiellement implémenté
- **Problème** : Le déblocage en masse nécessite des tests approfondis
- **Workaround** : Débloquer individuellement via ADUC

---

## 📊 Architecture modulaire

```
┌─────────────────────────────────────────────────────────────┐
│                    Feature Flags System                      │
├─────────────────────────────────────────────────────────────┤
│  config.py  →  Définition des flags (FEATURE_XXX_ENABLED)   │
│  features.py →  Utilitaires (is_feature_enabled, etc.)      │
│  app.py     →  Injection dans le contexte template          │
│  base.html  →  Menu conditionnel selon les flags            │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 Dépannage

### Une page affiche "Fonctionnalité non disponible"

1. Vérifiez que la feature est activée dans `.env`
2. Redémarrez le serveur
3. Vérifiez les logs : `logs/server.log`

### Une page retourne une erreur 500

1. Consultez les logs d'erreur
2. Vérifiez que toutes les dépendances sont installées
3. Assurez-vous que la route existe dans le blueprint correspondant

### Le menu n'affiche pas certaines options

1. Vérifiez les permissions RBAC de l'utilisateur
2. Vérifiez que `FEATURE_XXX_ENABLED=true` dans `.env`
3. Rechargez la page (F5)

---

## 📝 Bonnes pratiques

1. **Production** : Désactivez les fonctionnalités non testées
2. **Développement** : Activez toutes les fonctionnalités pour tester
3. **Sécurité** : Désactivez les fonctionnalités inutiles pour réduire la surface d'attaque
4. **Performance** : Désactivez les fonctionnalités non utilisées pour améliorer les performances

---

## 🔄 Mises à jour futures

Fonctionnalités prévues :
- [ ] Corbeille AD complète avec restauration
- [ ] Déblocage en masse des comptes
- [ ] Export PDF des rapports
- [ ] Multi-langue complet (FR/EN)
- [ ] Templates d'utilisateurs avancés

---

**Version** : 1.21.0  
**Dernière mise à jour** : 2026-04-01
