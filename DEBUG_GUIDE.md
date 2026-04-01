# 🛠️ Guide de Débogage - AD Web Interface v1.22.0

## 📋 Outils de débogage installés

### 1. Flask Debug Toolbar ✅

**Installation automatique** quand `FLASK_DEBUG=true`

**Fonctionnalités :**
- ⏱️ Timer de performance
- 📦 Versions des packages
- 📝 Requêtes SQL
- 🌐 Headers HTTP
- 📄 Templates rendus
- 🪵 Logs d'application
- 🗺️ Routes Flask
- 📊 Profiler de performance

**Accès :** La toolbar apparaît en bas de chaque page quand le debug est activé.

---

### 2. Debug Dashboard (`/_debug`)

**URL :** `http://localhost:5000/_debug`

**Fonctionnalités :**
- 💾 Informations de session
- 🚩 État des feature flags
- ⚙️ Configuration de l'application
- 📋 Liste des routes
- 📄 Liste des templates
- 📜 Logs (debug, error, audit)
- ✅ Test de toutes les pages

**Screenshot :**
```
┌─────────────────────────────────────┐
│  🔍 Debug Dashboard                 │
├─────────────────────────────────────┤
│  💾 Session                         │
│  ✅ Connecté: Oui                   │
│  👤 Username: admin                 │
│  🔑 Rôle: admin                     │
├─────────────────────────────────────┤
│  🚩 Feature Flags                   │
│  ✅ users      ❌ recycle_bin       │
│  ✅ groups     ❌ locked_accounts   │
│  ✅ computers  ✅ audit_logs        │
├─────────────────────────────────────┤
│  ⚡ Quick Actions                   │
│  [Voir routes] [Voir templates]     │
│  [Voir session] [Voir config]       │
│  [Voir logs] [Tester toutes pages]  │
└─────────────────────────────────────┘
```

---

### 3. Routes de Debug

| Route | Description |
|-------|-------------|
| `/_debug/` | Dashboard principal |
| `/_debug/api` | Infos de debug en JSON |
| `/_debug/routes` | Liste des routes |
| `/_debug/templates` | Liste des templates |
| `/_debug/session` | Contenu de la session |
| `/_debug/config` | Configuration |
| `/_debug/logs?type=debug` | Logs (debug/error/audit/service) |
| `/_debug/test/<page>` | Teste une page spécifique |
| `/_debug/all-pages` | Teste toutes les pages |

---

### 4. Logging

**Fichiers de logs :**
- `logs/debug.log` - Logs de debug détaillés
- `logs/server.log` - Logs du serveur
- `logs/audit.log` - Journal d'audit
- `logs/service.log` - Logs du service Windows

**Niveaux de log :**
- `DEBUG` - Informations détaillées
- `INFO` - Informations générales
- `WARNING` - Avertissements
- `ERROR` - Erreurs

**Exemple d'utilisation :**
```python
from debug_utils import logger

logger.debug("Valeur de x: %s", x)
logger.info("Utilisateur connecté: %s", username)
logger.warning("Tentative échouée: %s", ip)
logger.error("Erreur critique: %s", error)
```

---

### 5. Decorators de Debug

**`@debug_route`** - Décore une route pour la debugger :

```python
from debug_utils import debug_route

@app.route('/dashboard')
@debug_route
def dashboard():
    # Cette route sera automatiquement debugguée
    # Logs: début, fin, temps d'exécution, erreurs
    return render_template('dashboard.html')
```

**`DebugTimer`** - Chronomètre pour mesurer les performances :

```python
from debug_utils import DebugTimer

with DebugTimer("Requête LDAP"):
    conn.search(base_dn, filter, attributes)
    # Affiche le temps d'exécution dans les logs
```

---

## 🚀 Utilisation

### Étape 1 : Activer le debug

Dans `.env` :
```ini
FLASK_DEBUG=true
FLASK_ENV=development
AD_SILENT=false
```

### Étape 2 : Redémarrer le serveur

```bat
net stop ADWebInterface
net start ADWebInterface
```

Ou en mode développement :
```bat
python run.py
```

### Étape 3 : Accéder au Debug Dashboard

Ouvrez votre navigateur :
```
http://localhost:5000/_debug
```

### Étape 4 : Utiliser la Debug Toolbar

La toolbar apparaît en bas de chaque page :
- Cliquez sur les panneaux pour voir les détails
- Consultez le temps d'exécution
- Vérifiez les requêtes SQL
- Examinez les templates rendus

---

## 🐛 Déboguer une page spécifique

### Exemple : Page `/users` qui échoue

**1. Ouvrir DevTools du navigateur (`F12`)**
- Onglet **Console** → Voir les erreurs JavaScript
- Onglet **Network** → Voir la requête `/users`
- Status code : 500 ? 404 ?

**2. Consulter les logs**
```
http://localhost:5000/_debug/logs?type=error
```

**3. Tester la page**
```
http://localhost:5000/_debug/test/users
```

**4. Vérifier la route**
```
http://localhost:5000/_debug/routes
```

**5. Examiner la session**
```
http://localhost:5000/_debug/session
```

**6. Utiliser le decorator `@debug_route`**

Dans `routes/users.py` :
```python
from debug_utils import debug_route

@users_bp.route('/')
@debug_route
def list_users():
    # Logs automatiques ajoutés
    ...
```

---

## 📊 Analyser les performances

### Utiliser DebugTimer

```python
from debug_utils import DebugTimer

# Chronométrer une fonction
with DebugTimer("Recherche LDAP"):
    conn.search(base_dn, filter, SUBTREE, attributes)
    # Log: ⏱️  FIN: Recherche LDAP - 145.23ms
```

### Consulter le Timer Panel

1. Ouvrir une page
2. Regarder la Debug Toolbar en bas
3. Cliquer sur "Timer"
4. Voir le temps par appel :
   - Total request time
   - Template rendering
   - SQL queries
   - etc.

---

## 🔍 Commands utiles

### Voir les logs en temps réel
```powershell
powershell -Command "Get-Content logs\\debug.log -Wait -Tail 50"
```

### Tester toutes les pages
```
http://localhost:5000/_debug/all-pages
```

### Exporter les infos de debug
```
http://localhost:5000/_debug/api
```

### Vérifier une route spécifique
```python
python -c "from app import app; print([r.rule for r in app.url_map.iter_rules() if 'users' in r.endpoint])"
```

---

## ⚠️ Important

### Ne JAMAIS utiliser en production

```ini
# ❌ EN PRODUCTION :
FLASK_DEBUG=false
FLASK_ENV=production

# ✅ EN DÉVELOPPEMENT :
FLASK_DEBUG=true
FLASK_ENV=development
```

**Pourquoi ?**
- Les pages d'erreur affichent des informations sensibles
- La toolbar consomme des ressources
- Les logs peuvent contenir des données confidentielles

---

## 📖 Exemples

### Exemple 1 : Débugger une erreur 500

```python
# 1. Activer le debug
FLASK_DEBUG=true

# 2. Ajouter le decorator
@users_bp.route('/<path:dn>/edit')
@debug_route
def edit_user(dn):
    # Les logs afficheront :
    # 🔍 ROUTE: edit_user
    # 📄 ARGS: (...)
    # ❌ ERREUR: ... (si erreur)
    ...
```

### Exemple 2 : Mesurer une requête LDAP

```python
from debug_utils import DebugTimer, debug_ldap_query

@debug_ldap_query
def get_user(conn, dn):
    with DebugTimer("LDAP get_user"):
        conn.search(dn, '(objectClass=user)', attributes=['*'])
        return conn.entries
```

### Exemple 3 : Vérifier les feature flags

```python
# Dashboard de debug
http://localhost:5000/_debug

# Section "Feature Flags" montre :
# ✅ users
# ✅ groups
# ❌ recycle_bin (désactivé)
```

---

## 🎯 Checklist de débogage

- [ ] `FLASK_DEBUG=true` dans `.env`
- [ ] Serveur redémarré
- [ ] Debug Toolbar visible en bas des pages
- [ ] Accès à `/_debug` fonctionnel
- [ ] Logs dans `logs/debug.log`
- [ ] Decorators `@debug_route` ajoutés aux routes problématiques
- [ ] `DebugTimer` utilisé pour les opérations lentes

---

## 📞 Support

En cas de problème :

1. Consulter `logs/debug.log`
2. Vérifier `/_debug/logs?type=error`
3. Examiner la stack trace dans la console
4. Tester avec `/_debug/test/<page>`

---

**Débogage efficace !** 🐛🔍
