"""Routes diverses : modèles, favoris, API docs."""
from flask import render_template, request, session
from datetime import datetime
import secrets
import hashlib

from . import tools_bp
from ..core import require_connection, require_permission


@tools_bp.route('/templates')
@require_connection
def user_templates():
    """Page des modèles utilisateurs (placeholder)."""
    return render_template('user_templates.html', connected=True)


@tools_bp.route('/templates/create', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def create_user_template():
    """Créer un modèle utilisateur."""
    return render_template('template_form.html', action='create', connected=True)


@tools_bp.route('/templates/<template_id>/edit', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def edit_user_template(template_id):
    """Éditer un modèle."""
    return render_template('template_form.html', action='edit', template_id=template_id, connected=True)


@tools_bp.route('/templates/<template_id>/delete', methods=['POST'])
@require_connection
@require_permission('write')
def delete_user_template(template_id):
    """Supprimer un modèle."""
    # TODO: Implémenter la suppression
    return render_template('user_templates.html', connected=True)


@tools_bp.route('/favorites')
@require_connection
def favorites():
    """Page des favoris."""
    return render_template('favorites_page.html', connected=True)


@tools_bp.route('/favorites/toggle', methods=['POST'])
@require_connection
def toggle_favorite():
    """Ajouter/retirer un favori."""
    # TODO: Implémenter
    return render_template('favorites_page.html', connected=True)


@tools_bp.route('/api-docs')
@require_connection
@require_permission('admin')
def api_documentation():
    """Documentation de l'API."""
    from core.updater import get_current_version
    
    # Liste complète des endpoints API
    api_endpoints = {
        # Health & System
        '/api/health': {'GET': 'Health check de l\'application'},
        '/api/system-info': {'GET': 'Informations système complètes'},
        
        # Diagnostic
        '/api/diagnostic': {'GET': 'Exécuter un diagnostic complet'},
        
        # Password Audit
        '/api/password-audit': {'GET': 'Lancer un audit des mots de passe'},
        '/api/password-audit/quick-fix': {'POST': 'Appliquer des corrections rapides MDP'},
        
        # Alerts
        '/api/alerts': {'GET': 'Récupérer toutes les alertes'},
        '/api/alerts/<id>/acknowledge': {'POST': 'Acquitter une alerte'},
        '/api/alerts/<id>/delete': {'POST': 'Supprimer une alerte'},
        '/api/alerts/check': {'POST': 'Vérifier les nouvelles alertes'},
        
        # Updates
        '/api/check-update': {'GET': 'Vérifier les mises à jour'},
        '/api/perform-update': {'POST': 'Effectuer une mise à jour'},
        
        # Error Logs
        '/api/errors': {'GET': 'Récupérer les logs d\'erreurs'},
        
        # Security
        '/api/security-fix': {'POST': 'Appliquer une correction de sécurité'},
        
        # Permissions
        '/api/permissions': {'POST': 'Définir les permissions', 'DELETE': 'Supprimer permissions'},
        
        # Scripts PowerShell
        '/api/scripts': {'GET': 'Lister les scripts disponibles'},
        '/api/scripts/<name>/execute': {'POST': 'Exécuter un script'},
        '/api/scripts/<name>/download': {'GET': 'Télécharger un script'},
        '/api/scripts/<name>/content': {'GET': 'Voir le contenu d\'un script'},
        '/api/scripts/<name>/prerequisites': {'GET': 'Vérifier les prérequis'},
        '/api/scripts/history': {'GET': 'Historique des exécutions'},
        '/api/scripts/history/clear': {'POST': 'Vider l\'historique'},
    }
    
    api_data = {
        'version': get_current_version(),
        'base_url': request.host_url.rstrip('/') + '/api',
        'authentication': {
            'type': 'Session Cookie',
            'example': 'curl -b session=YOUR_SESSION_ID http://localhost:5000/api/health'
        },
        'endpoints': api_endpoints
    }
    
    # Récupérer les clés API de la session
    user_api_keys = session.get('api_keys', {})
    
    return render_template('api_docs.html', 
                         api_docs=api_data, 
                         api_keys=user_api_keys,
                         connected=True)


@tools_bp.route('/api-docs/generate-key', methods=['POST'])
@require_connection
@require_permission('admin')
def generate_api_key_route():
    """Générer une nouvelle clé API."""
    name = request.form.get('name', 'Clé API')
    permissions = request.form.getlist('permissions')
    
    # Générer une clé
    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()[:16]
    
    # Stocker la clé (dans la session pour l'instant)
    if 'api_keys' not in session:
        session['api_keys'] = {}
    
    session['api_keys'][key_hash] = {
        'name': name,
        'permissions': permissions,
        'created': datetime.now().isoformat(),
        'last_used': None,
        'raw_key': raw_key  # À ne jamais stocker en prod !
    }
    
    # Afficher la clé une seule fois
    return render_template('api_docs.html',
                         api_docs={'version': '1.0', 'base_url': request.host_url},
                         api_keys=session.get('api_keys', {}),
                         new_key=raw_key,
                         connected=True)


@tools_bp.route('/api-docs/revoke-key', methods=['POST'])
@require_connection
@require_permission('admin')
def revoke_api_key_route():
    """Révoquer une clé API."""
    key = request.form.get('key')
    
    if 'api_keys' in session and key in session['api_keys']:
        del session['api_keys'][key]
    
    return render_template('api_docs.html',
                         api_docs={'version': '1.0', 'base_url': request.host_url},
                         api_keys=session.get('api_keys', {}),
                         connected=True)
