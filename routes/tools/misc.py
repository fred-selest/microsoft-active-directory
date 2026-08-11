"""Routes diverses : modèles, favoris, API docs."""
from flask import render_template, request, session, redirect, url_for, flash
from datetime import datetime
import secrets
import hashlib

from . import tools_bp
from ..core import require_connection, require_permission
from core.user_templates import (
    load_templates, create_template, update_template, delete_template,
)

MAX_FAVORITES = 200


def _favorites_counts(favorites_list):
    counts = {'user': 0, 'group': 0, 'computer': 0, 'ou': 0}
    for fav in favorites_list:
        t = fav.get('type')
        if t in counts:
            counts[t] += 1
    return counts


@tools_bp.route('/templates')
@require_connection
def user_templates():
    """Page des modèles utilisateurs."""
    return render_template('user_templates.html', templates=load_templates(), connected=True)


@tools_bp.route('/templates/create', methods=['GET', 'POST'])
@require_connection
@require_permission('admin:user_templates')
def create_user_template():
    """Créer un modèle utilisateur."""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Le nom du modèle est requis.', 'error')
            return render_template('template_form.html', action='create', connected=True)

        attributes = {
            'department': request.form.get('department', '').strip(),
            'title': request.form.get('title', '').strip(),
            'description': request.form.get('user_description', '').strip(),
        }
        create_template(name, request.form.get('description', '').strip(), attributes)
        flash('Modèle créé.', 'success')
        return redirect(url_for('tools.user_templates'))

    return render_template('template_form.html', action='create', connected=True)


@tools_bp.route('/templates/<template_id>/edit', methods=['GET', 'POST'])
@require_connection
@require_permission('admin:user_templates')
def edit_user_template(template_id):
    """Éditer un modèle."""
    templates = load_templates()
    template = templates.get(template_id)
    if not template:
        flash('Modèle introuvable.', 'error')
        return redirect(url_for('tools.user_templates'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Le nom du modèle est requis.', 'error')
            return render_template('template_form.html', action='edit',
                                   template_id=template_id, template=template, connected=True)

        attributes = {
            'department': request.form.get('department', '').strip(),
            'title': request.form.get('title', '').strip(),
            'description': request.form.get('user_description', '').strip(),
        }
        update_template(template_id, name, request.form.get('description', '').strip(), attributes)
        flash('Modèle mis à jour.', 'success')
        return redirect(url_for('tools.user_templates'))

    return render_template('template_form.html', action='edit',
                           template_id=template_id, template=template, connected=True)


@tools_bp.route('/templates/<template_id>/delete', methods=['POST'])
@require_connection
@require_permission('admin:user_templates')
def delete_user_template(template_id):
    """Supprimer un modèle utilisateur."""
    if delete_template(template_id):
        flash('Modèle supprimé.', 'success')
    else:
        flash('Modèle introuvable.', 'error')
    return redirect(url_for('tools.user_templates'))


@tools_bp.route('/favorites')
@require_connection
def favorites():
    """Page des favoris."""
    favorites_list = session.get('favorites', [])
    return render_template('favorites_page.html', favorites=favorites_list,
                           counts=_favorites_counts(favorites_list), connected=True)


@tools_bp.route('/favorites/toggle', methods=['POST'])
@require_connection
def toggle_favorite():
    """Ajouter/retirer un favori."""
    dn = request.form.get('dn', '').strip()
    if not dn:
        flash('Élément invalide.', 'error')
        return redirect(url_for('tools.favorites'))

    favorites_list = session.get('favorites', [])

    if request.form.get('action') == 'remove':
        favorites_list = [f for f in favorites_list if f.get('dn') != dn]
    else:
        fav_type = request.form.get('type', '').strip()
        name = request.form.get('name', '').strip()
        if not fav_type or not name:
            flash('Élément invalide.', 'error')
            return redirect(request.referrer or url_for('tools.favorites'))
        if not any(f.get('dn') == dn for f in favorites_list):
            if len(favorites_list) >= MAX_FAVORITES:
                flash(f'Limite de {MAX_FAVORITES} favoris atteinte.', 'error')
                return redirect(request.referrer or url_for('tools.favorites'))
            favorites_list.append({
                'dn': dn,
                'type': fav_type,
                'name': name,
                'added': datetime.now().isoformat(),
            })

    session['favorites'] = favorites_list
    return redirect(request.referrer or url_for('tools.favorites'))


@tools_bp.route('/api-docs')
@require_connection
@require_permission('admin:api_keys')
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
    
    # Catalogue des permissions granulaires (le template affiche ce tableau)
    from core.granular_permissions import get_available_permissions

    api_data = {
        'version': get_current_version(),
        'base_url': request.host_url.rstrip('/') + '/api',
        'authentication': {
            'type': 'Session Cookie',
            'example': 'curl -b session=YOUR_SESSION_ID http://localhost:5000/api/health'
        },
        'endpoints': api_endpoints,
        'permissions': get_available_permissions()
    }
    
    # Récupérer les clés API de la session
    user_api_keys = session.get('api_keys', {})
    
    return render_template('api_docs.html', 
                         api_docs=api_data, 
                         api_keys=user_api_keys,
                         connected=True)


@tools_bp.route('/api-docs/generate-key', methods=['POST'])
@require_connection
@require_permission('admin:api_keys')
def generate_api_key_route():
    """Générer une nouvelle clé API."""
    name = request.form.get('name', 'Clé API')
    permissions = request.form.getlist('permissions')

    # Générer une clé
    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()[:16]

    # Stocker UNIQUEMENT le hash (JAMAIS la clé brute)
    if 'api_keys' not in session:
        session['api_keys'] = {}

    session['api_keys'][key_hash] = {
        'name': name,
        'permissions': permissions,
        'created': datetime.now().isoformat(),
        'last_used': None
        # raw_key N'est JAMAIS stocké - retourné une seule fois à l'utilisateur
    }

    # Afficher la clé une seule fois, via le flash (le template api_docs.html
    # ne rendait pas new_key de toute facon).
    flash(f'Nouvelle clé API générée : {raw_key} (elle ne sera plus jamais affichée, copiez-la maintenant).', 'success')
    return redirect(url_for('tools.api_documentation'))


@tools_bp.route('/api-docs/revoke-key', methods=['POST'])
@require_connection
@require_permission('admin:api_keys')
def revoke_api_key_route():
    """Révoquer une clé API."""
    key = request.form.get('key')

    if 'api_keys' in session and key in session['api_keys']:
        del session['api_keys'][key]
        flash('Clé API révoquée.', 'success')
    else:
        flash('Clé API introuvable.', 'error')

    return redirect(url_for('tools.api_documentation'))
