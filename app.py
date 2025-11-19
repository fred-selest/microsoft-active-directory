"""
Interface Web Multi-Plateforme pour Microsoft Active Directory.
Fonctionne sur les systèmes Windows et Linux.
"""

import os
import platform
import csv
import io
from datetime import timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, session, Response
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
from ldap3.core.exceptions import LDAPException
from config import get_config, CURRENT_OS, IS_WINDOWS
from audit import log_action, get_audit_logs, ACTIONS
from backup import backup_object, get_backups, get_backup_content, record_change, get_object_history, get_all_history
from security import (
    escape_ldap_filter, sanitize_dn_component, check_rate_limit, record_login_attempt,
    validate_password_strength, get_password_requirements, add_security_headers,
    get_secure_session_config, generate_csrf_token, validate_csrf_token
)
from translations import get_translation, get_all_translations, Translator
from api import generate_api_key, revoke_api_key, load_api_keys, get_api_documentation, require_api_key
from user_templates import get_all_templates, get_template, create_template, update_template, delete_template, apply_template, init_default_templates
from alerts import add_alert, get_alerts, acknowledge_alert, delete_alert as delete_alert_func, get_alert_counts, check_expiring_accounts, check_inactive_accounts
from favorites import get_user_favorites, add_favorite, remove_favorite, is_favorite, get_favorites_count


def decode_ldap_value(value):
    """Decoder correctement une valeur LDAP en UTF-8."""
    if value is None:
        return ''
    if hasattr(value, 'value'):
        val = value.value
    else:
        val = value

    if val is None:
        return ''
    if isinstance(val, bytes):
        try:
            return val.decode('utf-8')
        except:
            return val.decode('latin-1')
    if isinstance(val, list):
        return [decode_ldap_value(v) for v in val]
    return str(val)


app = Flask(__name__)
config = get_config()

# Appliquer la configuration
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['DEBUG'] = config.DEBUG
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=config.SESSION_TIMEOUT)

# Configuration de session securisee
secure_session = get_secure_session_config()
app.config['SESSION_COOKIE_HTTPONLY'] = secure_session['SESSION_COOKIE_HTTPONLY']
app.config['SESSION_COOKIE_SAMESITE'] = secure_session['SESSION_COOKIE_SAMESITE']
app.config['SESSION_COOKIE_NAME'] = secure_session['SESSION_COOKIE_NAME']

# Initialiser les répertoires
config.init_directories()

# Configuration RBAC
ROLE_PERMISSIONS = {
    'admin': ['read', 'write', 'delete', 'admin'],
    'operator': ['read', 'write'],
    'reader': ['read']
}


def require_permission(permission):
    """Decorateur pour verifier les permissions RBAC."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if config.RBAC_ENABLED:
                user_role = session.get('user_role', config.DEFAULT_ROLE)
                if permission not in ROLE_PERMISSIONS.get(user_role, []):
                    flash('Permission refusee. Vous n\'avez pas les droits necessaires.', 'error')
                    return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Cache pour la vérification des mises à jour (éviter les appels répétés)
_update_cache = {'last_check': 0, 'result': None}


@app.context_processor
def inject_update_info():
    """Injecter les infos de mise à jour dans tous les templates."""
    import time
    from updater import check_for_updates

    # Vérifier toutes les 5 minutes maximum
    current_time = time.time()
    if _update_cache['result'] is None or (current_time - _update_cache['last_check']) > 300:
        try:
            _update_cache['result'] = check_for_updates()
            _update_cache['last_check'] = current_time
        except:
            _update_cache['result'] = {'update_available': False}

    # Traductions
    lang = session.get('language', 'fr')
    translator = Translator(lang)

    return {
        'update_info': _update_cache['result'],
        'user_role': session.get('user_role', config.DEFAULT_ROLE),
        'dark_mode': session.get('dark_mode', False),
        'config': config,
        'csrf_token': generate_csrf_token,
        'password_requirements': get_password_requirements(),
        't': translator,
        'current_lang': lang,
        'alert_counts': get_alert_counts()
    }


@app.before_request
def before_request():
    """Verifier le timeout de session et rendre la session permanente."""
    session.permanent = True
    if is_connected():
        session.modified = True


@app.after_request
def after_request(response):
    """Ajouter les headers de securite a chaque reponse."""
    return add_security_headers(response)


def get_ad_connection(server=None, username=None, password=None, use_ssl=False, port=None):
    """
    Créer une connexion à Active Directory.
    Utilise les informations de session si non fournies.
    """
    # Utiliser les valeurs de session si non fournies
    if server is None:
        server = session.get('ad_server')
    if username is None:
        username = session.get('ad_username')
    if password is None:
        password = session.get('ad_password')
    if use_ssl is False:
        use_ssl = session.get('ad_use_ssl', False)
    if port is None:
        port = session.get('ad_port')

    if not all([server, username, password]):
        return None, "Non connecté à Active Directory"

    if port is None:
        port = 636 if use_ssl else 389

    try:
        ad_server = Server(
            server,
            port=port,
            use_ssl=use_ssl,
            get_info=ALL
        )
        conn = Connection(
            ad_server,
            user=username,
            password=password,
            auto_bind=True
        )
        return conn, None
    except LDAPException as e:
        return None, str(e)


def is_connected():
    """Vérifier si l'utilisateur est connecté à AD."""
    return all([
        session.get('ad_server'),
        session.get('ad_username'),
        session.get('ad_password')
    ])


def require_connection(f):
    """Décorateur pour exiger une connexion AD."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_connected():
            flash('Veuillez vous connecter à Active Directory.', 'error')
            return redirect(url_for('connect'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    """Page d'accueil - redirige vers le tableau de bord si connecte."""
    if is_connected():
        return redirect(url_for('dashboard'))

    system_info = {
        'os': platform.system(),
        'os_version': platform.version(),
        'hostname': platform.node(),
        'python_version': platform.python_version(),
        'architecture': platform.machine()
    }
    return render_template('index.html', system_info=system_info, connected=False)


@app.route('/connect', methods=['GET', 'POST'])
def connect():
    """Connexion au serveur Active Directory."""
    if request.method == 'POST':
        # Verifier le token CSRF
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            flash('Token de securite invalide. Veuillez reessayer.', 'error')
            return render_template('connect.html', connected=is_connected())

        # Verifier le rate limiting
        ip = request.remote_addr
        allowed, remaining = check_rate_limit(ip, max_attempts=5, window_seconds=300)
        if not allowed:
            flash(f'Trop de tentatives de connexion. Reessayez dans {remaining} secondes.', 'error')
            return render_template('connect.html', connected=is_connected())

        server = request.form.get('server')
        username = request.form.get('username')
        password = request.form.get('password')
        use_ssl = request.form.get('use_ssl') == 'on'
        port = request.form.get('port', '')
        base_dn = request.form.get('base_dn', '')

        port = int(port) if port else None

        conn, error = get_ad_connection(server, username, password, use_ssl, port)

        if conn:
            # Enregistrer le succes et reinitialiser le compteur
            record_login_attempt(ip, success=True)
            # Stocker les informations de connexion en session
            session['ad_server'] = server
            session['ad_username'] = username
            session['ad_password'] = password
            session['ad_use_ssl'] = use_ssl
            session['ad_port'] = port
            session['ad_base_dn'] = base_dn

            # Détecter le Base DN si non fourni
            if not base_dn and conn.server.info:
                try:
                    naming_contexts = conn.server.info.naming_contexts
                    if naming_contexts:
                        session['ad_base_dn'] = str(naming_contexts[0])
                except:
                    pass

            conn.unbind()
            session['user_role'] = config.DEFAULT_ROLE
            log_action(ACTIONS['LOGIN'], username, {'server': server}, True, request.remote_addr)
            flash('Connexion réussie à Active Directory!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Enregistrer l'echec pour le rate limiting
            record_login_attempt(ip, success=False)
            log_action(ACTIONS['LOGIN'], username, {'server': server, 'error': error}, False, request.remote_addr)
            flash(f'Erreur de connexion: {error}', 'error')

    return render_template('connect.html', connected=is_connected())


@app.route('/disconnect')
def disconnect():
    """Déconnexion d'Active Directory."""
    username = session.get('ad_username', 'unknown')
    log_action(ACTIONS['LOGOUT'], username, {}, True, request.remote_addr)
    session.clear()
    flash('Déconnecté d\'Active Directory.', 'success')
    return redirect(url_for('index'))


@app.route('/toggle-dark-mode')
def toggle_dark_mode():
    """Basculer le mode sombre."""
    session['dark_mode'] = not session.get('dark_mode', False)
    return redirect(request.referrer or url_for('index'))


@app.route('/dashboard')
@require_connection
def dashboard():
    """Page du tableau de bord avec statistiques."""
    conn, error = get_ad_connection()
    stats = {
        'total_users': 0,
        'active_users': 0,
        'disabled_users': 0,
        'total_groups': 0,
        'empty_groups': 0,
        'total_ous': 0
    }

    if conn:
        base_dn = session.get('ad_base_dn', '')
        try:
            # Compter les utilisateurs
            conn.search(base_dn, '(&(objectClass=user)(objectCategory=person))', SUBTREE,
                       attributes=['userAccountControl'])
            stats['total_users'] = len(conn.entries)

            for entry in conn.entries:
                uac = entry.userAccountControl.value if entry.userAccountControl else 512
                if uac and int(uac) & 2:
                    stats['disabled_users'] += 1
                else:
                    stats['active_users'] += 1

            # Compter les groupes
            conn.search(base_dn, '(objectClass=group)', SUBTREE, attributes=['member'])
            stats['total_groups'] = len(conn.entries)
            for entry in conn.entries:
                members = list(entry.member) if entry.member else []
                if not members:
                    stats['empty_groups'] += 1

            # Compter les OUs
            conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE)
            stats['total_ous'] = len(conn.entries)

            conn.unbind()
        except Exception as e:
            conn.unbind()

    # Derniers logs d'audit
    recent_logs = get_audit_logs(limit=10)

    return render_template('dashboard.html', stats=stats, logs=recent_logs, connected=is_connected())


@app.route('/users')
@require_connection
def users():
    """Liste des utilisateurs Active Directory avec pagination."""
    conn, error = get_ad_connection()

    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = config.ITEMS_PER_PAGE

    # Construire le filtre de recherche avec protection contre injection LDAP
    if search_query:
        safe_query = escape_ldap_filter(search_query)
        search_filter = f'(&(objectClass=user)(objectCategory=person)(|(cn=*{safe_query}*)(sAMAccountName=*{safe_query}*)(mail=*{safe_query}*)))'
    else:
        search_filter = '(&(objectClass=user)(objectCategory=person))'

    try:
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[
                'cn', 'sAMAccountName', 'mail', 'distinguishedName',
                'givenName', 'sn', 'displayName', 'userAccountControl',
                'whenCreated', 'lastLogon', 'memberOf', 'department', 'title'
            ]
        )

        user_list = []
        for entry in conn.entries:
            # Vérifier si le compte est désactivé
            uac = entry.userAccountControl.value if hasattr(entry, 'userAccountControl') and entry.userAccountControl else 512
            is_disabled = bool(int(uac) & 2) if uac else False

            user_list.append({
                'cn': decode_ldap_value(entry.cn),
                'sAMAccountName': decode_ldap_value(entry.sAMAccountName),
                'mail': decode_ldap_value(entry.mail),
                'dn': decode_ldap_value(entry.distinguishedName),
                'givenName': decode_ldap_value(entry.givenName),
                'sn': decode_ldap_value(entry.sn),
                'displayName': decode_ldap_value(entry.displayName),
                'department': decode_ldap_value(entry.department),
                'title': decode_ldap_value(entry.title),
                'disabled': is_disabled
            })

        # Recuperer les OUs pour le deplacement
        ou_list = []
        conn.search(
            search_base=base_dn,
            search_filter='(objectClass=organizationalUnit)',
            search_scope=SUBTREE,
            attributes=['name', 'distinguishedName']
        )
        for entry in conn.entries:
            ou_list.append({
                'name': decode_ldap_value(entry.name),
                'dn': decode_ldap_value(entry.distinguishedName)
            })

        conn.unbind()

        # Pagination
        total = len(user_list)
        total_pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        end = start + per_page
        paginated_users = user_list[start:end]

        return render_template('users.html',
                             users=paginated_users,
                             search=search_query,
                             page=page,
                             total_pages=total_pages,
                             total=total,
                             ous=ou_list,
                             connected=is_connected())

    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur de recherche: {str(e)}', 'error')
        return render_template('users.html', users=[], search=search_query, page=1, total_pages=1, total=0, ous=[], connected=is_connected())


@app.route('/users/create', methods=['GET', 'POST'])
@require_connection
def create_user():
    """Créer un nouvel utilisateur."""
    if request.method == 'POST':
        conn, error = get_ad_connection()

        if not conn:
            flash(f'Erreur de connexion: {error}', 'error')
            return redirect(url_for('connect'))

        # Récupérer les données du formulaire
        username = request.form.get('sAMAccountName')
        first_name = request.form.get('givenName')
        last_name = request.form.get('sn')
        display_name = request.form.get('displayName') or f"{first_name} {last_name}"
        email = request.form.get('mail')
        password = request.form.get('password')
        ou = request.form.get('ou', '')
        department = request.form.get('department', '')
        title = request.form.get('title', '')

        # Valider la force du mot de passe
        if password:
            is_valid, pwd_message = validate_password_strength(password)
            if not is_valid:
                flash(f'Mot de passe invalide: {pwd_message}', 'error')
                conn.unbind()
                return redirect(url_for('create_user'))

        # Construire le DN
        base_dn = session.get('ad_base_dn', '')
        if ou:
            user_dn = f"CN={display_name},{ou}"
        else:
            user_dn = f"CN={display_name},CN=Users,{base_dn}"

        # Attributs de l'utilisateur
        user_attrs = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'cn': display_name,
            'sAMAccountName': username,
            'userPrincipalName': f"{username}@{session.get('ad_server', '')}",
            'givenName': first_name,
            'sn': last_name,
            'displayName': display_name,
        }

        if email:
            user_attrs['mail'] = email
        if department:
            user_attrs['department'] = department
        if title:
            user_attrs['title'] = title

        try:
            # Créer l'utilisateur
            conn.add(user_dn, attributes=user_attrs)

            if conn.result['result'] == 0:
                # Définir le mot de passe
                if password:
                    # Encoder le mot de passe pour AD
                    unicode_pwd = f'"{password}"'.encode('utf-16-le')
                    conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})

                    # Activer le compte
                    conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})

                log_action(ACTIONS['CREATE_USER'], session.get('ad_username'),
                          {'username': username, 'dn': user_dn}, True, request.remote_addr)
                flash(f'Utilisateur {username} créé avec succès!', 'success')
                conn.unbind()
                return redirect(url_for('users'))
            else:
                log_action(ACTIONS['CREATE_USER'], session.get('ad_username'),
                          {'username': username, 'error': conn.result['description']}, False, request.remote_addr)
                flash(f'Erreur lors de la création: {conn.result["description"]}', 'error')

        except LDAPException as e:
            flash(f'Erreur LDAP: {str(e)}', 'error')

        conn.unbind()

    # Récupérer les OUs disponibles
    conn, error = get_ad_connection()
    ous = []

    if conn:
        try:
            base_dn = session.get('ad_base_dn', '')
            conn.search(
                search_base=base_dn,
                search_filter='(objectClass=organizationalUnit)',
                search_scope=SUBTREE,
                attributes=['distinguishedName', 'name']
            )

            for entry in conn.entries:
                ous.append({
                    'dn': str(entry.distinguishedName),
                    'name': str(entry.name)
                })

            conn.unbind()
        except:
            pass

    return render_template('user_form.html', user=None, ous=ous, action='create', connected=is_connected())


@app.route('/users/<path:dn>/edit', methods=['GET', 'POST'])
@require_connection
def edit_user(dn):
    """Modifier un utilisateur existant."""
    conn, error = get_ad_connection()

    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('connect'))

    if request.method == 'POST':
        # Récupérer les données du formulaire
        modifications = {}

        fields = ['givenName', 'sn', 'displayName', 'mail', 'department', 'title', 'telephoneNumber', 'description']

        for field in fields:
            value = request.form.get(field, '')
            if value:
                modifications[field] = [(MODIFY_REPLACE, [value])]
            else:
                # Supprimer l'attribut si vide
                modifications[field] = [(MODIFY_DELETE, [])]

        try:
            if modifications:
                conn.modify(dn, modifications)

                if conn.result['result'] == 0:
                    flash('Utilisateur modifié avec succès!', 'success')
                else:
                    flash(f'Erreur: {conn.result["description"]}', 'error')

            # Gérer le changement de mot de passe
            new_password = request.form.get('new_password')
            if new_password:
                # Valider la force du mot de passe
                is_valid, pwd_message = validate_password_strength(new_password)
                if not is_valid:
                    flash(f'Mot de passe invalide: {pwd_message}', 'error')
                    conn.unbind()
                    return redirect(url_for('edit_user', dn=dn))

                unicode_pwd = f'"{new_password}"'.encode('utf-16-le')
                conn.modify(dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})

                if conn.result['result'] == 0:
                    flash('Mot de passe modifié avec succès!', 'success')
                else:
                    flash(f'Erreur mot de passe: {conn.result["description"]}', 'error')

            # Gérer l'activation/désactivation
            enable_account = request.form.get('enable_account')
            if enable_account == 'on':
                conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})
            elif enable_account == 'off':
                conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [514])]})

            conn.unbind()
            return redirect(url_for('users'))

        except LDAPException as e:
            flash(f'Erreur LDAP: {str(e)}', 'error')
            conn.unbind()
            return redirect(url_for('users'))

    # GET: Récupérer les informations de l'utilisateur
    try:
        conn.search(
            search_base=dn,
            search_filter='(objectClass=user)',
            search_scope=SUBTREE,
            attributes=[
                'cn', 'sAMAccountName', 'mail', 'givenName', 'sn',
                'displayName', 'department', 'title', 'telephoneNumber',
                'description', 'userAccountControl', 'memberOf'
            ]
        )

        if conn.entries:
            entry = conn.entries[0]
            uac = entry.userAccountControl.value if hasattr(entry, 'userAccountControl') and entry.userAccountControl else 512
            is_disabled = bool(int(uac) & 2) if uac else False

            user = {
                'dn': dn,
                'cn': decode_ldap_value(entry.cn),
                'sAMAccountName': decode_ldap_value(entry.sAMAccountName),
                'mail': decode_ldap_value(entry.mail),
                'givenName': decode_ldap_value(entry.givenName),
                'sn': decode_ldap_value(entry.sn),
                'displayName': decode_ldap_value(entry.displayName),
                'department': decode_ldap_value(entry.department),
                'title': decode_ldap_value(entry.title),
                'telephoneNumber': decode_ldap_value(entry.telephoneNumber),
                'description': decode_ldap_value(entry.description),
                'disabled': is_disabled,
                'memberOf': list(entry.memberOf) if entry.memberOf else []
            }

            conn.unbind()
            return render_template('user_form.html', user=user, action='edit', connected=is_connected())
        else:
            conn.unbind()
            flash('Utilisateur non trouvé.', 'error')
            return redirect(url_for('users'))

    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
        return redirect(url_for('users'))


@app.route('/users/<path:dn>/delete', methods=['POST'])
@require_connection
def delete_user(dn):
    """Supprimer un utilisateur."""
    conn, error = get_ad_connection()

    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('users'))

    try:
        conn.delete(dn)

        if conn.result['result'] == 0:
            flash('Utilisateur supprimé avec succès!', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')

        conn.unbind()
    except LDAPException as e:
        flash(f'Erreur LDAP: {str(e)}', 'error')

    return redirect(url_for('users'))


@app.route('/groups')
@require_connection
def groups():
    """Liste des groupes Active Directory."""
    conn, error = get_ad_connection()

    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')
    filter_type = request.args.get('filter', '')

    # Construire le filtre de recherche avec protection contre injection LDAP
    if search_query:
        safe_query = escape_ldap_filter(search_query)
        search_filter = f'(&(objectClass=group)(|(cn=*{safe_query}*)(description=*{safe_query}*)))'
    else:
        search_filter = '(objectClass=group)'

    try:
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[
                'cn', 'distinguishedName', 'description', 'member',
                'groupType', 'whenCreated', 'managedBy'
            ]
        )

        group_list = []
        for entry in conn.entries:
            members = list(entry.member) if entry.member else []
            group_type_val = int(entry.groupType.value) if entry.groupType and entry.groupType.value else 0

            # Determiner le type et l'etendue du groupe
            is_security = bool(group_type_val & 0x80000000)
            scope = 'global'
            if group_type_val & 0x00000004:
                scope = 'domain_local'
            elif group_type_val & 0x00000008:
                scope = 'universal'

            # Appliquer les filtres
            if filter_type == 'security' and not is_security:
                continue
            if filter_type == 'distribution' and is_security:
                continue
            if filter_type == 'empty' and len(members) > 0:
                continue
            if filter_type == 'with_members' and len(members) == 0:
                continue
            if filter_type == 'global' and scope != 'global':
                continue
            if filter_type == 'domain_local' and scope != 'domain_local':
                continue
            if filter_type == 'universal' and scope != 'universal':
                continue

            group_list.append({
                'cn': decode_ldap_value(entry.cn),
                'dn': decode_ldap_value(entry.distinguishedName),
                'description': decode_ldap_value(entry.description),
                'member_count': len(members),
                'groupType': str(entry.groupType) if entry.groupType else '',
                'is_security': is_security,
                'scope': scope
            })

        conn.unbind()
        return render_template('groups.html', groups=group_list, search=search_query, filter=filter_type, connected=is_connected())

    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur de recherche: {str(e)}', 'error')
        return render_template('groups.html', groups=[], search=search_query, filter=filter_type, connected=is_connected())


@app.route('/groups/<path:dn>')
@require_connection
def group_details(dn):
    """Détails d'un groupe et ses membres."""
    conn, error = get_ad_connection()

    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('groups'))

    try:
        # Récupérer les infos du groupe
        conn.search(
            search_base=dn,
            search_filter='(objectClass=group)',
            search_scope=SUBTREE,
            attributes=['cn', 'description', 'member', 'managedBy']
        )

        if conn.entries:
            entry = conn.entries[0]
            members_dn = list(entry.member) if entry.member else []

            # Récupérer les infos des membres
            members = []
            for member_dn in members_dn:
                conn.search(
                    search_base=str(member_dn),
                    search_filter='(objectClass=*)',
                    search_scope=SUBTREE,
                    attributes=['cn', 'sAMAccountName', 'objectClass']
                )

                if conn.entries:
                    m_entry = conn.entries[0]
                    obj_classes = list(m_entry.objectClass) if m_entry.objectClass else []

                    members.append({
                        'dn': str(member_dn),
                        'cn': str(m_entry.cn) if m_entry.cn else '',
                        'sAMAccountName': str(m_entry.sAMAccountName) if m_entry.sAMAccountName else '',
                        'type': 'user' if 'user' in obj_classes else 'group'
                    })

            group = {
                'dn': dn,
                'cn': str(entry.cn) if entry.cn else '',
                'description': str(entry.description) if entry.description else '',
                'members': members
            }

            conn.unbind()
            return render_template('group_details.html', group=group, connected=is_connected())
        else:
            conn.unbind()
            flash('Groupe non trouvé.', 'error')
            return redirect(url_for('groups'))

    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
        return redirect(url_for('groups'))


@app.route('/groups/create', methods=['GET', 'POST'])
@require_connection
def create_group():
    """Creer un nouveau groupe."""
    if request.method == 'POST':
        conn, error = get_ad_connection()
        if not conn:
            flash(f'Erreur de connexion: {error}', 'error')
            return redirect(url_for('connect'))

        name = request.form.get('name')
        description = request.form.get('description', '')
        group_scope = request.form.get('group_scope', 'global')
        group_type = request.form.get('group_type', 'security')
        ou = request.form.get('ou', '')

        base_dn = session.get('ad_base_dn', '')
        if ou:
            group_dn = f"CN={name},{ou}"
        else:
            group_dn = f"CN={name},CN=Users,{base_dn}"

        # Calculer groupType
        # Security: -2147483646 (global), -2147483644 (domain local), -2147483640 (universal)
        # Distribution: 2 (global), 4 (domain local), 8 (universal)
        scope_values = {'global': 2, 'domain_local': 4, 'universal': 8}
        scope_val = scope_values.get(group_scope, 2)
        if group_type == 'security':
            group_type_val = -2147483648 + scope_val
        else:
            group_type_val = scope_val

        group_attrs = {
            'objectClass': ['top', 'group'],
            'cn': name,
            'sAMAccountName': name,
            'groupType': group_type_val
        }
        if description:
            group_attrs['description'] = description

        try:
            conn.add(group_dn, attributes=group_attrs)
            if conn.result['result'] == 0:
                flash(f'Groupe {name} cree avec succes!', 'success')
                conn.unbind()
                return redirect(url_for('groups'))
            else:
                flash(f'Erreur: {conn.result["description"]}', 'error')
        except LDAPException as e:
            flash(f'Erreur LDAP: {str(e)}', 'error')
        conn.unbind()

    # GET: Recuperer les OUs
    conn, error = get_ad_connection()
    ous = []
    if conn:
        try:
            base_dn = session.get('ad_base_dn', '')
            conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['distinguishedName', 'name'])
            for entry in conn.entries:
                ous.append({'dn': str(entry.distinguishedName), 'name': str(entry.name)})
            conn.unbind()
        except:
            pass
    return render_template('group_form.html', group=None, ous=ous, action='create', connected=is_connected())


@app.route('/groups/<path:dn>/edit', methods=['GET', 'POST'])
@require_connection
def edit_group(dn):
    """Modifier un groupe existant."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('connect'))

    if request.method == 'POST':
        description = request.form.get('description', '')
        try:
            if description:
                conn.modify(dn, {'description': [(MODIFY_REPLACE, [description])]})
            else:
                conn.modify(dn, {'description': [(MODIFY_DELETE, [])]})
            if conn.result['result'] == 0:
                flash('Groupe modifie avec succes!', 'success')
            else:
                flash(f'Erreur: {conn.result["description"]}', 'error')
        except LDAPException as e:
            flash(f'Erreur LDAP: {str(e)}', 'error')
        conn.unbind()
        return redirect(url_for('groups'))

    # GET
    try:
        conn.search(dn, '(objectClass=group)', SUBTREE, attributes=['cn', 'description', 'groupType'])
        if conn.entries:
            entry = conn.entries[0]
            group = {
                'dn': dn,
                'cn': str(entry.cn) if entry.cn else '',
                'description': str(entry.description) if entry.description else ''
            }
            conn.unbind()
            return render_template('group_form.html', group=group, action='edit', connected=is_connected())
        conn.unbind()
        flash('Groupe non trouve.', 'error')
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
    return redirect(url_for('groups'))


@app.route('/groups/<path:dn>/duplicate', methods=['GET', 'POST'])
@require_connection
@require_permission('write')
def duplicate_group(dn):
    """Dupliquer un groupe existant."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('groups'))

    base_dn = session.get('ad_base_dn', '')

    # Recuperer le groupe source
    try:
        conn.search(base_dn, f'(distinguishedName={escape_ldap_filter(dn)})', SUBTREE,
                   attributes=['cn', 'description', 'groupType', 'member'])

        if not conn.entries:
            flash('Groupe non trouve.', 'error')
            conn.unbind()
            return redirect(url_for('groups'))

        source_group = conn.entries[0]
        source_cn = decode_ldap_value(source_group.cn)
        source_description = decode_ldap_value(source_group.description)
        source_group_type = int(source_group.groupType.value) if source_group.groupType else -2147483646
        source_members = source_group.member.values if hasattr(source_group.member, 'values') else []

        if request.method == 'POST':
            new_name = request.form.get('name')
            new_description = request.form.get('description', source_description)
            copy_members = request.form.get('copy_members') == 'on'
            ou = request.form.get('ou', '')

            if ou:
                new_dn = f"CN={new_name},{ou}"
            else:
                new_dn = f"CN={new_name},CN=Users,{base_dn}"

            group_attrs = {
                'objectClass': ['top', 'group'],
                'cn': new_name,
                'sAMAccountName': new_name,
                'groupType': source_group_type
            }
            if new_description:
                group_attrs['description'] = new_description

            try:
                conn.add(new_dn, attributes=group_attrs)
                if conn.result['result'] == 0:
                    # Copier les membres si demande
                    if copy_members and source_members:
                        for member_dn in source_members:
                            conn.modify(new_dn, {'member': [(MODIFY_ADD, [member_dn])]})

                    log_action('duplicate_group', session.get('ad_username'),
                              {'source': dn, 'new_name': new_name, 'copy_members': copy_members},
                              True, request.remote_addr)
                    flash(f'Groupe {new_name} cree avec succes!', 'success')
                    conn.unbind()
                    return redirect(url_for('groups'))
                else:
                    flash(f'Erreur: {conn.result["description"]}', 'error')
            except LDAPException as e:
                flash(f'Erreur LDAP: {str(e)}', 'error')

        # Recuperer les OUs pour le formulaire
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'distinguishedName'])
        ous = [{'name': decode_ldap_value(e.name), 'dn': decode_ldap_value(e.distinguishedName)} for e in conn.entries]

        conn.unbind()
        return render_template('group_form.html',
                             group={'cn': source_cn + '_copie', 'description': source_description},
                             ous=ous,
                             duplicate=True,
                             source_members_count=len(source_members),
                             connected=is_connected())
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
        return redirect(url_for('groups'))


@app.route('/groups/<path:dn>/delete', methods=['POST'])
@require_connection
def delete_group(dn):
    """Supprimer un groupe."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('groups'))
    try:
        conn.delete(dn)
        if conn.result['result'] == 0:
            flash('Groupe supprime avec succes!', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except LDAPException as e:
        flash(f'Erreur LDAP: {str(e)}', 'error')
    conn.unbind()
    return redirect(url_for('groups'))


@app.route('/groups/<path:dn>/add-member', methods=['POST'])
@require_connection
def add_group_member(dn):
    """Ajouter un membre au groupe."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('group_details', dn=dn))

    member_dn = request.form.get('member_dn')
    try:
        conn.modify(dn, {'member': [(MODIFY_ADD, [member_dn])]})
        if conn.result['result'] == 0:
            flash('Membre ajoute avec succes!', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except LDAPException as e:
        flash(f'Erreur LDAP: {str(e)}', 'error')
    conn.unbind()
    return redirect(url_for('group_details', dn=dn))


@app.route('/groups/<path:dn>/remove-member', methods=['POST'])
@require_connection
def remove_group_member(dn):
    """Retirer un membre du groupe."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('group_details', dn=dn))

    member_dn = request.form.get('member_dn')
    try:
        conn.modify(dn, {'member': [(MODIFY_DELETE, [member_dn])]})
        if conn.result['result'] == 0:
            flash('Membre retire avec succes!', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except LDAPException as e:
        flash(f'Erreur LDAP: {str(e)}', 'error')
    conn.unbind()
    return redirect(url_for('group_details', dn=dn))


# === OPERATIONS EN MASSE ===

@app.route('/users/export')
@require_connection
def export_users():
    """Exporter les utilisateurs en CSV."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('users'))

    base_dn = session.get('ad_base_dn', '')
    try:
        conn.search(base_dn, '(&(objectClass=user)(objectCategory=person))', SUBTREE,
                   attributes=['sAMAccountName', 'givenName', 'sn', 'displayName', 'mail', 'department', 'title', 'telephoneNumber'])

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['sAMAccountName', 'givenName', 'sn', 'displayName', 'mail', 'department', 'title', 'telephoneNumber'])

        for entry in conn.entries:
            writer.writerow([
                str(entry.sAMAccountName) if entry.sAMAccountName else '',
                str(entry.givenName) if entry.givenName else '',
                str(entry.sn) if entry.sn else '',
                str(entry.displayName) if entry.displayName else '',
                str(entry.mail) if entry.mail else '',
                str(entry.department) if entry.department else '',
                str(entry.title) if entry.title else '',
                str(entry.telephoneNumber) if entry.telephoneNumber else ''
            ])

        conn.unbind()
        output.seek(0)
        return Response(output.getvalue(), mimetype='text/csv',
                       headers={'Content-Disposition': 'attachment; filename=utilisateurs.csv'})
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
        return redirect(url_for('users'))


@app.route('/users/export/excel')
@require_connection
def export_users_excel():
    """Exporter les utilisateurs en Excel (.xlsx)."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill
    except ImportError:
        flash('Module openpyxl non installe. Executez: pip install openpyxl', 'error')
        return redirect(url_for('users'))

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('users'))

    base_dn = session.get('ad_base_dn', '')
    try:
        conn.search(base_dn, '(&(objectClass=user)(objectCategory=person))', SUBTREE,
                   attributes=['sAMAccountName', 'givenName', 'sn', 'displayName', 'mail', 'department', 'title', 'telephoneNumber'])

        wb = Workbook()
        ws = wb.active
        ws.title = "Utilisateurs"

        # En-tetes avec style
        headers = ['Identifiant', 'Prenom', 'Nom', 'Nom affiche', 'Email', 'Service', 'Fonction', 'Telephone']
        header_font = Font(bold=True, color='FFFFFF')
        header_fill = PatternFill(start_color='0078D4', end_color='0078D4', fill_type='solid')

        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = header_font
            cell.fill = header_fill

        # Donnees
        for row, entry in enumerate(conn.entries, 2):
            ws.cell(row=row, column=1, value=decode_ldap_value(entry.sAMAccountName))
            ws.cell(row=row, column=2, value=decode_ldap_value(entry.givenName))
            ws.cell(row=row, column=3, value=decode_ldap_value(entry.sn))
            ws.cell(row=row, column=4, value=decode_ldap_value(entry.displayName))
            ws.cell(row=row, column=5, value=decode_ldap_value(entry.mail))
            ws.cell(row=row, column=6, value=decode_ldap_value(entry.department))
            ws.cell(row=row, column=7, value=decode_ldap_value(entry.title))
            ws.cell(row=row, column=8, value=decode_ldap_value(entry.telephoneNumber))

        # Ajuster largeur colonnes
        for col in ws.columns:
            max_length = max(len(str(cell.value or '')) for cell in col)
            ws.column_dimensions[col[0].column_letter].width = min(max_length + 2, 50)

        conn.unbind()

        # Sauvegarder en memoire
        output = io.BytesIO()
        wb.save(output)
        output.seek(0)

        return Response(output.getvalue(),
                       mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                       headers={'Content-Disposition': 'attachment; filename=utilisateurs.xlsx'})
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
        return redirect(url_for('users'))


@app.route('/users/<path:dn>/move', methods=['POST'])
@require_connection
@require_permission('write')
def move_user(dn):
    """Deplacer un utilisateur vers une autre OU."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        flash('Token CSRF invalide.', 'error')
        return redirect(url_for('users'))

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('users'))

    new_ou = request.form.get('new_ou')
    if not new_ou:
        flash('Aucune OU de destination selectionnee.', 'error')
        return redirect(url_for('users'))

    # Extraire le CN de l'utilisateur
    cn = dn.split(',')[0]

    try:
        conn.modify_dn(dn, cn, new_superior=new_ou)
        if conn.result['result'] == 0:
            log_action('move_user', session.get('ad_username'),
                      {'dn': dn, 'new_ou': new_ou}, True, request.remote_addr)
            flash('Utilisateur deplace avec succes!', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except LDAPException as e:
        flash(f'Erreur LDAP: {str(e)}', 'error')

    conn.unbind()
    return redirect(url_for('users'))


@app.route('/users/import', methods=['GET', 'POST'])
@require_connection
def import_users():
    """Importer des utilisateurs depuis un CSV."""
    if request.method == 'POST':
        conn, error = get_ad_connection()
        if not conn:
            flash(f'Erreur de connexion: {error}', 'error')
            return redirect(url_for('connect'))

        file = request.files.get('csv_file')
        if not file:
            flash('Aucun fichier selectionne.', 'error')
            return redirect(url_for('import_users'))

        default_password = request.form.get('default_password', 'P@ssw0rd123!')
        ou = request.form.get('ou', '')
        base_dn = session.get('ad_base_dn', '')

        try:
            content = file.read().decode('utf-8')
            reader = csv.DictReader(io.StringIO(content))

            created = 0
            errors = []

            for row in reader:
                username = row.get('sAMAccountName', '').strip()
                if not username:
                    continue

                first_name = row.get('givenName', '').strip()
                last_name = row.get('sn', '').strip()
                display_name = row.get('displayName', '').strip() or f"{first_name} {last_name}"

                if ou:
                    user_dn = f"CN={display_name},{ou}"
                else:
                    user_dn = f"CN={display_name},CN=Users,{base_dn}"

                user_attrs = {
                    'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
                    'cn': display_name,
                    'sAMAccountName': username,
                    'userPrincipalName': f"{username}@{session.get('ad_server', '')}",
                    'givenName': first_name,
                    'sn': last_name,
                    'displayName': display_name
                }

                for field in ['mail', 'department', 'title', 'telephoneNumber']:
                    if row.get(field):
                        user_attrs[field] = row[field].strip()

                try:
                    conn.add(user_dn, attributes=user_attrs)
                    if conn.result['result'] == 0:
                        # Definir mot de passe et activer
                        unicode_pwd = f'"{default_password}"'.encode('utf-16-le')
                        conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})
                        conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})
                        created += 1
                    else:
                        errors.append(f"{username}: {conn.result['description']}")
                except Exception as e:
                    errors.append(f"{username}: {str(e)}")

            conn.unbind()
            flash(f'{created} utilisateur(s) cree(s) avec succes!', 'success')
            if errors:
                flash(f'Erreurs: {"; ".join(errors[:5])}', 'error')
            return redirect(url_for('users'))

        except Exception as e:
            conn.unbind()
            flash(f'Erreur: {str(e)}', 'error')
            return redirect(url_for('import_users'))

    # GET: Recuperer les OUs
    conn, error = get_ad_connection()
    ous = []
    if conn:
        try:
            base_dn = session.get('ad_base_dn', '')
            conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['distinguishedName', 'name'])
            for entry in conn.entries:
                ous.append({'dn': str(entry.distinguishedName), 'name': str(entry.name)})
            conn.unbind()
        except:
            pass
    return render_template('import_users.html', ous=ous, connected=is_connected())


@app.route('/users/bulk', methods=['GET', 'POST'])
@require_connection
def bulk_operations():
    """Operations en masse sur les utilisateurs."""
    if request.method == 'POST':
        conn, error = get_ad_connection()
        if not conn:
            flash(f'Erreur de connexion: {error}', 'error')
            return redirect(url_for('connect'))

        action = request.form.get('action')
        user_dns = request.form.getlist('user_dns')
        new_password = request.form.get('new_password', '')

        if not user_dns:
            flash('Aucun utilisateur selectionne.', 'error')
            return redirect(url_for('bulk_operations'))

        success = 0
        for user_dn in user_dns:
            try:
                if action == 'enable':
                    conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})
                elif action == 'disable':
                    conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [514])]})
                elif action == 'reset_password' and new_password:
                    unicode_pwd = f'"{new_password}"'.encode('utf-16-le')
                    conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})
                elif action == 'delete':
                    conn.delete(user_dn)

                if conn.result['result'] == 0:
                    success += 1
            except:
                pass

        conn.unbind()
        flash(f'Operation effectuee sur {success}/{len(user_dns)} utilisateur(s).', 'success')
        return redirect(url_for('users'))

    # GET: Liste des utilisateurs
    conn, error = get_ad_connection()
    users = []
    if conn:
        try:
            base_dn = session.get('ad_base_dn', '')
            conn.search(base_dn, '(&(objectClass=user)(objectCategory=person))', SUBTREE,
                       attributes=['cn', 'sAMAccountName', 'distinguishedName', 'userAccountControl'])
            for entry in conn.entries:
                uac = entry.userAccountControl.value if entry.userAccountControl else 512
                users.append({
                    'cn': str(entry.cn) if entry.cn else '',
                    'sAMAccountName': str(entry.sAMAccountName) if entry.sAMAccountName else '',
                    'dn': str(entry.distinguishedName) if entry.distinguishedName else '',
                    'disabled': bool(int(uac) & 2) if uac else False
                })
            conn.unbind()
        except:
            pass
    return render_template('bulk_operations.html', users=users, connected=is_connected())


# === GESTION DES OUs ===

@app.route('/ous')
@require_connection
def ous():
    """Liste des unites organisationnelles."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    try:
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'distinguishedName', 'description', 'whenCreated'])

        ou_list = []
        for entry in conn.entries:
            ou_list.append({
                'name': str(entry.name) if entry.name else '',
                'dn': str(entry.distinguishedName) if entry.distinguishedName else '',
                'description': str(entry.description) if entry.description else ''
            })

        conn.unbind()
        return render_template('ous.html', ous=ou_list, connected=is_connected())
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
        return render_template('ous.html', ous=[], connected=is_connected())


@app.route('/ous/create', methods=['GET', 'POST'])
@require_connection
def create_ou():
    """Creer une nouvelle OU."""
    if request.method == 'POST':
        conn, error = get_ad_connection()
        if not conn:
            flash(f'Erreur de connexion: {error}', 'error')
            return redirect(url_for('connect'))

        name = request.form.get('name')
        description = request.form.get('description', '')
        parent_ou = request.form.get('parent_ou', '')
        base_dn = session.get('ad_base_dn', '')

        if parent_ou:
            ou_dn = f"OU={name},{parent_ou}"
        else:
            ou_dn = f"OU={name},{base_dn}"

        ou_attrs = {
            'objectClass': ['top', 'organizationalUnit'],
            'ou': name
        }
        if description:
            ou_attrs['description'] = description

        try:
            conn.add(ou_dn, attributes=ou_attrs)
            if conn.result['result'] == 0:
                flash(f'OU {name} creee avec succes!', 'success')
                conn.unbind()
                return redirect(url_for('ous'))
            else:
                flash(f'Erreur: {conn.result["description"]}', 'error')
        except LDAPException as e:
            flash(f'Erreur LDAP: {str(e)}', 'error')
        conn.unbind()

    # GET
    conn, error = get_ad_connection()
    parent_ous = []
    if conn:
        try:
            base_dn = session.get('ad_base_dn', '')
            conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['distinguishedName', 'name'])
            for entry in conn.entries:
                parent_ous.append({'dn': str(entry.distinguishedName), 'name': str(entry.name)})
            conn.unbind()
        except:
            pass
    return render_template('ou_form.html', ou=None, parent_ous=parent_ous, action='create', connected=is_connected())


@app.route('/ous/<path:dn>/edit', methods=['GET', 'POST'])
@require_connection
def edit_ou(dn):
    """Modifier une OU."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('connect'))

    if request.method == 'POST':
        description = request.form.get('description', '')
        try:
            if description:
                conn.modify(dn, {'description': [(MODIFY_REPLACE, [description])]})
            else:
                conn.modify(dn, {'description': [(MODIFY_DELETE, [])]})
            if conn.result['result'] == 0:
                flash('OU modifiee avec succes!', 'success')
            else:
                flash(f'Erreur: {conn.result["description"]}', 'error')
        except LDAPException as e:
            flash(f'Erreur LDAP: {str(e)}', 'error')
        conn.unbind()
        return redirect(url_for('ous'))

    # GET
    try:
        conn.search(dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['name', 'description'])
        if conn.entries:
            entry = conn.entries[0]
            ou = {
                'dn': dn,
                'name': str(entry.name) if entry.name else '',
                'description': str(entry.description) if entry.description else ''
            }
            conn.unbind()
            return render_template('ou_form.html', ou=ou, action='edit', connected=is_connected())
        conn.unbind()
        flash('OU non trouvee.', 'error')
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
    return redirect(url_for('ous'))


@app.route('/ous/<path:dn>/delete', methods=['POST'])
@require_connection
def delete_ou(dn):
    """Supprimer une OU."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('ous'))
    try:
        conn.delete(dn)
        if conn.result['result'] == 0:
            flash('OU supprimee avec succes!', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except LDAPException as e:
        flash(f'Erreur LDAP: {str(e)}', 'error')
    conn.unbind()
    return redirect(url_for('ous'))


@app.route('/users/<path:dn>/move', methods=['POST'])
@require_connection
def move_user(dn):
    """Deplacer un utilisateur vers une autre OU."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('users'))

    new_ou = request.form.get('new_ou')
    if not new_ou:
        flash('Aucune OU de destination selectionnee.', 'error')
        return redirect(url_for('users'))

    # Extraire le CN de l'utilisateur
    cn = dn.split(',')[0]

    try:
        conn.modify_dn(dn, cn, new_superior=new_ou)
        if conn.result['result'] == 0:
            flash('Utilisateur deplace avec succes!', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except LDAPException as e:
        flash(f'Erreur LDAP: {str(e)}', 'error')
    conn.unbind()
    return redirect(url_for('users'))


@app.route('/tree')
@require_connection
def ad_tree():
    """Afficher l'arborescence Active Directory."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')

    def build_tree(base, conn):
        tree = {'name': base.split(',')[0], 'dn': base, 'children': [], 'type': 'container'}

        # Chercher les OUs
        try:
            conn.search(base, '(objectClass=organizationalUnit)', SUBTREE,
                       attributes=['distinguishedName', 'name'])
            for entry in conn.entries:
                entry_dn = str(entry.distinguishedName)
                if entry_dn != base:
                    # Verifier si c'est un enfant direct
                    parent = ','.join(entry_dn.split(',')[1:])
                    if parent == base:
                        child = {
                            'name': str(entry.name),
                            'dn': entry_dn,
                            'type': 'ou',
                            'children': []
                        }
                        tree['children'].append(child)
        except:
            pass

        return tree

    tree = build_tree(base_dn, conn)
    conn.unbind()

    return render_template('tree.html', tree=tree, connected=is_connected())


@app.route('/audit')
@require_connection
def audit_logs():
    """Afficher les logs d'audit."""
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    logs = get_audit_logs(limit=100, action_filter=action_filter, user_filter=user_filter)
    return render_template('audit.html', logs=logs, action_filter=action_filter,
                         user_filter=user_filter, connected=is_connected())


# === GESTION DES ORDINATEURS ===

@app.route('/computers')
@require_connection
def computers():
    """Liste des ordinateurs Active Directory."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')

    # Protection contre injection LDAP
    if search_query:
        safe_query = escape_ldap_filter(search_query)
        search_filter = f'(&(objectClass=computer)(cn=*{safe_query}*))'
    else:
        search_filter = '(objectClass=computer)'

    try:
        conn.search(base_dn, search_filter, SUBTREE,
                   attributes=['cn', 'distinguishedName', 'operatingSystem', 'operatingSystemVersion',
                             'lastLogonTimestamp', 'userAccountControl', 'description', 'dNSHostName'])

        computer_list = []
        for entry in conn.entries:
            uac = entry.userAccountControl.value if entry.userAccountControl else 4096
            is_disabled = bool(int(uac) & 2) if uac else False

            computer_list.append({
                'cn': decode_ldap_value(entry.cn),
                'dn': decode_ldap_value(entry.distinguishedName),
                'os': decode_ldap_value(entry.operatingSystem),
                'os_version': decode_ldap_value(entry.operatingSystemVersion),
                'dns_name': decode_ldap_value(entry.dNSHostName),
                'description': decode_ldap_value(entry.description),
                'disabled': is_disabled
            })

        # Recuperer les OUs pour le deplacement
        ous = []
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['distinguishedName', 'name'])
        for entry in conn.entries:
            ous.append({'dn': decode_ldap_value(entry.distinguishedName), 'name': decode_ldap_value(entry.name)})

        conn.unbind()
        return render_template('computers.html', computers=computer_list, ous=ous, search=search_query, connected=is_connected())
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
        return render_template('computers.html', computers=[], ous=[], search=search_query, connected=is_connected())


@app.route('/computers/<path:dn>/toggle', methods=['POST'])
@require_connection
def toggle_computer(dn):
    """Activer/desactiver un ordinateur."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('computers'))

    action = request.form.get('action', 'disable')
    try:
        if action == 'enable':
            conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [4096])]})
        else:
            conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [4098])]})

        if conn.result['result'] == 0:
            flash(f'Ordinateur {"active" if action == "enable" else "desactive"} avec succes!', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except LDAPException as e:
        flash(f'Erreur LDAP: {str(e)}', 'error')

    conn.unbind()
    return redirect(url_for('computers'))


@app.route('/computers/<path:dn>/delete', methods=['POST'])
@require_connection
def delete_computer(dn):
    """Supprimer un ordinateur."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('computers'))

    try:
        conn.delete(dn)
        if conn.result['result'] == 0:
            flash('Ordinateur supprime avec succes!', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except LDAPException as e:
        flash(f'Erreur LDAP: {str(e)}', 'error')

    conn.unbind()
    return redirect(url_for('computers'))


@app.route('/computers/<path:dn>/move', methods=['POST'])
@require_connection
def move_computer(dn):
    """Deplacer un ordinateur vers une autre OU."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('computers'))

    new_ou = request.form.get('new_ou')
    if not new_ou:
        flash('Aucune OU de destination selectionnee.', 'error')
        return redirect(url_for('computers'))

    # Extraire le CN de l'ordinateur
    cn = dn.split(',')[0]

    try:
        conn.modify_dn(dn, cn, new_superior=new_ou)
        if conn.result['result'] == 0:
            log_action('move_computer', session.get('ad_username'),
                      {'dn': dn, 'new_ou': new_ou}, True, request.remote_addr)
            flash('Ordinateur deplace avec succes!', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except LDAPException as e:
        flash(f'Erreur LDAP: {str(e)}', 'error')

    conn.unbind()
    return redirect(url_for('computers'))


# === COMPTES VERROUILLES ===

@app.route('/locked-accounts')
@require_connection
def locked_accounts():
    """Liste des comptes verrouilles."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')

    try:
        # Rechercher les comptes avec lockoutTime > 0
        conn.search(base_dn, '(&(objectClass=user)(objectCategory=person)(lockoutTime>=1))', SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'distinguishedName', 'lockoutTime', 'mail'])

        locked_list = []
        for entry in conn.entries:
            locked_list.append({
                'cn': str(entry.cn) if entry.cn else '',
                'sAMAccountName': str(entry.sAMAccountName) if entry.sAMAccountName else '',
                'dn': str(entry.distinguishedName) if entry.distinguishedName else '',
                'mail': str(entry.mail) if entry.mail else '',
                'lockoutTime': str(entry.lockoutTime) if entry.lockoutTime else ''
            })

        conn.unbind()
        return render_template('locked_accounts.html', accounts=locked_list, connected=is_connected())
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
        return render_template('locked_accounts.html', accounts=[], connected=is_connected())


@app.route('/locked-accounts/<path:dn>/unlock', methods=['POST'])
@require_connection
def unlock_account(dn):
    """Deverrouiller un compte."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('locked_accounts'))

    try:
        conn.modify(dn, {'lockoutTime': [(MODIFY_REPLACE, [0])]})
        if conn.result['result'] == 0:
            log_action('unlock_account', session.get('ad_username'), {'dn': dn}, True, request.remote_addr)
            flash('Compte deverrouille avec succes!', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except LDAPException as e:
        flash(f'Erreur LDAP: {str(e)}', 'error')

    conn.unbind()
    return redirect(url_for('locked_accounts'))


# === POLITIQUE DE MOTS DE PASSE ===

@app.route('/password-policy')
@require_connection
def password_policy():
    """Afficher la politique de mots de passe du domaine."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    policy = {}

    try:
        # Rechercher la politique dans le domaine
        conn.search(base_dn, '(objectClass=domain)', SUBTREE,
                   attributes=['minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'minPwdAge',
                             'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow',
                             'pwdProperties'])

        if conn.entries:
            entry = conn.entries[0]
            policy = {
                'min_length': str(entry.minPwdLength) if entry.minPwdLength else 'Non defini',
                'history_length': str(entry.pwdHistoryLength) if entry.pwdHistoryLength else 'Non defini',
                'max_age': str(entry.maxPwdAge) if entry.maxPwdAge else 'Non defini',
                'min_age': str(entry.minPwdAge) if entry.minPwdAge else 'Non defini',
                'lockout_threshold': str(entry.lockoutThreshold) if entry.lockoutThreshold else 'Non defini',
                'lockout_duration': str(entry.lockoutDuration) if entry.lockoutDuration else 'Non defini',
                'lockout_window': str(entry.lockOutObservationWindow) if entry.lockOutObservationWindow else 'Non defini',
                'complexity': 'Oui' if entry.pwdProperties and int(str(entry.pwdProperties)) & 1 else 'Non'
            }

        conn.unbind()
        return render_template('password_policy.html', policy=policy, connected=is_connected())
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')
        return render_template('password_policy.html', policy={}, connected=is_connected())


# === DUPLICATION D'UTILISATEUR ===

@app.route('/users/<path:dn>/duplicate', methods=['GET', 'POST'])
@require_connection
def duplicate_user(dn):
    """Dupliquer un utilisateur existant."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('users'))

    if request.method == 'POST':
        # Creer le nouvel utilisateur
        username = request.form.get('sAMAccountName')
        first_name = request.form.get('givenName')
        last_name = request.form.get('sn')
        display_name = request.form.get('displayName') or f"{first_name} {last_name}"
        email = request.form.get('mail')
        password = request.form.get('password')
        ou = request.form.get('ou', '')

        base_dn = session.get('ad_base_dn', '')
        if ou:
            user_dn = f"CN={display_name},{ou}"
        else:
            user_dn = f"CN={display_name},CN=Users,{base_dn}"

        user_attrs = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'cn': display_name,
            'sAMAccountName': username,
            'userPrincipalName': f"{username}@{session.get('ad_server', '')}",
            'givenName': first_name,
            'sn': last_name,
            'displayName': display_name
        }

        # Copier les attributs supplementaires
        for field in ['department', 'title', 'telephoneNumber', 'description']:
            if request.form.get(field):
                user_attrs[field] = request.form.get(field)

        if email:
            user_attrs['mail'] = email

        try:
            conn.add(user_dn, attributes=user_attrs)
            if conn.result['result'] == 0:
                if password:
                    unicode_pwd = f'"{password}"'.encode('utf-16-le')
                    conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})
                    conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})

                # Copier les groupes si demande
                if request.form.get('copy_groups'):
                    conn.search(dn, '(objectClass=user)', SUBTREE, attributes=['memberOf'])
                    if conn.entries and conn.entries[0].memberOf:
                        for group_dn in conn.entries[0].memberOf:
                            conn.modify(str(group_dn), {'member': [(MODIFY_ADD, [user_dn])]})

                log_action(ACTIONS['CREATE_USER'], session.get('ad_username'),
                          {'username': username, 'duplicated_from': dn}, True, request.remote_addr)
                flash(f'Utilisateur {username} cree avec succes (copie de {dn.split(",")[0]})!', 'success')
                conn.unbind()
                return redirect(url_for('users'))
            else:
                flash(f'Erreur: {conn.result["description"]}', 'error')
        except LDAPException as e:
            flash(f'Erreur LDAP: {str(e)}', 'error')

        conn.unbind()

    # GET: Recuperer les infos de l'utilisateur source
    try:
        conn.search(dn, '(objectClass=user)', SUBTREE,
                   attributes=['cn', 'givenName', 'sn', 'displayName', 'mail', 'department',
                             'title', 'telephoneNumber', 'description', 'memberOf'])

        if conn.entries:
            entry = conn.entries[0]
            source_user = {
                'dn': dn,
                'givenName': str(entry.givenName) if entry.givenName else '',
                'sn': str(entry.sn) if entry.sn else '',
                'displayName': str(entry.displayName) if entry.displayName else '',
                'mail': str(entry.mail) if entry.mail else '',
                'department': str(entry.department) if entry.department else '',
                'title': str(entry.title) if entry.title else '',
                'telephoneNumber': str(entry.telephoneNumber) if entry.telephoneNumber else '',
                'description': str(entry.description) if entry.description else '',
                'memberOf': list(entry.memberOf) if entry.memberOf else []
            }

            # Recuperer les OUs
            ous = []
            conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE, attributes=['distinguishedName', 'name'])
            for ou_entry in conn.entries:
                ous.append({'dn': str(ou_entry.distinguishedName), 'name': str(ou_entry.name)})

            conn.unbind()
            return render_template('duplicate_user.html', user=source_user, ous=ous, connected=is_connected())

        conn.unbind()
        flash('Utilisateur non trouve.', 'error')
    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur: {str(e)}', 'error')

    return redirect(url_for('users'))


# === HISTORIQUE DES CHANGEMENTS ===

@app.route('/history')
@require_connection
def change_history():
    """Afficher l'historique des changements."""
    history = get_all_history(limit=100)
    return render_template('history.html', history=history, connected=is_connected())


@app.route('/backups')
@require_connection
def backups():
    """Afficher les backups disponibles."""
    backup_list = get_backups(limit=100)
    return render_template('backups.html', backups=backup_list, connected=is_connected())


@app.route('/backups/<filename>')
@require_connection
def view_backup(filename):
    """Voir le contenu d'un backup."""
    content = get_backup_content(filename)
    if content:
        return render_template('backup_detail.html', backup=content, filename=filename, connected=is_connected())
    flash('Backup non trouve.', 'error')
    return redirect(url_for('backups'))


@app.route('/api/users/search')
@require_connection
def api_users_search():
    """API pour recherche AJAX des utilisateurs."""
    conn, error = get_ad_connection()
    if not conn:
        return jsonify({'success': False, 'error': error})

    base_dn = session.get('ad_base_dn', '')
    query = request.args.get('q', '')

    # Protection contre injection LDAP
    if query:
        safe_query = escape_ldap_filter(query)
        search_filter = f'(&(objectClass=user)(objectCategory=person)(|(cn=*{safe_query}*)(sAMAccountName=*{safe_query}*)(mail=*{safe_query}*)))'
    else:
        search_filter = '(&(objectClass=user)(objectCategory=person))'

    try:
        conn.search(base_dn, search_filter, SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'mail', 'distinguishedName', 'userAccountControl'])

        users = []
        for entry in conn.entries:
            uac = entry.userAccountControl.value if entry.userAccountControl else 512
            users.append({
                'cn': str(entry.cn) if entry.cn else '',
                'sAMAccountName': str(entry.sAMAccountName) if entry.sAMAccountName else '',
                'mail': str(entry.mail) if entry.mail else '',
                'dn': str(entry.distinguishedName) if entry.distinguishedName else '',
                'disabled': bool(int(uac) & 2) if uac else False
            })

        conn.unbind()
        return jsonify({'success': True, 'users': users[:50]})  # Limiter a 50 resultats
    except Exception as e:
        conn.unbind()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/groups/search')
@require_connection
def api_groups_search():
    """API pour recherche AJAX des groupes."""
    conn, error = get_ad_connection()
    if not conn:
        return jsonify({'success': False, 'error': error})

    base_dn = session.get('ad_base_dn', '')
    query = request.args.get('q', '')

    # Protection contre injection LDAP
    if query:
        safe_query = escape_ldap_filter(query)
        search_filter = f'(&(objectClass=group)(cn=*{safe_query}*))'
    else:
        search_filter = '(objectClass=group)'

    try:
        conn.search(base_dn, search_filter, SUBTREE,
                   attributes=['cn', 'distinguishedName', 'description'])

        groups = []
        for entry in conn.entries:
            groups.append({
                'cn': str(entry.cn) if entry.cn else '',
                'dn': str(entry.distinguishedName) if entry.distinguishedName else '',
                'description': str(entry.description) if entry.description else ''
            })

        conn.unbind()
        return jsonify({'success': True, 'groups': groups[:50]})
    except Exception as e:
        conn.unbind()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/users/<path:dn>/add-to-group', methods=['POST'])
@require_connection
def add_user_to_group(dn):
    """Ajouter un utilisateur a un groupe."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('edit_user', dn=dn))

    group_dn = request.form.get('group_dn')
    if not group_dn:
        flash('Aucun groupe selectionne.', 'error')
        return redirect(url_for('edit_user', dn=dn))

    try:
        conn.modify(group_dn, {'member': [(MODIFY_ADD, [dn])]})
        if conn.result['result'] == 0:
            log_action(ACTIONS['ADD_MEMBER'], session.get('ad_username'),
                      {'user_dn': dn, 'group_dn': group_dn}, True, request.remote_addr)
            flash('Utilisateur ajoute au groupe avec succes!', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except LDAPException as e:
        flash(f'Erreur LDAP: {str(e)}', 'error')

    conn.unbind()
    return redirect(url_for('edit_user', dn=dn))


@app.route('/users/<path:dn>/remove-from-group', methods=['POST'])
@require_connection
def remove_user_from_group(dn):
    """Retirer un utilisateur d'un groupe."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('edit_user', dn=dn))

    group_dn = request.form.get('group_dn')
    if not group_dn:
        flash('Aucun groupe selectionne.', 'error')
        return redirect(url_for('edit_user', dn=dn))

    try:
        conn.modify(group_dn, {'member': [(MODIFY_DELETE, [dn])]})
        if conn.result['result'] == 0:
            log_action(ACTIONS['REMOVE_MEMBER'], session.get('ad_username'),
                      {'user_dn': dn, 'group_dn': group_dn}, True, request.remote_addr)
            flash('Utilisateur retire du groupe avec succes!', 'success')
        else:
            flash(f'Erreur: {conn.result["description"]}', 'error')
    except LDAPException as e:
        flash(f'Erreur LDAP: {str(e)}', 'error')

    conn.unbind()
    return redirect(url_for('edit_user', dn=dn))


@app.route('/api/search', methods=['POST'])
def api_search():
    """
    Point d'accès API pour rechercher dans Active Directory.
    Compatible multi-plateforme.
    """
    data = request.get_json()

    server = data.get('server')
    username = data.get('username')
    password = data.get('password')
    base_dn = data.get('base_dn')
    search_filter = data.get('filter', '(objectClass=*)')
    attributes = data.get('attributes', ['cn', 'distinguishedName'])

    conn, error = get_ad_connection(server, username, password)

    if not conn:
        return jsonify({'success': False, 'error': error}), 400

    try:
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes
        )

        results = []
        for entry in conn.entries:
            results.append(entry.entry_to_json())

        conn.unbind()
        return jsonify({'success': True, 'results': results})

    except LDAPException as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/system-info')
def api_system_info():
    """Retourner les informations système pour le débogage."""
    return jsonify({
        'os': CURRENT_OS,
        'is_windows': IS_WINDOWS,
        'hostname': platform.node(),
        'python_version': platform.python_version(),
        'platform': platform.platform()
    })


@app.route('/health')
def health():
    """Point de vérification de santé."""
    return jsonify({'status': 'ok', 'platform': CURRENT_OS})


@app.route('/update')
def update_page():
    """Page de mise à jour."""
    from updater import check_for_updates, get_current_version

    update_info = check_for_updates()
    return render_template('update.html',
                         update_info=update_info,
                         connected=is_connected())


@app.route('/api/check-update')
def api_check_update():
    """API pour vérifier les mises à jour."""
    from updater import check_for_updates
    return jsonify(check_for_updates())


@app.route('/api/perform-update', methods=['POST'])
def api_perform_update():
    """API pour effectuer une mise à jour."""
    import threading
    from updater import download_update, apply_update, update_dependencies, check_for_updates, restart_server

    try:
        # Vérifier qu'une mise à jour est disponible
        info = check_for_updates()
        if not info['update_available']:
            return jsonify({
                'success': False,
                'message': 'Aucune mise à jour disponible'
            })

        # Télécharger et appliquer
        zip_path, temp_dir = download_update()
        if apply_update(zip_path, temp_dir):
            update_dependencies()

            # Redémarrer le serveur après un délai
            def delayed_restart():
                import time
                time.sleep(2)
                restart_server()
                os._exit(0)

            threading.Thread(target=delayed_restart, daemon=True).start()

            return jsonify({
                'success': True,
                'message': f'Mise à jour vers la version {info["latest_version"]} réussie. Le serveur redémarre...',
                'restarting': True
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Erreur lors de l\'application de la mise à jour'
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        })


# === NOUVELLES FONCTIONNALITES VERSION 1.6 ===

@app.route('/search')
@require_connection
def global_search():
    """Recherche globale dans tous les objets AD."""
    query = request.args.get('q', '')
    types = request.args.getlist('type') or ['users', 'groups', 'computers', 'ous']

    results = {'users': [], 'groups': [], 'computers': [], 'ous': []}
    total = 0

    if query:
        conn, error = get_ad_connection()
        if conn:
            base_dn = session.get('ad_base_dn', '')
            safe_query = escape_ldap_filter(query)

            if 'users' in types:
                conn.search(base_dn, f'(&(objectClass=user)(objectCategory=person)(|(cn=*{safe_query}*)(sAMAccountName=*{safe_query}*)))',
                           SUBTREE, attributes=['cn', 'sAMAccountName', 'mail', 'distinguishedName'])
                results['users'] = [{'cn': decode_ldap_value(e.cn), 'sAMAccountName': decode_ldap_value(e.sAMAccountName),
                                    'mail': decode_ldap_value(e.mail), 'dn': decode_ldap_value(e.distinguishedName)} for e in conn.entries]

            if 'groups' in types:
                conn.search(base_dn, f'(&(objectClass=group)(cn=*{safe_query}*))',
                           SUBTREE, attributes=['cn', 'description', 'distinguishedName'])
                results['groups'] = [{'cn': decode_ldap_value(e.cn), 'description': decode_ldap_value(e.description),
                                     'dn': decode_ldap_value(e.distinguishedName)} for e in conn.entries]

            if 'computers' in types:
                conn.search(base_dn, f'(&(objectClass=computer)(cn=*{safe_query}*))',
                           SUBTREE, attributes=['cn', 'operatingSystem', 'distinguishedName'])
                results['computers'] = [{'cn': decode_ldap_value(e.cn), 'os': decode_ldap_value(e.operatingSystem),
                                        'dn': decode_ldap_value(e.distinguishedName)} for e in conn.entries]

            if 'ous' in types:
                conn.search(base_dn, f'(&(objectClass=organizationalUnit)(name=*{safe_query}*))',
                           SUBTREE, attributes=['name', 'description', 'distinguishedName'])
                results['ous'] = [{'name': decode_ldap_value(e.name), 'description': decode_ldap_value(e.description),
                                  'dn': decode_ldap_value(e.distinguishedName)} for e in conn.entries]

            conn.unbind()
            total = sum(len(v) for v in results.values())

    return render_template('global_search.html', query=query, types=types, results=results,
                          total_results=total, connected=is_connected())


@app.route('/alerts')
@require_connection
def alerts_page():
    """Page des alertes."""
    severity_filter = request.args.get('severity', '')
    ack_filter = request.args.get('acknowledged', '')

    acknowledged = None
    if ack_filter == 'yes':
        acknowledged = True
    elif ack_filter == 'no':
        acknowledged = False

    alerts = get_alerts(limit=100, severity=severity_filter if severity_filter else None, acknowledged=acknowledged)

    return render_template('alerts_page.html', alerts=alerts, alert_counts=get_alert_counts(),
                          severity_filter=severity_filter, ack_filter=ack_filter, connected=is_connected())


@app.route('/alerts/<alert_id>/acknowledge', methods=['POST'])
@require_connection
def acknowledge_alert_route(alert_id):
    """Acquitter une alerte."""
    acknowledge_alert(alert_id, session.get('ad_username', 'unknown'))
    flash('Alerte acquittee.', 'success')
    return redirect(url_for('alerts_page'))


@app.route('/alerts/<alert_id>/delete', methods=['POST'])
@require_connection
def delete_alert_route(alert_id):
    """Supprimer une alerte."""
    delete_alert_func(alert_id)
    flash('Alerte supprimee.', 'success')
    return redirect(url_for('alerts_page'))


@app.route('/templates')
@require_connection
def user_templates_page():
    """Page des modeles d'utilisateurs."""
    init_default_templates()
    templates = get_all_templates()
    return render_template('user_templates.html', templates=templates, connected=is_connected())


@app.route('/templates/create', methods=['GET', 'POST'])
@require_connection
def create_user_template():
    """Creer un modele d'utilisateur."""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description', '')
        attributes = {
            'department': request.form.get('department', ''),
            'title': request.form.get('title', ''),
            'description': request.form.get('user_description', '')
        }
        groups = request.form.getlist('groups')
        ou = request.form.get('ou', '')

        create_template(name, description, attributes, groups, ou)
        flash('Modele cree avec succes!', 'success')
        return redirect(url_for('user_templates_page'))

    return render_template('template_form.html', action='create', template=None, connected=is_connected())


@app.route('/templates/<template_id>/edit', methods=['GET', 'POST'])
@require_connection
def edit_user_template(template_id):
    """Modifier un modele d'utilisateur."""
    template = get_template(template_id)
    if not template:
        flash('Modele non trouve.', 'error')
        return redirect(url_for('user_templates_page'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description', '')
        attributes = {
            'department': request.form.get('department', ''),
            'title': request.form.get('title', ''),
            'description': request.form.get('user_description', '')
        }

        update_template(template_id, name=name, description=description, attributes=attributes)
        flash('Modele modifie avec succes!', 'success')
        return redirect(url_for('user_templates_page'))

    return render_template('template_form.html', action='edit', template=template,
                          template_id=template_id, connected=is_connected())


@app.route('/templates/<template_id>/delete', methods=['POST'])
@require_connection
def delete_user_template(template_id):
    """Supprimer un modele d'utilisateur."""
    delete_template(template_id)
    flash('Modele supprime.', 'success')
    return redirect(url_for('user_templates_page'))


@app.route('/favorites')
@require_connection
def favorites_page():
    """Page des favoris."""
    username = session.get('ad_username', '')
    favorites = get_user_favorites(username)
    counts = get_favorites_count(username)
    return render_template('favorites_page.html', favorites=favorites, counts=counts, connected=is_connected())


@app.route('/favorites/toggle', methods=['POST'])
@require_connection
def toggle_favorite():
    """Ajouter ou retirer un favori."""
    username = session.get('ad_username', '')
    action = request.form.get('action', 'add')
    obj_type = request.form.get('type', 'user')
    dn = request.form.get('dn')
    name = request.form.get('name', '')
    description = request.form.get('description', '')

    if action == 'remove':
        remove_favorite(username, dn)
        flash('Retire des favoris.', 'success')
    else:
        if add_favorite(username, obj_type, dn, name, description):
            flash('Ajoute aux favoris!', 'success')
        else:
            flash('Deja dans les favoris.', 'info')

    return redirect(request.referrer or url_for('favorites_page'))


@app.route('/expiring')
@require_connection
def expiring_accounts():
    """Page des comptes expirants."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')

    exp_accounts = check_expiring_accounts(conn, base_dn, days=30)
    pwd_expiring = []  # check_password_expiring(conn, base_dn, days=14)
    inactive = check_inactive_accounts(conn, base_dn, days=90)

    conn.unbind()

    return render_template('expiring_accounts.html', expiring_accounts=exp_accounts,
                          password_expiring=pwd_expiring, inactive_accounts=inactive,
                          connected=is_connected())


@app.route('/api/docs')
@require_connection
def api_documentation_page():
    """Page de documentation de l'API."""
    api_docs = get_api_documentation()
    api_keys = load_api_keys()
    return render_template('api_docs.html', api_docs=api_docs, api_keys=api_keys, connected=is_connected())


@app.route('/api/keys/generate', methods=['POST'])
@require_connection
def generate_api_key_route():
    """Generer une nouvelle cle API."""
    name = request.form.get('name', 'Default')
    permissions = request.form.getlist('permissions') or ['read']

    key = generate_api_key(name, permissions)
    flash(f'Cle API generee: {key}', 'success')
    return redirect(url_for('api_documentation_page'))


@app.route('/api/keys/revoke', methods=['POST'])
@require_connection
def revoke_api_key_route():
    """Revoquer une cle API."""
    key = request.form.get('key')
    if revoke_api_key(key):
        flash('Cle API revoquee.', 'success')
    else:
        flash('Cle non trouvee.', 'error')
    return redirect(url_for('api_documentation_page'))


@app.route('/language/<lang>')
def set_language(lang):
    """Changer la langue de l'interface."""
    if lang in ['fr', 'en']:
        session['language'] = lang
    return redirect(request.referrer or url_for('index'))


@app.route('/export/audit')
@require_connection
def export_audit_logs():
    """Exporter les logs d'audit en CSV."""
    logs = get_audit_logs(limit=1000)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Action', 'Utilisateur', 'Succes', 'IP', 'Details'])

    for log in logs:
        writer.writerow([
            log.get('timestamp', ''),
            log.get('action', ''),
            log.get('user', ''),
            'Oui' if log.get('success') else 'Non',
            log.get('ip', ''),
            str(log.get('details', ''))
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=audit_logs.csv'}
    )


@app.route('/export/expiring/pdf')
@require_connection
def export_expiring_pdf():
    """Exporter les comptes expirants en PDF."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas

        conn, error = get_ad_connection()
        if not conn:
            flash('Erreur de connexion', 'error')
            return redirect(url_for('expiring_accounts'))

        base_dn = session.get('ad_base_dn', '')
        exp_accounts = check_expiring_accounts(conn, base_dn, days=30)
        conn.unbind()

        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.setTitle("Comptes expirants")

        c.drawString(50, 750, "Rapport des comptes expirants")
        c.drawString(50, 730, f"Genere le: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}")

        y = 700
        for account in exp_accounts:
            if y < 50:
                c.showPage()
                y = 750
            c.drawString(50, y, f"{account['cn']} ({account['sAMAccountName']})")
            y -= 20

        if not exp_accounts:
            c.drawString(50, y, "Aucun compte expirant.")

        c.save()
        buffer.seek(0)

        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={'Content-Disposition': 'attachment; filename=expiring_accounts.pdf'}
        )

    except ImportError:
        flash('Module reportlab non installe pour l\'export PDF.', 'error')
        return redirect(url_for('expiring_accounts'))


def run_server():
    """
    Démarrer le serveur web avec support multi-plateforme.
    Utilise Waitress sur Windows, Gunicorn sur Linux, ou le serveur intégré Flask pour le développement.
    """
    import sys

    host = config.HOST
    port = config.PORT

    # Mode silencieux si AD_SILENT est defini ou si pas de console
    silent_mode = os.environ.get('AD_SILENT', '').lower() == 'true'

    # Detecter si on a une console (pour pythonw.exe)
    try:
        if sys.stdout is None or not hasattr(sys.stdout, 'write'):
            silent_mode = True
    except:
        silent_mode = True

    if not silent_mode:
        print(f"\n{'='*50}")
        print(f"Interface Web Microsoft Active Directory")
        print(f"{'='*50}")
        print(f"Plateforme: {platform.system()} ({platform.release()})")
        print(f"Écoute sur: http://{host}:{port}")
        print(f"Accès depuis n'importe quel appareil: http://<votre-ip>:{port}")
        print(f"{'='*50}\n")

    if os.environ.get('FLASK_ENV') == 'production':
        if IS_WINDOWS:
            # Utiliser Waitress sur Windows (serveur WSGI multi-plateforme)
            from waitress import serve
            if not silent_mode:
                print("Démarrage avec Waitress (serveur de production Windows)...")
            serve(app, host=host, port=port)
        else:
            # Sur Linux, recommander d'utiliser gunicorn en externe
            # gunicorn -w 4 -b 0.0.0.0:5000 app:app
            if not silent_mode:
                print("Pour la production sur Linux, utilisez: gunicorn -w 4 -b 0.0.0.0:5000 app:app")
            app.run(host=host, port=port, debug=False)
    else:
        # Serveur de développement
        app.run(host=host, port=port, debug=config.DEBUG)


if __name__ == '__main__':
    run_server()
