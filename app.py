"""
Interface Web Multi-Plateforme pour Microsoft Active Directory.
Fonctionne sur les systèmes Windows et Linux.
"""

import os
import platform
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, session
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
from ldap3.core.exceptions import LDAPException
from config import get_config, CURRENT_OS, IS_WINDOWS

app = Flask(__name__)
config = get_config()

# Appliquer la configuration
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['DEBUG'] = config.DEBUG

# Initialiser les répertoires
config.init_directories()


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
    """Page d'accueil avec informations système."""
    system_info = {
        'os': platform.system(),
        'os_version': platform.version(),
        'hostname': platform.node(),
        'python_version': platform.python_version(),
        'architecture': platform.machine()
    }
    return render_template('index.html', system_info=system_info, connected=is_connected())


@app.route('/connect', methods=['GET', 'POST'])
def connect():
    """Connexion au serveur Active Directory."""
    if request.method == 'POST':
        server = request.form.get('server')
        username = request.form.get('username')
        password = request.form.get('password')
        use_ssl = request.form.get('use_ssl') == 'on'
        port = request.form.get('port', '')
        base_dn = request.form.get('base_dn', '')

        port = int(port) if port else None

        conn, error = get_ad_connection(server, username, password, use_ssl, port)

        if conn:
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
            flash('Connexion réussie à Active Directory!', 'success')
            return redirect(url_for('users'))
        else:
            flash(f'Erreur de connexion: {error}', 'error')

    return render_template('connect.html', connected=is_connected())


@app.route('/disconnect')
def disconnect():
    """Déconnexion d'Active Directory."""
    session.clear()
    flash('Déconnecté d\'Active Directory.', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard')
@require_connection
def dashboard():
    """Page du tableau de bord."""
    return render_template('dashboard.html', connected=is_connected())


@app.route('/users')
@require_connection
def users():
    """Liste des utilisateurs Active Directory."""
    conn, error = get_ad_connection()

    if not conn:
        flash(f'Erreur de connexion: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')

    # Construire le filtre de recherche
    if search_query:
        search_filter = f'(&(objectClass=user)(objectCategory=person)(|(cn=*{search_query}*)(sAMAccountName=*{search_query}*)(mail=*{search_query}*)))'
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
                'cn': str(entry.cn) if entry.cn else '',
                'sAMAccountName': str(entry.sAMAccountName) if entry.sAMAccountName else '',
                'mail': str(entry.mail) if entry.mail else '',
                'dn': str(entry.distinguishedName) if entry.distinguishedName else '',
                'givenName': str(entry.givenName) if entry.givenName else '',
                'sn': str(entry.sn) if entry.sn else '',
                'displayName': str(entry.displayName) if entry.displayName else '',
                'department': str(entry.department) if entry.department else '',
                'title': str(entry.title) if entry.title else '',
                'disabled': is_disabled
            })

        conn.unbind()
        return render_template('users.html', users=user_list, search=search_query, connected=is_connected())

    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur de recherche: {str(e)}', 'error')
        return render_template('users.html', users=[], search=search_query, connected=is_connected())


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

                flash(f'Utilisateur {username} créé avec succès!', 'success')
                conn.unbind()
                return redirect(url_for('users'))
            else:
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
                'cn': str(entry.cn) if entry.cn else '',
                'sAMAccountName': str(entry.sAMAccountName) if entry.sAMAccountName else '',
                'mail': str(entry.mail) if entry.mail else '',
                'givenName': str(entry.givenName) if entry.givenName else '',
                'sn': str(entry.sn) if entry.sn else '',
                'displayName': str(entry.displayName) if entry.displayName else '',
                'department': str(entry.department) if entry.department else '',
                'title': str(entry.title) if entry.title else '',
                'telephoneNumber': str(entry.telephoneNumber) if entry.telephoneNumber else '',
                'description': str(entry.description) if entry.description else '',
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

    # Construire le filtre de recherche
    if search_query:
        search_filter = f'(&(objectClass=group)(|(cn=*{search_query}*)(description=*{search_query}*)))'
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

            group_list.append({
                'cn': str(entry.cn) if entry.cn else '',
                'dn': str(entry.distinguishedName) if entry.distinguishedName else '',
                'description': str(entry.description) if entry.description else '',
                'member_count': len(members),
                'groupType': str(entry.groupType) if entry.groupType else ''
            })

        conn.unbind()
        return render_template('groups.html', groups=group_list, search=search_query, connected=is_connected())

    except LDAPException as e:
        conn.unbind()
        flash(f'Erreur de recherche: {str(e)}', 'error')
        return render_template('groups.html', groups=[], search=search_query, connected=is_connected())


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
    from updater import download_update, apply_update, update_dependencies, check_for_updates

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
            return jsonify({
                'success': True,
                'message': f'Mise à jour vers la version {info["latest_version"]} réussie. Redémarrez le serveur.'
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


def run_server():
    """
    Démarrer le serveur web avec support multi-plateforme.
    Utilise Waitress sur Windows, Gunicorn sur Linux, ou le serveur intégré Flask pour le développement.
    """
    host = config.HOST
    port = config.PORT

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
            print("Démarrage avec Waitress (serveur de production Windows)...")
            serve(app, host=host, port=port)
        else:
            # Sur Linux, recommander d'utiliser gunicorn en externe
            # gunicorn -w 4 -b 0.0.0.0:5000 app:app
            print("Pour la production sur Linux, utilisez: gunicorn -w 4 -b 0.0.0.0:5000 app:app")
            app.run(host=host, port=port, debug=False)
    else:
        # Serveur de développement
        app.run(host=host, port=port, debug=config.DEBUG)


if __name__ == '__main__':
    run_server()
