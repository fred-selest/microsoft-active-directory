"""
Interface Web Multi-Plateforme pour Microsoft Active Directory.
Fonctionne sur les systèmes Windows et Linux.
"""

import os
import platform
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException
from config import get_config, CURRENT_OS, IS_WINDOWS

app = Flask(__name__)
config = get_config()

# Appliquer la configuration
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['DEBUG'] = config.DEBUG

# Initialiser les répertoires
config.init_directories()


def get_ad_connection(server, username, password, use_ssl=False, port=None):
    """
    Créer une connexion à Active Directory.
    Fonctionne sur Windows et Linux.
    """
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
    return render_template('index.html', system_info=system_info)


@app.route('/connect', methods=['GET', 'POST'])
def connect():
    """Connexion au serveur Active Directory."""
    if request.method == 'POST':
        server = request.form.get('server')
        username = request.form.get('username')
        password = request.form.get('password')
        use_ssl = request.form.get('use_ssl') == 'on'
        port = request.form.get('port', '')

        port = int(port) if port else None

        conn, error = get_ad_connection(server, username, password, use_ssl, port)

        if conn:
            flash('Connexion réussie à Active Directory!', 'success')
            # Stocker les informations de connexion pour une utilisation ultérieure
            return redirect(url_for('dashboard'))
        else:
            flash(f'Erreur de connexion: {error}', 'error')

    return render_template('connect.html')


@app.route('/dashboard')
def dashboard():
    """Page du tableau de bord."""
    return render_template('dashboard.html')


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
