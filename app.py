"""
Cross-platform Web Interface for Microsoft Active Directory.
Works on Windows and Linux systems.
"""

import os
import platform
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException
from config import get_config, CURRENT_OS, IS_WINDOWS

app = Flask(__name__)
config = get_config()

# Apply configuration
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['DEBUG'] = config.DEBUG

# Initialize directories
config.init_directories()


def get_ad_connection(server, username, password, use_ssl=False, port=None):
    """
    Create a connection to Active Directory.
    Works on both Windows and Linux.
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
    """Home page with system information."""
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
    """Connect to Active Directory server."""
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
            # Store connection info in session for later use
            return redirect(url_for('dashboard'))
        else:
            flash(f'Erreur de connexion: {error}', 'error')

    return render_template('connect.html')


@app.route('/dashboard')
def dashboard():
    """Dashboard page."""
    return render_template('dashboard.html')


@app.route('/api/search', methods=['POST'])
def api_search():
    """
    API endpoint to search Active Directory.
    Cross-platform compatible.
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
    """Return system information for debugging."""
    return jsonify({
        'os': CURRENT_OS,
        'is_windows': IS_WINDOWS,
        'hostname': platform.node(),
        'python_version': platform.python_version(),
        'platform': platform.platform()
    })


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'platform': CURRENT_OS})


def run_server():
    """
    Run the web server with cross-platform support.
    Uses Waitress on Windows, Gunicorn on Linux, or Flask's built-in server for development.
    """
    host = config.HOST
    port = config.PORT

    print(f"\n{'='*50}")
    print(f"Microsoft Active Directory Web Interface")
    print(f"{'='*50}")
    print(f"Platform: {platform.system()} ({platform.release()})")
    print(f"Listening on: http://{host}:{port}")
    print(f"Access from any device on network: http://<your-ip>:{port}")
    print(f"{'='*50}\n")

    if os.environ.get('FLASK_ENV') == 'production':
        if IS_WINDOWS:
            # Use Waitress on Windows (cross-platform WSGI server)
            from waitress import serve
            print("Starting with Waitress (Windows production server)...")
            serve(app, host=host, port=port)
        else:
            # On Linux, recommend using gunicorn externally
            # gunicorn -w 4 -b 0.0.0.0:5000 app:app
            print("For production on Linux, use: gunicorn -w 4 -b 0.0.0.0:5000 app:app")
            app.run(host=host, port=port, debug=False)
    else:
        # Development server
        app.run(host=host, port=port, debug=config.DEBUG)


if __name__ == '__main__':
    run_server()
