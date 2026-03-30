"""
Module de diagnostic et dépannage automatique pour AD Web Interface.
Vérifie la configuration, les dépendances, et propose des corrections.
"""

import os
import sys
import subprocess
import ssl
import socket
from pathlib import Path
from datetime import datetime

# Diagnostic results
DIAG_RESULTS = {
    'timestamp': None,
    'status': 'unknown',
    'checks': [],
    'errors': [],
    'warnings': [],
    'suggestions': []
}


def add_check(name, passed, message='', details=''):
    """Ajouter un résultat de vérification."""
    DIAG_RESULTS['checks'].append({
        'name': name,
        'passed': passed,
        'message': message,
        'details': details
    })
    if not passed:
        DIAG_RESULTS['errors'].append(f"{name}: {message}")


def add_warning(name, message, suggestion=''):
    """Ajouter un avertissement."""
    DIAG_RESULTS['warnings'].append({
        'name': name,
        'message': message,
        'suggestion': suggestion
    })


def check_openssl_conf():
    """Vérifier la configuration OpenSSL pour MD4/NTLM."""
    openssl_conf = os.environ.get('OPENSSL_CONF', '')
    
    if not openssl_conf:
        add_check('OPENSSL_CONF', False, 
                  'Variable OPENSSL_CONF non définie',
                  'Le support MD4/NTLM ne sera pas actif avec Python 3.12+')
        DIAG_RESULTS['suggestions'].append({
            'title': 'Activer le support MD4/NTLM',
            'description': 'Exécutez fix_md4_final.ps1 en administrateur',
            'command': '.\\fix_md4_final.ps1'
        })
        return False
    
    if not os.path.exists(openssl_conf):
        add_check('openssl_legacy.cnf', False, 
                  f'Fichier introuvable: {openssl_conf}',
                  'Le fichier de configuration OpenSSL est manquant')
        return False
    
    # Vérifier le contenu
    try:
        content = Path(openssl_conf).read_text(encoding='ascii')
        if 'legacy' in content and 'activate = 1' in content:
            add_check('openssl_legacy.cnf', True, 
                      f'Configuration valide: {openssl_conf}')
            return True
        else:
            add_check('openssl_legacy.cnf', False,
                      'Configuration incomplete (provider legacy manquant)',
                      'Le fichier doit contenir [legacy_sect] avec activate = 1')
            return False
    except Exception as e:
        add_check('openssl_legacy.cnf', False, 
                  f'Erreur de lecture: {str(e)}')
        return False


def check_python_version():
    """Vérifier la version de Python."""
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    
    if version.major < 3:
        add_check('Python version', False, 
                  f'Python {version_str} non supporté',
                  'Python 3.8+ requis')
        return False
    
    if version.major == 3 and version.minor >= 12:
        add_check('Python version', True, 
                  f'Python {version_str} (MD4/NTLM nécessite configuration)',
                  'Python 3.12+ nécessite OPENSSL_CONF pour NTLM')
        return True
    
    add_check('Python version', True, f'Python {version_str}')
    return True


def check_dependencies():
    """Vérifier les dépendances critiques."""
    deps = {
        'flask': 'Flask',
        'ldap3': 'ldap3',
        'cryptography': 'cryptography',
        'dotenv': 'python-dotenv'
    }
    
    all_ok = True
    for module, name in deps.items():
        try:
            __import__(module)
            add_check(f'Dépendance: {name}', True)
        except ImportError:
            add_check(f'Dépendance: {name}', False, 'Module non installé')
            all_ok = False
    
    if not all_ok:
        DIAG_RESULTS['suggestions'].append({
            'title': 'Installer les dépendances',
            'command': 'pip install -r requirements.txt'
        })
    
    return all_ok


def check_ad_connectivity(server='localhost', port=389):
    """Vérifier la connectivité au port LDAP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((server, port))
        sock.close()
        
        if result == 0:
            add_check(f'Connectivité LDAP ({server}:{port})', True)
            return True
        else:
            add_check(f'Connectivité LDAP ({server}:{port})', False,
                      f'Port fermé (code: {result})',
                      'Vérifiez que le service AD DS tourne et que le pare-feu autorise le port')
            return False
    except Exception as e:
        add_check(f'Connectivité LDAP ({server}:{port})', False, str(e))
        return False


def check_service_status():
    """Vérifier si le service Windows est installé (Windows uniquement)."""
    if os.name != 'nt':
        add_check('Service Windows', True, 'Non applicable (Linux)')
        return True
    
    try:
        result = subprocess.run(['sc', 'query', 'ADWebInterface'], 
                              capture_output=True, text=True, timeout=5)
        if 'RUNNING' in result.stdout or 'STOPPED' in result.stdout:
            add_check('Service Windows', True, 'Service ADWebInterface installé')
            return True
        else:
            add_check('Service Windows', False, 'Service non installé',
                      'Exécutez install_ad.ps1 ou install_service.bat')
            return False
    except Exception as e:
        add_check('Service Windows', False, f'Erreur: {str(e)}')
        return False


def check_directories():
    """Vérifier les répertoires requis."""
    dirs = ['logs', 'data']
    all_ok = True
    
    for directory in dirs:
        path = Path(directory)
        if not path.exists():
            try:
                path.mkdir(parents=True, exist_ok=True)
                add_check(f'Répertoire: {directory}', True, 'Créé automatiquement')
            except Exception as e:
                add_check(f'Répertoire: {directory}', False, f'Impossible à créer: {str(e)}')
                all_ok = False
        else:
            if path.is_dir():
                add_check(f'Répertoire: {directory}', True)
            else:
                add_check(f'Répertoire: {directory}', False, 'Existe mais n\'est pas un dossier')
                all_ok = False
    
    return all_ok


def check_env_file():
    """Vérifier le fichier .env."""
    env_file = Path('.env')
    
    if not env_file.exists():
        add_check('Fichier .env', False, 'Fichier manquant',
                  'Le fichier .env sera généré automatiquement au prochain démarrage')
        add_warning('.env', 'Fichier manquant', 
                    'Générez un .env avec: python -c "import secrets; print(\'SECRET_KEY=\'+secrets.token_hex(32))" > .env')
        return False
    
    try:
        content = env_file.read_text(encoding='utf-8')
        has_secret = 'SECRET_KEY=' in content and len(content) > 50
        has_flask_env = 'FLASK_ENV=' in content
        
        if has_secret and has_flask_env:
            add_check('Fichier .env', True, 'Configuration présente')
            return True
        elif has_secret:
            add_check('Fichier .env', True, 'Présent (configuration minimale)')
            return True
        else:
            add_check('Fichier .env', False, 'SECRET_KEY manquante ou trop courte',
                      'Générez une SECRET_KEY forte')
            return False
    except Exception as e:
        add_check('Fichier .env', False, f'Erreur de lecture: {str(e)}')
        return False


def check_ssl_context():
    """Vérifier que le contexte SSL peut être créé."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        add_check('Contexte SSL', True)
        return True
    except Exception as e:
        add_check('Contexte SSL', False, f'Erreur: {str(e)}',
                  'Problème de configuration OpenSSL')
        return False


def run_full_diagnostic(server='localhost', port=389):
    """Exécuter tous les diagnostics."""
    DIAG_RESULTS['timestamp'] = datetime.now().isoformat()
    DIAG_RESULTS['status'] = 'running'
    DIAG_RESULTS['checks'] = []
    DIAG_RESULTS['errors'] = []
    DIAG_RESULTS['warnings'] = []
    DIAG_RESULTS['suggestions'] = []
    
    # Exécuter tous les checks
    check_python_version()
    check_openssl_conf()
    check_dependencies()
    check_ssl_context()
    check_env_file()
    check_directories()
    check_service_status()
    check_ad_connectivity(server, port)
    
    # Déterminer le statut global
    failed = sum(1 for c in DIAG_RESULTS['checks'] if not c['passed'])
    total = len(DIAG_RESULTS['checks'])
    
    if failed == 0:
        DIAG_RESULTS['status'] = 'healthy'
    elif failed < total / 2:
        DIAG_RESULTS['status'] = 'warning'
    else:
        DIAG_RESULTS['status'] = 'error'
    
    return DIAG_RESULTS


def get_diagnostic_html():
    """Générer un rapport HTML du diagnostic."""
    html = f"""
    <div class="diagnostic-report">
        <h3>Rapport de Diagnostic</h3>
        <p><strong>Date:</strong> {DIAG_RESULTS['timestamp']}</p>
        <p><strong>Statut:</strong> 
            <span class="badge badge-{'success' if DIAG_RESULTS['status'] == 'healthy' else 'warning' if DIAG_RESULTS['status'] == 'warning' else 'danger'}">
                {DIAG_RESULTS['status'].upper()}
            </span>
        </p>
        
        <h4>Vérifications</h4>
        <table class="table">
            <thead>
                <tr>
                    <th>Test</th>
                    <th>Statut</th>
                    <th>Détails</th>
                </tr>
            </thead>
            <tbody>
    """
    
    for check in DIAG_RESULTS['checks']:
        icon = '✅' if check['passed'] else '❌'
        status_class = 'success' if check['passed'] else 'danger'
        html += f"""
                <tr>
                    <td>{check['name']}</td>
                    <td><span class="badge badge-{status_class}">{icon}</span></td>
                    <td>{check.get('message', '')} {check.get('details', '')}</td>
                </tr>
        """
    
    html += """
            </tbody>
        </table>
    """
    
    if DIAG_RESULTS['suggestions']:
        html += """
        <h4>Suggestions</h4>
        <ul>
        """
        for sug in DIAG_RESULTS['suggestions']:
            html += f"""
            <li>
                <strong>{sug.get('title', 'Action requise')}</strong><br>
                {sug.get('description', '')}
                {f'<code>{sug.get("command", "")}</code>' if sug.get('command') else ''}
            </li>
            """
        html += """
        </ul>
        """
    
    html += """
    </div>
    """
    
    return html
