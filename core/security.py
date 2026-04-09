"""
Module de securite pour l'interface Web Active Directory.
Contient les fonctions de protection contre les attaques courantes.
"""

import os
import re
import time
from functools import wraps
from flask import request, jsonify, session

# === PROTECTION CONTRE INJECTION LDAP ===

# Caracteres speciaux LDAP a echapper
LDAP_ESCAPE_CHARS = {
    '\\': r'\5c',
    '*': r'\2a',
    '(': r'\28',
    ')': r'\29',
    '\x00': r'\00',
    '/': r'\2f',
}


def escape_ldap_filter(value):
    """
    Echapper les caracteres speciaux pour les filtres LDAP.
    Previent les injections LDAP.
    """
    if not value:
        return value

    result = str(value)
    for char, escaped in LDAP_ESCAPE_CHARS.items():
        result = result.replace(char, escaped)

    return result


def sanitize_dn_component(value):
    """
    Nettoyer un composant DN pour eviter les injections.
    """
    if not value:
        return value

    # Caracteres interdits dans les DNs
    forbidden = ['\\', ',', '+', '"', '<', '>', ';', '=', '\n', '\r']
    result = str(value)

    for char in forbidden:
        result = result.replace(char, '')

    return result.strip()


# === RATE LIMITING ===

# Stockage des tentatives de connexion (en memoire)
_login_attempts = {}
_action_attempts = {}  # Pour les actions sensibles
_api_attempts = {}
_cleanup_time = 0


def _cleanup_old_attempts():
    """Nettoyer les anciennes tentatives."""
    global _login_attempts, _action_attempts, _api_attempts, _cleanup_time
    current_time = time.time()

    # Nettoyer toutes les 5 minutes
    if current_time - _cleanup_time > 300:
        cutoff = current_time - 900  # 15 minutes
        _login_attempts = {
            ip: data for ip, data in _login_attempts.items()
            if data.get('last_attempt', 0) > cutoff
        }
        _action_attempts = {
            (ip, action): data for (ip, action), data in _action_attempts.items()
            if data.get('last_attempt', 0) > cutoff
        }
        _api_attempts = {
            ip: data for ip, data in _api_attempts.items()
            if data.get('last_attempt', 0) > cutoff
        }
        _cleanup_time = current_time


def check_rate_limit(ip_address, max_attempts=5, window_seconds=300, action=None):
    """
    Verifier si une IP a depasse la limite de tentatives.

    Args:
        ip_address: Adresse IP a verifier
        max_attempts: Nombre maximum de tentatives autorisees
        window_seconds: Fenetre de temps en secondes
        action: Nom de l'action (pour rate limiting par action)

    Returns:
        tuple: (autorise, temps_restant, tentatives_restantes)
    """
    _cleanup_old_attempts()
    current_time = time.time()

    # ClÃ© unique : IP seule ou IP + action
    key = (ip_address, action) if action else ip_address
    attempts_dict = _action_attempts if action else _login_attempts

    if key not in attempts_dict:
        return True, 0, max_attempts

    data = attempts_dict[key]

    # Verifier si la fenetre est expiree
    if current_time - data.get('first_attempt', 0) > window_seconds:
        if key in attempts_dict:
            del attempts_dict[key]
        return True, 0, max_attempts

    # Calculer le temps restant et les tentatives restantes
    elapsed = current_time - data.get('first_attempt', 0)
    remaining_time = int(window_seconds - elapsed)
    attempts_left = max(0, max_attempts - data.get('count', 0))

    # Verifier le nombre de tentatives
    if data.get('count', 0) >= max_attempts:
        return False, remaining_time, 0

    return True, remaining_time, attempts_left


def record_attempt(ip_address, success=False, action=None):
    """
    Enregistrer une tentative (login ou action sensible).

    Args:
        ip_address: Adresse IP
        success: Si l'action a reussi
        action: Nom de l'action (pour les actions sensibles)
    """
    current_time = time.time()

    # ClÃ© unique : IP seule ou IP + action
    key = (ip_address, action) if action else ip_address
    attempts_dict = _action_attempts if action else _login_attempts

    if success:
        # Reinitialiser les tentatives en cas de succes
        if key in attempts_dict:
            del attempts_dict[key]
        return

    if key not in attempts_dict:
        attempts_dict[key] = {
            'count': 1,
            'first_attempt': current_time,
            'last_attempt': current_time,
            'action': action
        }
    else:
        attempts_dict[key]['count'] += 1
        attempts_dict[key]['last_attempt'] = current_time


def get_rate_limit_status(ip_address, action=None):
    """
    Obtenir le statut du rate limiting pour une IP.
    Utile pour afficher les informations dans l'UI.
    """
    key = (ip_address, action) if action else ip_address
    attempts_dict = _action_attempts if action else _login_attempts

    if key not in attempts_dict:
        return {'limited': False, 'attempts': 0, 'max_attempts': 5, 'remaining_time': 0}

    data = attempts_dict[key]
    current_time = time.time()
    elapsed = current_time - data.get('first_attempt', 0)

    return {
        'limited': data.get('count', 0) >= 5,
        'attempts': data.get('count', 0),
        'max_attempts': 5,
        'remaining_time': max(0, int(300 - elapsed))
    }


def rate_limit(max_attempts=5, window_seconds=300, action=None):
    """
    Decorateur pour limiter le nombre de requetes.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            allowed, remaining, attempts_left = check_rate_limit(
                ip, max_attempts, window_seconds, action
            )

            if not allowed:
                # Enregistrer la tentative Ã©chouÃ©e
                record_attempt(ip, success=False, action=action)

                # RÃ©ponse adaptÃ©e selon le type de requÃªte
                if request.is_json or request.endpoint.startswith('api_'):
                    return jsonify({
                        'success': False,
                        'error': 'Trop de tentatives',
                        'retry_after': remaining,
                        'attempts_remaining': attempts_left
                    }), 429

                # Page HTML pour les requÃªtes normales
                from flask import render_template
                return render_template('rate_limited.html',
                                       action=action or 'login',
                                       retry_after=remaining,
                                       attempts_remaining=attempts_left), 429

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def rate_limit_api(max_attempts=100, window_seconds=60):
    """
    Decorateur spÃ©cial pour les endpoints API.
    Plus permissif pour permettre l'automatisation.
    """
    def decorator(f):
        @wraps(f)
        @rate_limit(max_attempts, window_seconds, action='api')
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def rate_limit_sensitive(max_attempts=10, window_seconds=300):
    """
    Decorateur pour les actions sensibles (delete, unlock, restore).
    """
    def decorator(f):
        @wraps(f)
        @rate_limit(max_attempts, window_seconds)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# === VALIDATION MOT DE PASSE ===

def validate_password_strength(password, min_length=8):
    """
    Valider la force d'un mot de passe.

    Args:
        password: Mot de passe a valider
        min_length: Longueur minimale requise

    Returns:
        tuple: (valide, message)
    """
    if not password:
        return False, "Le mot de passe est requis"

    if len(password) < min_length:
        return False, f"Le mot de passe doit contenir au moins {min_length} caracteres"

    # Verifier la complexite
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    complexity_score = sum([has_upper, has_lower, has_digit, has_special])

    if complexity_score < 3:
        return False, "Le mot de passe doit contenir au moins 3 des elements suivants: majuscule, minuscule, chiffre, caractere special"

    return True, "Mot de passe valide"


def get_password_requirements():
    """
    Retourner les exigences de mot de passe pour affichage.
    """
    return {
        'min_length': 8,
        'require_uppercase': True,
        'require_lowercase': True,
        'require_digit': True,
        'require_special': True,
        'min_complexity': 3
    }


# === HEADERS DE SECURITE ===

def add_security_headers(response):
    """
    Ajouter les headers de securite HTTP a une reponse.

    Args:
        response: Objet Response Flask

    Returns:
        Response avec headers de securite
    """
    # Protection contre clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'

    # Protection contre le sniffing MIME
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Protection XSS
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Politique de referrer
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # HTTP Strict Transport Security (HSTS) - Force HTTPS
    # Active seulement si la connexion est sÃ©curisÃ©e
    if request.is_secure or os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Permissions-Policy - Restreint les APIs du navigateur
    response.headers['Permissions-Policy'] = (
        'geolocation=(), '
        'microphone=(), '
        'camera=(), '
        'payment=(), '
        'usb=(), '
        'magnetometer=(), '
        'gyroscope=()'
    )

    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "frame-ancestors 'self'"
    )

    # Cache control pour les pages sensibles
    if request.endpoint in ['connect', 'dashboard', 'users', 'groups']:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'

    return response


# === CONFIGURATION SESSION SECURISEE ===

def get_secure_session_config():
    """
    Retourner la configuration securisee pour les sessions Flask.
    Par dÃ©faut, SESSION_COOKIE_SECURE est activÃ© (HTTPS requis).
    Pour dÃ©sactiver en dÃ©veloppement: SESSION_COOKIE_SECURE=false dans .env
    """
    import os
    # Par defaut desactive (Waitress sert en HTTP interne)
    # Activer uniquement si HTTPS termine directement (reverse proxy ou LDAPS)
    cookie_secure = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

    return {
        'SESSION_COOKIE_SECURE': cookie_secure,
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'SESSION_COOKIE_NAME': 'ad_session',
        'PERMANENT_SESSION_LIFETIME': 7200  # 2 heures
    }


# === PROTECTION CSRF ===

import secrets

def generate_csrf_token():
    """Generer un token CSRF."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf_token(token):
    """Valider un token CSRF."""
    return token and token == session.get('csrf_token')


def csrf_protect():
    """
    Decorateur pour proteger une route contre les attaques CSRF.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
                if not validate_csrf_token(token):
                    return jsonify({'success': False, 'error': 'Token CSRF invalide'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

