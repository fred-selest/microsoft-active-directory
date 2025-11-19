"""
Module de securite pour l'interface Web Active Directory.
Contient les fonctions de protection contre les attaques courantes.
"""

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
_cleanup_time = 0


def _cleanup_old_attempts():
    """Nettoyer les anciennes tentatives."""
    global _login_attempts, _cleanup_time
    current_time = time.time()

    # Nettoyer toutes les 5 minutes
    if current_time - _cleanup_time > 300:
        cutoff = current_time - 900  # 15 minutes
        _login_attempts = {
            ip: data for ip, data in _login_attempts.items()
            if data['last_attempt'] > cutoff
        }
        _cleanup_time = current_time


def check_rate_limit(ip_address, max_attempts=5, window_seconds=300):
    """
    Verifier si une IP a depasse la limite de tentatives.

    Args:
        ip_address: Adresse IP a verifier
        max_attempts: Nombre maximum de tentatives autorisees
        window_seconds: Fenetre de temps en secondes

    Returns:
        tuple: (autorise, temps_restant)
    """
    _cleanup_old_attempts()
    current_time = time.time()

    if ip_address not in _login_attempts:
        return True, 0

    data = _login_attempts[ip_address]

    # Verifier si la fenetre est expiree
    if current_time - data['first_attempt'] > window_seconds:
        del _login_attempts[ip_address]
        return True, 0

    # Verifier le nombre de tentatives
    if data['count'] >= max_attempts:
        remaining = int(window_seconds - (current_time - data['first_attempt']))
        return False, remaining

    return True, 0


def record_login_attempt(ip_address, success=False):
    """
    Enregistrer une tentative de connexion.

    Args:
        ip_address: Adresse IP
        success: Si la connexion a reussi
    """
    current_time = time.time()

    if success:
        # Reinitialiser les tentatives en cas de succes
        if ip_address in _login_attempts:
            del _login_attempts[ip_address]
        return

    if ip_address not in _login_attempts:
        _login_attempts[ip_address] = {
            'count': 1,
            'first_attempt': current_time,
            'last_attempt': current_time
        }
    else:
        _login_attempts[ip_address]['count'] += 1
        _login_attempts[ip_address]['last_attempt'] = current_time


def rate_limit(max_attempts=5, window_seconds=300):
    """
    Decorateur pour limiter le nombre de requetes.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            allowed, remaining = check_rate_limit(ip, max_attempts, window_seconds)

            if not allowed:
                return jsonify({
                    'success': False,
                    'error': f'Trop de tentatives. Reessayez dans {remaining} secondes.'
                }), 429

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

    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
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
    """
    return {
        'SESSION_COOKIE_SECURE': False,  # Mettre True si HTTPS
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'SESSION_COOKIE_NAME': 'ad_session',
        'PERMANENT_SESSION_LIFETIME': 1800  # 30 minutes
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
