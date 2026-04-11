# -*- coding: utf-8 -*-
"""
Tests pour le module core/security.py

Couvre :
- Echappement LDAP (escape_ldap_filter, sanitize_dn_component)
- Rate limiting (check_rate_limit, record_attempt, get_rate_limit_status)
- Validation mot de passe (validate_password_strength, get_password_requirements)
- Headers de securite (add_security_headers)
- Configuration session (get_secure_session_config)
- Protection CSRF (generate_csrf_token, validate_csrf_token, csrf_protect)

Les donnees sensibles (tokens, sessions) sont mockees pour eviter les effets de bord.
"""
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock
from importlib import reload

import pytest

# Ajouter le repertoire parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def reset_rate_limits():
    """
    Fixture qui reinitialise les dictionnaires de rate limiting
    avant et apres chaque test pour eviter les effets de bord.
    """
    from core import security
    # Sauvegarder l'etat initial
    original_login = security._login_attempts.copy()
    original_action = security._action_attempts.copy()
    original_api = security._api_attempts.copy()
    original_cleanup = security._cleanup_time

    # Reinitialiser
    security._login_attempts.clear()
    security._action_attempts.clear()
    security._api_attempts.clear()
    security._cleanup_time = 0

    yield security

    # Restaurer
    security._login_attempts.clear()
    security._login_attempts.update(original_login)
    security._action_attempts.clear()
    security._action_attempts.update(original_action)
    security._api_attempts.clear()
    security._api_attempts.update(original_api)
    security._cleanup_time = original_cleanup


@pytest.fixture
def flask_session_mock():
    """
    Fixture qui mocke l'objet session Flask comme un dictionnaire simple.
    """
    with patch('core.security.session', {}) as mock_session:
        yield mock_session


@pytest.fixture
def flask_request_mock():
    """
    Fixture qui mocke l'objet request Flask avec des valeurs par defaut.
    """
    with patch('core.security.request') as mock_request:
        mock_request.remote_addr = '127.0.0.1'
        mock_request.is_secure = False
        mock_request.is_json = False
        mock_request.endpoint = 'main.index'
        mock_request.method = 'GET'
        mock_request.form = {}
        mock_request.headers = {}
        yield mock_request


# =============================================================================
# TESTS : LDAP ESCAPE
# =============================================================================

class TestEscapeLdapFilter:
    """Tests pour la fonction escape_ldap_filter."""

    def test_escape_basic_string(self):
        """Une chaine sans caracteres speciaux reste inchangee."""
        from core.security import escape_ldap_filter
        result = escape_ldap_filter('john.doe')
        assert result == 'john.doe'

    def test_escape_asterisk(self):
        """Le caractere * est echappe en \\2a."""
        from core.security import escape_ldap_filter
        result = escape_ldap_filter('admin*')
        assert result == 'admin\\2a'

    def test_escape_parentheses(self):
        """Les parentheses ( et ) sont echappees en \\28 et \\29."""
        from core.security import escape_ldap_filter
        result = escape_ldap_filter('test(user)')
        assert result == 'test\\28user\\29'

    def test_escape_backslash(self):
        """Le backslash \\ est echappe en \\5c."""
        from core.security import escape_ldap_filter
        result = escape_ldap_filter('domain\\user')
        assert result == 'domain\\5cuser'

    def test_escape_null_byte(self):
        """Le caractere null \\x00 est echappe en \\00."""
        from core.security import escape_ldap_filter
        result = escape_ldap_filter('test\x00value')
        assert result == 'test\\00value'

    def test_escape_forward_slash(self):
        """Le slash / est echappe en \\2f."""
        from core.security import escape_ldap_filter
        result = escape_ldap_filter('path/to/resource')
        assert result == 'path\\2fto\\2fresource'

    def test_escape_multiple_special_chars(self):
        """Plusieurs caracteres speciaux sont tous echappes."""
        from core.security import escape_ldap_filter
        result = escape_ldap_filter('admin*(test)\\value')
        assert '\\2a' in result
        assert '\\28' in result
        assert '\\29' in result
        assert '\\5c' in result

    def test_escape_empty_string(self):
        """Une chaine vide retourne une chaine vide."""
        from core.security import escape_ldap_filter
        result = escape_ldap_filter('')
        assert result == ''

    def test_escape_none(self):
        """Une valeur None retourne None sans lever d'exception."""
        from core.security import escape_ldap_filter
        result = escape_ldap_filter(None)
        assert result is None

    def test_escape_injection_attempt(self):
        """
        Tenter d'injecter un filtre LDAP via *)
        doit resulter en une chaine completement echappee.
        """
        from core.security import escape_ldap_filter
        # Injection classique : *) (|(uid=*
        malicious = '*)(|(uid=*)'
        result = escape_ldap_filter(malicious)
        # Le resultat ne doit plus contenir de parentheses non echappees
        assert '(' not in result
        assert ')' not in result
        assert '*' not in result

    def test_escape_unicode_string(self):
        """Les caracteres unicode sont preserves apres echappement."""
        from core.security import escape_ldap_filter
        result = escape_ldap_filter('utilisateu\U000000e9')
        assert 'utilisateu\U000000e9' in result

    def test_escape_numeric_string(self):
        """Un entier converti en chaine est correctement traite."""
        from core.security import escape_ldap_filter
        result = escape_ldap_filter(12345)
        assert result == '12345'


# =============================================================================
# TESTS : SANITIZE DN COMPONENT
# =============================================================================

class TestSanitizeDnComponent:
    """Tests pour la fonction sanitize_dn_component."""

    def test_sanitize_basic_string(self):
        """Une chaine sans caracteres interdits reste inchangee."""
        from core.security import sanitize_dn_component
        result = sanitize_dn_component('Users')
        assert result == 'Users'

    def test_sanitize_removes_backslash(self):
        """Le backslash est supprime."""
        from core.security import sanitize_dn_component
        result = sanitize_dn_component('user\\name')
        assert '\\' not in result
        assert result == 'username'

    def test_sanitize_removes_comma(self):
        """La virgule est supprimee."""
        from core.security import sanitize_dn_component
        result = sanitize_dn_component('CN=John,OU=Users')
        assert ',' not in result

    def test_sanitize_removes_plus(self):
        """Le signe + est supprime."""
        from core.security import sanitize_dn_component
        result = sanitize_dn_component('test+value')
        assert '+' not in result

    def test_sanitize_removes_quotes(self):
        """Les guillemets sont supprimes."""
        from core.security import sanitize_dn_component
        result = sanitize_dn_component('"admin"')
        assert '"' not in result

    def test_sanitize_removes_angle_brackets(self):
        """Les symboles < et > sont supprimes."""
        from core.security import sanitize_dn_component
        result = sanitize_dn_component('<script>')
        assert '<' not in result
        assert '>' not in result

    def test_sanitize_removes_semicolon(self):
        """Le point-virgule est supprime."""
        from core.security import sanitize_dn_component
        result = sanitize_dn_component('value;injection')
        assert ';' not in result

    def test_sanitize_removes_equals(self):
        """Le signe = est supprime."""
        from core.security import sanitize_dn_component
        result = sanitize_dn_component('CN=Users')
        assert '=' not in result

    def test_sanitize_removes_newlines(self):
        """Les retours a la ligne sont supprimes."""
        from core.security import sanitize_dn_component
        result = sanitize_dn_component('line1\nline2\rline3')
        assert '\n' not in result
        assert '\r' not in result

    def test_sanitize_strips_whitespace(self):
        """Les espaces en debut et fin sont supprimes."""
        from core.security import sanitize_dn_component
        result = sanitize_dn_component('  Users  ')
        assert result == 'Users'

    def test_sanitize_empty_string(self):
        """Une chaine vide retourne une chaine vide."""
        from core.security import sanitize_dn_component
        result = sanitize_dn_component('')
        assert result == ''

    def test_sanitize_none(self):
        """Une valeur None retourne None sans lever d'exception."""
        from core.security import sanitize_dn_component
        result = sanitize_dn_component(None)
        assert result is None

    def test_sanitize_all_forbidden_chars(self):
        """Tous les caracteres interdits sont supprimes simultanement."""
        from core.security import sanitize_dn_component
        forbidden = '\\,+"<>;=\n\r'
        result = sanitize_dn_component(forbidden)
        assert result == ''


# =============================================================================
# TESTS : RATE LIMITING
# =============================================================================

class TestRateLimiting:
    """Tests pour les fonctions de rate limiting."""

    def test_check_rate_limit_first_attempt(self, reset_rate_limits):
        """La premiere tentative d'une IP est toujours autorisee."""
        from core.security import check_rate_limit
        allowed, remaining, attempts_left = check_rate_limit('192.168.1.1')
        assert allowed is True
        assert attempts_left == 5

    def test_record_attempt_increments(self, reset_rate_limits):
        """Chaque tentative echouee incremente le compteur."""
        from core.security import check_rate_limit, record_attempt
        ip = '10.0.0.1'

        record_attempt(ip)
        allowed, _, attempts_left = check_rate_limit(ip)
        assert attempts_left == 4

        record_attempt(ip)
        allowed, _, attempts_left = check_rate_limit(ip)
        assert attempts_left == 3

    def test_rate_limit_blocks_after_max_attempts(self, reset_rate_limits):
        """Apres 5 tentatives, l'IP est bloquee."""
        from core.security import check_rate_limit, record_attempt
        ip = '172.16.0.1'

        # 5 tentatives echouees
        for _ in range(5):
            record_attempt(ip)

        allowed, remaining, attempts_left = check_rate_limit(ip)
        assert allowed is False
        assert attempts_left == 0
        assert remaining > 0

    def test_successful_attempt_resets_counter(self, reset_rate_limits):
        """Une tentative reussie reinitialise le compteur."""
        from core.security import check_rate_limit, record_attempt
        ip = '192.168.1.100'

        # 3 tentatives echouees
        for _ in range(3):
            record_attempt(ip)

        # Une tentative reussie
        record_attempt(ip, success=True)

        # Le compteur doit etre reinitialise
        allowed, _, attempts_left = check_rate_limit(ip)
        assert allowed is True
        assert attempts_left == 5

    def test_rate_limit_window_expires(self, reset_rate_limits):
        """Apres expiration de la fenetre, le compteur est reinitialise."""
        from core.security import check_rate_limit, record_attempt
        ip = '10.10.10.10'

        # 5 tentatives echouees
        for _ in range(5):
            record_attempt(ip)

        # Avancer le temps de 15 minutes (900 secondes + 1)
        with patch('core.security.time.time', return_value=time.time() + 901):
            allowed, _, attempts_left = check_rate_limit(ip)
            assert allowed is True
            assert attempts_left == 5

    def test_rate_limit_with_action(self, reset_rate_limits):
        """Le rate limiting par action est independant du rate limiting global."""
        from core.security import check_rate_limit, record_attempt
        ip = '192.168.2.1'
        action = 'delete_user'

        # 5 tentatives sur l'action
        for _ in range(5):
            record_attempt(ip, action=action)

        # L'action est bloquee
        allowed_action, _, _ = check_rate_limit(ip, action=action)
        assert allowed_action is False

        # Mais le login global est toujours autorise
        allowed_global, _, _ = check_rate_limit(ip)
        assert allowed_global is True

    def test_get_rate_limit_status_no_attempts(self, reset_rate_limits):
        """Le statut sans tentatives montre 0 tentatives."""
        from core.security import get_rate_limit_status
        status = get_rate_limit_status('1.2.3.4')
        assert status['limited'] is False
        assert status['attempts'] == 0
        assert status['max_attempts'] == 5
        assert status['remaining_time'] == 0

    def test_get_rate_limit_status_with_attempts(self, reset_rate_limits):
        """Le statut avec tentatives montre le bon nombre."""
        from core.security import record_attempt, get_rate_limit_status
        ip = '5.6.7.8'

        for _ in range(3):
            record_attempt(ip)

        status = get_rate_limit_status(ip)
        assert status['attempts'] == 3
        assert status['limited'] is False

    def test_cleanup_old_attempts(self, reset_rate_limits):
        """Les anciennes tentatives sont nettoyees apres 15 minutes."""
        from core.security import record_attempt, _login_attempts, _cleanup_old_attempts

        ip = '192.168.50.1'
        record_attempt(ip)

        # Simuler un temps ancien pour forcer le nettoyage
        with patch('core.security.time.time', return_value=time.time() + 1000):
            _cleanup_old_attempts()

        # La tentative ancienne doit etre supprimee
        assert ip not in _login_attempts

    def test_rate_limit_custom_max_attempts(self, reset_rate_limits):
        """Le rate limiting respecte un maximum d'essais personnalise."""
        from core.security import check_rate_limit, record_attempt
        ip = '10.20.30.40'

        # 3 tentatives
        for _ in range(3):
            record_attempt(ip)

        # Verifier avec max_attempts=3 (doit etre bloque)
        allowed, _, _ = check_rate_limit(ip, max_attempts=3)
        assert allowed is False

        # Verifier avec max_attempts=5 (doit etre autorise)
        allowed, _, _ = check_rate_limit(ip, max_attempts=5)
        assert allowed is True


# =============================================================================
# TESTS : RATE LIMIT DECORATORS
# =============================================================================

class TestRateLimitDecorators:
    """Tests pour les decorateurs de rate limiting."""

    @patch('core.security.request')
    def test_rate_limit_decorator_allows_request(self, mock_request, reset_rate_limits):
        """Le decorateur rate_limit laisse passer les requetes sous la limite."""
        from core.security import rate_limit
        mock_request.remote_addr = '127.0.0.1'
        mock_request.is_json = False
        mock_request.endpoint = 'main.index'
        mock_request.method = 'GET'

        @rate_limit(max_attempts=5, window_seconds=60)
        def test_view():
            return 'OK'

        result = test_view()
        assert result == 'OK'

    @patch('core.security.request')
    def test_rate_limit_decorator_blocks_json(self, mock_request, reset_rate_limits):
        """Le decorateur retourne une reponse JSON 429 quand bloque."""
        from core.security import rate_limit, record_attempt
        mock_request.remote_addr = '127.0.0.1'
        mock_request.is_json = True
        mock_request.endpoint = 'api.test'
        mock_request.method = 'POST'

        # Bloquer l'IP
        for _ in range(5):
            record_attempt('127.0.0.1')

        @rate_limit(max_attempts=5, window_seconds=60)
        def test_view():
            return 'OK'

        response, status_code = test_view()
        assert status_code == 429
        assert response.get_json()['success'] is False
        assert 'retry_after' in response.get_json()

    def test_rate_limit_api_decorator(self):
        """Le decorateur rate_limit_api existe et est callable."""
        from core.security import rate_limit_api
        assert callable(rate_limit_api)

    def test_rate_limit_sensitive_decorator(self):
        """Le decorateur rate_limit_sensitive existe et est callable."""
        from core.security import rate_limit_sensitive
        assert callable(rate_limit_sensitive)


# =============================================================================
# TESTS : PASSWORD VALIDATION
# =============================================================================

class TestPasswordValidation:
    """Tests pour la validation des mots de passe."""

    def test_valid_strong_password(self):
        """Un mot de passe avec majuscule, minuscule, chiffre et special est valide."""
        from core.security import validate_password_strength
        valid, message = validate_password_strength('MyP@ssw0rd!')
        assert valid is True
        assert 'valide' in message.lower()

    def test_password_too_short(self):
        """Un mot de passe de moins de 8 caracteres est rejete."""
        from core.security import validate_password_strength
        valid, message = validate_password_strength('Ab1!')
        assert valid is False
        assert '8 caracteres' in message

    def test_password_no_uppercase(self):
        """Un mot de passe sans majuscule a un score de complexite reduit."""
        from core.security import validate_password_strength
        # lowercase + digit + special = 3/4, donc valide
        valid, message = validate_password_strength('my password1!')
        # lowercase, digit, special = 3 >= 3, donc valide
        assert valid is True

    def test_password_no_lowercase(self):
        """Un mot de passe sans minuscule mais avec 3 autres criteres est valide."""
        from core.security import validate_password_strength
        valid, message = validate_password_strength('MY PASSWORD1!')
        assert valid is True

    def test_password_no_digit(self):
        """Un mot de passe sans chiffre mais avec 3 autres criteres est valide."""
        from core.security import validate_password_strength
        valid, message = validate_password_strength('MyPassword!@#')
        assert valid is True

    def test_password_no_special(self):
        """Un mot de passe sans caractere special mais avec 3 autres criteres est valide."""
        from core.security import validate_password_strength
        valid, message = validate_password_strength('MyPassword123')
        assert valid is True

    def test_password_only_two_criteria(self):
        """Un mot de passe avec seulement 2 criteres est rejete."""
        from core.security import validate_password_strength
        # Seulement lowercase + digits (pas de majuscule, pas de special)
        valid, message = validate_password_strength('mylowercase123')
        assert valid is False
        assert '3 des elements' in message

    def test_password_empty(self):
        """Un mot de passe vide est rejete."""
        from core.security import validate_password_strength
        valid, message = validate_password_strength('')
        assert valid is False
        assert 'requis' in message.lower()

    def test_password_none(self):
        """Un mot de passe None est rejete."""
        from core.security import validate_password_strength
        valid, message = validate_password_strength(None)
        assert valid is False

    def test_password_custom_min_length(self):
        """Un mot de passe valide avec une longueur minimale personnalisee."""
        from core.security import validate_password_strength
        valid, message = validate_password_strength('Ab1!xyz', min_length=6)
        assert valid is True

    def test_password_very_long(self):
        """Un mot de passe tres long et complexe est valide."""
        from core.security import validate_password_strength
        long_pwd = 'A' * 100 + 'b1!'
        valid, message = validate_password_strength(long_pwd)
        assert valid is True

    def test_get_password_requirements(self):
        """Les exigences de mot de passe sont retournees avec la bonne structure."""
        from core.security import get_password_requirements
        reqs = get_password_requirements()
        assert reqs['min_length'] == 8
        assert reqs['require_uppercase'] is True
        assert reqs['require_lowercase'] is True
        assert reqs['require_digit'] is True
        assert reqs['require_special'] is True
        assert reqs['min_complexity'] == 3


# =============================================================================
# TESTS : SECURITY HEADERS
# =============================================================================

class TestSecurityHeaders:
    """Tests pour l'ajout de headers de securite HTTP."""

    @patch('core.security.request')
    @patch('core.security.os.environ', {'SESSION_COOKIE_SECURE': 'true'})
    def test_add_security_headers_basic(self, mock_request):
        """Les headers de securite standards sont ajoutes."""
        from core.security import add_security_headers
        mock_request.is_secure = False
        mock_request.endpoint = 'main.index'

        response = MagicMock()
        response.headers = {}

        result = add_security_headers(response)

        assert result.headers['X-Frame-Options'] == 'SAMEORIGIN'
        assert result.headers['X-Content-Type-Options'] == 'nosniff'
        assert result.headers['X-XSS-Protection'] == '1; mode=block'
        assert result.headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'
        assert 'Permissions-Policy' in result.headers
        assert 'Content-Security-Policy' in result.headers

    @patch('core.security.request')
    @patch('core.security.os.environ', {'SESSION_COOKIE_SECURE': 'true'})
    def test_hsts_header_when_secure(self, mock_request):
        """Le header HSTS est ajoute quand la connexion est consideree secure."""
        from core.security import add_security_headers
        mock_request.is_secure = True
        mock_request.endpoint = 'main.index'

        response = MagicMock()
        response.headers = {}

        result = add_security_headers(response)

        assert 'Strict-Transport-Security' in result.headers
        assert 'max-age=31536000' in result.headers['Strict-Transport-Security']

    @patch('core.security.request')
    @patch('core.security.os.environ', {'SESSION_COOKIE_SECURE': 'false'})
    def test_no_hsts_when_not_secure(self, mock_request):
        """Le header HSTS n'est pas ajoute si la connexion n'est pas secure."""
        from core.security import add_security_headers
        mock_request.is_secure = False
        mock_request.endpoint = 'main.index'

        response = MagicMock()
        response.headers = {}

        result = add_security_headers(response)

        # HSTS ne doit pas etre present si SESSION_COOKIE_SECURE=false et non secure
        assert 'Strict-Transport-Security' not in result.headers

    @patch('core.security.request')
    @patch('core.security.os.environ', {'SESSION_COOKIE_SECURE': 'true'})
    def test_cache_control_for_sensitive_pages(self, mock_request):
        """Les pages sensibles ont des headers Cache-Control."""
        from core.security import add_security_headers

        sensitive_endpoints = ['connect', 'dashboard', 'users', 'groups']

        for endpoint in sensitive_endpoints:
            mock_request.is_secure = False
            mock_request.endpoint = endpoint

            response = MagicMock()
            response.headers = {}

            result = add_security_headers(response)

            assert result.headers['Cache-Control'] == 'no-store, no-cache, must-revalidate, max-age=0'
            assert result.headers['Pragma'] == 'no-cache'

    @patch('core.security.request')
    @patch('core.security.os.environ', {'SESSION_COOKIE_SECURE': 'true'})
    def test_no_cache_control_for_normal_pages(self, mock_request):
        """Les pages normales n'ont pas de headers Cache-Control restrictifs."""
        from core.security import add_security_headers
        mock_request.is_secure = False
        mock_request.endpoint = 'main.index'

        response = MagicMock()
        response.headers = {}

        result = add_security_headers(response)

        assert 'Cache-Control' not in result.headers
        assert 'Pragma' not in result.headers

    @patch('core.security.request')
    def test_permissions_policy_restricts_apis(self, mock_request):
        """Le header Permissions-Policy restreint les APIs navigateur."""
        from core.security import add_security_headers
        mock_request.is_secure = False
        mock_request.endpoint = 'main.index'

        response = MagicMock()
        response.headers = {}

        result = add_security_headers(response)

        policy = result.headers['Permissions-Policy']
        assert 'geolocation=()' in policy
        assert 'microphone=()' in policy
        assert 'camera=()' in policy

    @patch('core.security.request')
    def test_content_security_policy(self, mock_request):
        """Le header CSP autorise self et CDN jsdelivr."""
        from core.security import add_security_headers
        mock_request.is_secure = False
        mock_request.endpoint = 'main.index'

        response = MagicMock()
        response.headers = {}

        result = add_security_headers(response)

        csp = result.headers['Content-Security-Policy']
        assert "default-src 'self'" in csp
        assert 'cdn.jsdelivr.net' in csp

    @patch('core.security.request')
    def test_response_is_returned(self, mock_request):
        """La fonction retourne l'objet response modifie."""
        from core.security import add_security_headers
        mock_request.is_secure = False
        mock_request.endpoint = 'main.index'

        response = MagicMock()
        response.headers = {}

        result = add_security_headers(response)

        assert result is response


# =============================================================================
# TESTS : SESSION CONFIG
# =============================================================================

class TestSessionConfig:
    """Tests pour la configuration de session securisee."""

    def test_session_config_default(self):
        """La config par defaut a SESSION_COOKIE_SECURE=false."""
        from core.security import get_secure_session_config
        # S'assurer que la variable d'environnement n'est pas positionnee
        old_val = os.environ.pop('SESSION_COOKIE_SECURE', None)
        try:
            config = get_secure_session_config()
            assert config['SESSION_COOKIE_SECURE'] is False
            assert config['SESSION_COOKIE_HTTPONLY'] is True
            assert config['SESSION_COOKIE_SAMESITE'] == 'Lax'
            assert config['SESSION_COOKIE_NAME'] == 'ad_session'
            assert config['PERMANENT_SESSION_LIFETIME'] == 7200
        finally:
            if old_val is not None:
                os.environ['SESSION_COOKIE_SECURE'] = old_val

    def test_session_config_secure_enabled(self):
        """SESSION_COOKIE_SECURE=true quand la variable d'environnement est true."""
        old_val = os.environ.get('SESSION_COOKIE_SECURE')
        os.environ['SESSION_COOKIE_SECURE'] = 'true'
        try:
            # Recharger le module pour lire la nouvelle variable
            from core import security
            reload(security)
            config = security.get_secure_session_config()
            assert config['SESSION_COOKIE_SECURE'] is True
        finally:
            if old_val is not None:
                os.environ['SESSION_COOKIE_SECURE'] = old_val
            else:
                os.environ.pop('SESSION_COOKIE_SECURE', None)
            # Restaurer le module
            from core import security
            reload(security)

    def test_session_config_secure_disabled_explicit(self):
        """SESSION_COOKIE_SECURE=false quand la variable est explicitement false."""
        old_val = os.environ.get('SESSION_COOKIE_SECURE')
        os.environ['SESSION_COOKIE_SECURE'] = 'false'
        try:
            from core import security
            reload(security)
            config = security.get_secure_session_config()
            assert config['SESSION_COOKIE_SECURE'] is False
        finally:
            if old_val is not None:
                os.environ['SESSION_COOKIE_SECURE'] = old_val
            else:
                os.environ.pop('SESSION_COOKIE_SECURE', None)
            from core import security
            reload(security)


# =============================================================================
# TESTS : CSRF PROTECTION
# =============================================================================

class TestCSRF:
    """Tests pour la protection CSRF."""

    def test_generate_csrf_token_creates_token(self, flask_session_mock):
        """generate_csrf_token cree un token et le stocke en session."""
        from core.security import generate_csrf_token

        assert 'csrf_token' not in flask_session_mock

        token = generate_csrf_token()

        assert token is not None
        assert len(token) > 0
        assert 'csrf_token' in flask_session_mock
        assert flask_session_mock['csrf_token'] == token

    def test_generate_csrf_token_returns_existing(self, flask_session_mock):
        """generate_csrf_token retourne le token existant s'il est deja present."""
        from core.security import generate_csrf_token

        flask_session_mock['csrf_token'] = 'existing_token_value'

        token = generate_csrf_token()

        assert token == 'existing_token_value'

    def test_generate_csrf_token_is_hex(self, flask_session_mock):
        """Le token CSRF est une chaine hexadecimale de 64 caracteres (32 bytes)."""
        from core.security import generate_csrf_token
        import re

        token = generate_csrf_token()

        # 32 bytes = 64 caracteres hex
        assert re.match(r'^[0-9a-f]{64}$', token)

    def test_generate_csrf_token_is_random(self, flask_session_mock):
        """Chaque appel a generate_csrf_token sur une nouvelle session donne un token unique."""
        from core.security import generate_csrf_token

        # Premier token
        token1 = generate_csrf_token()

        # Simuler une nouvelle session vide
        flask_session_mock.clear()

        # Deuxieme token
        token2 = generate_csrf_token()

        assert token1 != token2

    def test_validate_csrf_token_valid(self, flask_session_mock):
        """Un token valide retourne True."""
        from core.security import generate_csrf_token, validate_csrf_token

        token = generate_csrf_token()
        result = validate_csrf_token(token)

        assert result is True

    def test_validate_csrf_token_invalid(self, flask_session_mock):
        """Un token incorrect retourne False."""
        from core.security import generate_csrf_token, validate_csrf_token

        generate_csrf_token()
        result = validate_csrf_token('wrong_token_value')

        assert result is False

    def test_validate_csrf_token_empty(self, flask_session_mock):
        """Un token vide retourne False."""
        from core.security import generate_csrf_token, validate_csrf_token

        generate_csrf_token()
        result = validate_csrf_token('')

        assert result is False

    def test_validate_csrf_token_none(self, flask_session_mock):
        """Un token None retourne False."""
        from core.security import generate_csrf_token, validate_csrf_token

        generate_csrf_token()
        result = validate_csrf_token(None)

        assert result is False

    def test_validate_csrf_token_no_session_token(self, flask_session_mock):
        """Valider un token sans token en session retourne False."""
        from core.security import validate_csrf_token

        result = validate_csrf_token('some_token')

        assert result is False


# =============================================================================
# TESTS : CSRF PROTECT DECORATOR
# =============================================================================

class TestCSRFProtectDecorator:
    """Tests pour le decorateur csrf_protect."""

    @patch('core.security.request')
    def test_csrf_protect_allows_get(self, mock_request, flask_session_mock):
        """Les requetes GET ne sont pas verifiees pour le CSRF."""
        from core.security import csrf_protect
        mock_request.method = 'GET'

        @csrf_protect()
        def test_view():
            return 'OK'

        result = test_view()
        assert result == 'OK'

    @patch('core.security.request')
    def test_csrf_protect_allows_valid_token(self, mock_request, flask_session_mock):
        """Une requete POST avec un token valide est acceptee."""
        from core.security import csrf_protect, generate_csrf_token
        mock_request.method = 'POST'
        mock_request.is_json = False

        token = generate_csrf_token()
        mock_request.form = {'csrf_token': token}

        @csrf_protect()
        def test_view():
            return 'OK'

        result = test_view()
        assert result == 'OK'

    @patch('core.security.request')
    def test_csrf_protect_rejects_invalid_token(self, mock_request, flask_session_mock):
        """Une requete POST avec un token invalide retourne 403."""
        from core.security import csrf_protect, generate_csrf_token
        mock_request.method = 'POST'
        mock_request.is_json = False

        generate_csrf_token()
        mock_request.form = {'csrf_token': 'wrong_token'}

        @csrf_protect()
        def test_view():
            return 'OK'

        response, status_code = test_view()
        assert status_code == 403
        assert response.get_json()['success'] is False
        assert 'CSRF' in response.get_json()['error']

    @patch('core.security.request')
    def test_csrf_protect_rejects_missing_token(self, mock_request, flask_session_mock):
        """Une requete POST sans token retourne 403."""
        from core.security import csrf_protect, generate_csrf_token
        mock_request.method = 'POST'
        mock_request.is_json = False
        mock_request.form = {}

        generate_csrf_token()

        @csrf_protect()
        def test_view():
            return 'OK'

        response, status_code = test_view()
        assert status_code == 403

    @patch('core.security.request')
    def test_csrf_protect_accepts_header_token(self, mock_request, flask_session_mock):
        """Le token CSRF peut etre passe via le header X-CSRF-Token."""
        from core.security import csrf_protect, generate_csrf_token
        mock_request.method = 'POST'
        mock_request.is_json = False
        mock_request.form = {}

        token = generate_csrf_token()
        mock_request.headers = {'X-CSRF-Token': token}

        @csrf_protect()
        def test_view():
            return 'OK'

        result = test_view()
        assert result == 'OK'

    @patch('core.security.request')
    def test_csrf_protect_protects_put(self, mock_request, flask_session_mock):
        """Les requetes PUT sont protegees par CSRF."""
        from core.security import csrf_protect, generate_csrf_token
        mock_request.method = 'PUT'
        mock_request.is_json = False
        mock_request.form = {}

        generate_csrf_token()

        @csrf_protect()
        def test_view():
            return 'OK'

        response, status_code = test_view()
        assert status_code == 403

    @patch('core.security.request')
    def test_csrf_protect_protects_delete(self, mock_request, flask_session_mock):
        """Les requetes DELETE sont protegees par CSRF."""
        from core.security import csrf_protect, generate_csrf_token
        mock_request.method = 'DELETE'
        mock_request.is_json = False
        mock_request.form = {}

        generate_csrf_token()

        @csrf_protect()
        def test_view():
            return 'OK'

        response, status_code = test_view()
        assert status_code == 403

    @patch('core.security.request')
    def test_csrf_protect_protects_patch(self, mock_request, flask_session_mock):
        """Les requetes PATCH sont protegees par CSRF."""
        from core.security import csrf_protect, generate_csrf_token
        mock_request.method = 'PATCH'
        mock_request.is_json = False
        mock_request.form = {}

        generate_csrf_token()

        @csrf_protect()
        def test_view():
            return 'OK'

        response, status_code = test_view()
        assert status_code == 403


# =============================================================================
# TESTS : CONSTANTS AND MODULE STRUCTURE
# =============================================================================

class TestModuleStructure:
    """Tests pour verifier la structure du module security."""

    def test_ldap_escape_chars_defined(self):
        """La constante LDAP_ESCAPE_CHARS est definie et contient les bons caracteres."""
        from core.security import LDAP_ESCAPE_CHARS
        assert isinstance(LDAP_ESCAPE_CHARS, dict)
        assert '\\' in LDAP_ESCAPE_CHARS
        assert '*' in LDAP_ESCAPE_CHARS
        assert '(' in LDAP_ESCAPE_CHARS
        assert ')' in LDAP_ESCAPE_CHARS
        assert '\x00' in LDAP_ESCAPE_CHARS
        assert '/' in LDAP_ESCAPE_CHARS

    def test_all_public_functions_exist(self):
        """Toutes les fonctions publiques du module existent."""
        from core import security

        expected_functions = [
            'escape_ldap_filter',
            'sanitize_dn_component',
            'check_rate_limit',
            'record_attempt',
            'get_rate_limit_status',
            'rate_limit',
            'rate_limit_api',
            'rate_limit_sensitive',
            'validate_password_strength',
            'get_password_requirements',
            'add_security_headers',
            'get_secure_session_config',
            'generate_csrf_token',
            'validate_csrf_token',
            'csrf_protect',
        ]

        for func_name in expected_functions:
            assert hasattr(security, func_name)
            assert callable(getattr(security, func_name))


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
