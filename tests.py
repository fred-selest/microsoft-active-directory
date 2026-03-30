#!/usr/bin/env python3
"""
Script de test pour l'Interface Web Active Directory.
Vérifie le bon fonctionnement de tous les modules.
"""

import os
import sys
import json
from datetime import datetime

# Charger .env avant tout
from dotenv import load_dotenv
load_dotenv('.env', override=True)

# Résultats des tests
results = {
    'timestamp': datetime.now().isoformat(),
    'version': '1.17.4',
    'tests': [],
    'passed': 0,
    'failed': 0,
    'warnings': 0
}

def test(name, func):
    """Exécuter un test et enregistrer le résultat."""
    try:
        result = func()
        if result[0]:
            results['passed'] += 1
            status = '✅ PASS'
        else:
            results['failed'] += 1
            status = '❌ FAIL'
        results['tests'].append({
            'name': name,
            'status': 'passed' if result[0] else 'failed',
            'message': result[1]
        })
        print(f"{status} - {name}: {result[1]}")
        return result[0]
    except Exception as e:
        results['failed'] += 1
        results['tests'].append({
            'name': name,
            'status': 'error',
            'message': str(e)
        })
        print(f"❌ ERROR - {name}: {e}")
        return False

def test_config():
    """Tester la configuration."""
    from config import Config
    checks = [
        Config.SECRET_KEY and len(Config.SECRET_KEY) >= 32,
        Config.RBAC_ENABLED == True,
        Config.DEFAULT_ROLE == 'reader'
    ]
    if all(checks):
        return True, "Configuration valide"
    return False, "Configuration invalide"

def test_security_ldap():
    """Tester l'échappement LDAP."""
    from security import escape_ldap_filter
    result = escape_ldap_filter('test*(user)')
    expected = 'test\\2a\\28user\\29'
    if result == expected:
        return True, f"Échappement correct: {result}"
    return False, f"Échappement incorrect: {result}"

def test_security_csrf():
    """Tester la génération de token CSRF."""
    from security import generate_csrf_token, validate_csrf_token
    from flask import Flask, session
    app = Flask(__name__)
    app.secret_key = os.environ.get('SECRET_KEY', 'test')
    with app.test_request_context('/'):
        token = generate_csrf_token()
        valid = validate_csrf_token(token)
    if valid and len(token) == 64:
        return True, f"Token CSRF valide: {token[:20]}..."
    return False, "Token CSRF invalide"

def test_crypto():
    """Tester le chiffrement de session."""
    from session_crypto import init_crypto, encrypt_password, decrypt_password
    init_crypto(os.environ.get('SECRET_KEY', 'test'))
    password = 'MonMotDePasse123!'
    encrypted = encrypt_password(password)
    decrypted = decrypt_password(encrypted)
    if decrypted == password:
        return True, f"Chiffrement OK (longueur: {len(encrypted)})"
    return False, "Déchiffrement échoué"

def test_translations():
    """Tester les traductions."""
    from translations import TRANSLATIONS
    langs = list(TRANSLATIONS.keys())
    if 'fr' in langs and 'en' in langs:
        return True, f"Langues: {', '.join(langs)}"
    return False, f"Langues manquantes: {langs}"

def test_audit():
    """Tester le module d'audit."""
    from audit import ACTIONS
    if len(ACTIONS) >= 15:
        return True, f"{len(ACTIONS)} actions définies"
    return False, f"Trop peu d'actions: {len(ACTIONS)}"

def test_routes_core():
    """Tester le module core des routes."""
    from routes.core import decode_ldap_value, ROLE_PERMISSIONS
    roles = list(ROLE_PERMISSIONS.keys())
    if 'admin' in roles and 'operator' in roles and 'reader' in roles:
        return True, f"Rôles: {', '.join(roles)}"
    return False, f"Rôles manquants: {roles}"

def test_app():
    """Tester l'application Flask."""
    from app import app
    if app.name == 'app':
        rules = [r.rule for r in app.url_map.iter_rules()]
        return True, f"{len(rules)} routes enregistrées"
    return False, "Application invalide"

def test_health_endpoint():
    """Tester l'endpoint de health."""
    import requests
    try:
        resp = requests.get('http://localhost:5000/api/health', timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'healthy':
                return True, f"Version: {data.get('version')}"
    except:
        pass
    return False, "Endpoint non accessible"

def test_update_endpoint():
    """Tester l'endpoint de mise à jour."""
    import requests
    try:
        resp = requests.get('http://localhost:5000/api/check-update', timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return True, f"Mise à jour: {data.get('update_available', False)}"
    except:
        pass
    return False, "Endpoint non accessible"

def test_homepage():
    """Tester la page d'accueil."""
    import requests
    try:
        resp = requests.get('http://localhost:5000/', timeout=5)
        if resp.status_code == 200 and 'Active Directory' in resp.text:
            return True, "Page d'accueil OK"
    except:
        pass
    return False, "Page non accessible"

def test_directories():
    """Tester les répertoires."""
    dirs = ['logs', 'data']
    missing = [d for d in dirs if not os.path.exists(d)]
    if not missing:
        return True, "Répertoires existants"
    return False, f"Manquants: {', '.join(missing)}"

def test_env_file():
    """Tester le fichier .env."""
    if os.path.exists('.env'):
        with open('.env', 'r') as f:
            content = f.read()
        if 'SECRET_KEY=' in content and len(content) > 50:
            return True, "Fichier .env valide"
    return False, "Fichier .env manquant ou invalide"

def test_dependencies():
    """Tester les dépendances."""
    deps = ['flask', 'ldap3', 'cryptography', 'dotenv', 'waitress', 'requests']
    missing = []
    for dep in deps:
        try:
            if dep == 'dotenv':
                __import__('dotenv')
            else:
                __import__(dep)
        except:
            missing.append(dep)
    if not missing:
        return True, f"{len(deps)} dépendances OK"
    return False, f"Manquantes: {', '.join(missing)}"

# Exécution des tests
if __name__ == '__main__':
    print("=" * 60)
    print(" TESTS - Interface Web Active Directory")
    print(f" Version: {results['version']}")
    print("=" * 60)
    print()
    
    # Tests unitaires
    test("Configuration", test_config)
    test("Échappement LDAP", test_security_ldap)
    test("Token CSRF", test_security_csrf)
    test("Chiffrement sessions", test_crypto)
    test("Traductions", test_translations)
    test("Module audit", test_audit)
    test("Routes core", test_routes_core)
    test("Application Flask", test_app)
    
    # Tests d'intégration (nécessitent serveur)
    print()
    print("--- Tests d'intégration ---")
    test("Endpoint /api/health", test_health_endpoint)
    test("Endpoint /api/check-update", test_update_endpoint)
    test("Page d'accueil /", test_homepage)
    
    # Tests de fichiers
    print()
    print("--- Tests de fichiers ---")
    test("Répertoires", test_directories)
    test("Fichier .env", test_env_file)
    test("Dépendances", test_dependencies)
    
    # Résumé
    print()
    print("=" * 60)
    total = results['passed'] + results['failed']
    print(f" RÉSULTATS: {results['passed']}/{total} tests passés")
    if results['failed'] > 0:
        print(f" ⚠️  {results['failed']} tests échoués")
    print("=" * 60)
    
    # Sauvegarder le rapport
    with open('logs/test_report.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n Rapport sauvegardé: logs/test_report.json")
    
    # Code de retour
    sys.exit(0 if results['failed'] == 0 else 1)
