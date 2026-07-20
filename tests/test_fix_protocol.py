# -*- coding: utf-8 -*-
"""
Tests de la route /api/fix-protocol (câblage protocoles hérités -> scripts).
"""
import os

import pytest

os.environ.setdefault('SECRET_KEY', 'test-fix-protocol')
os.environ.setdefault('FLASK_ENV', 'production')

TEST_CSRF = 'jeton-csrf-de-test-fixe'


@pytest.fixture
def client():
    from app import app
    app.config['TESTING'] = True
    return app.test_client()


def _set_session(c, **extra):
    """Injecte un jeton CSRF connu (protection globale É3) + champs de session."""
    with c.session_transaction() as s:
        s['csrf_token'] = TEST_CSRF
        s.update(extra)


def _admin_session(c):
    _set_session(c, ad_server='dc.demo.local', ad_username='DEMO\\admin',
                 ad_password='x', ad_base_dn='DC=demo,DC=local',
                 user_role='admin', user_groups=['Administrateurs du domaine'])


def _post(c, url, **kwargs):
    """POST avec en-tête CSRF valide."""
    headers = kwargs.pop('headers', {})
    headers['X-CSRFToken'] = TEST_CSRF
    return c.post(url, headers=headers, **kwargs)


# --- Contrôle d'accès -------------------------------------------------------

def test_refuse_sans_connexion(client):
    _set_session(client)  # jeton CSRF mais pas de connexion
    r = _post(client, '/api/fix-protocol', json={'item': 'SMBv1'})
    assert r.status_code in (401, 403)


def test_refuse_sans_permission(client):
    _set_session(client, ad_server='dc.demo.local', ad_username='DEMO\\bob',
                 ad_password='x', ad_base_dn='DC=demo,DC=local',
                 user_role='reader', user_groups=['Utilisateurs du domaine'])
    r = _post(client, '/api/fix-protocol', json={'item': 'SMBv1'})
    assert r.status_code == 403


# --- CSRF -------------------------------------------------------------------

def test_refuse_sans_jeton_csrf(client):
    _admin_session(client)
    r = client.post('/api/fix-protocol', json={'item': 'SMBv1'})  # sans en-tête
    assert r.status_code == 403


# --- Validation de l'entrée -------------------------------------------------

def test_protocole_inconnu_rejete(client):
    _admin_session(client)
    r = _post(client, '/api/fix-protocol', json={'item': 'télépathie'})
    assert r.status_code == 400
    assert 'non reconnu' in r.get_json()['error'].lower()


def test_item_vide_rejete(client):
    _admin_session(client)
    r = _post(client, '/api/fix-protocol', json={})
    assert r.status_code == 400


def test_le_client_ne_choisit_pas_le_script(client):
    """Envoyer un nom de script arbitraire ne doit pas l'exécuter : seul un
    identifiant de protocole connu est accepté (mapping serveur)."""
    _admin_session(client)
    r = _post(client, '/api/fix-protocol', json={'item': 'fix_smbv1.ps1'})
    assert r.status_code == 400
    assert 'non reconnu' in r.get_json()['error'].lower()


def test_protocole_connu_resout_le_script(client):
    """Un protocole connu passe la validation d'entrée et atteint l'exécution.
    Sous Linux (pas de PowerShell), l'échec attendu est 'prérequis', PAS
    'protocole non reconnu' — ce qui prouve que le mapping a résolu le script."""
    _admin_session(client)
    r = _post(client, '/api/fix-protocol', json={'item': 'SMBv1'})
    body = r.get_json()
    assert 'non reconnu' not in (body.get('error') or '').lower()
