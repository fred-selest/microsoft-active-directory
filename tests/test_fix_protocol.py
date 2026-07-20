# -*- coding: utf-8 -*-
"""
Tests de la route /api/fix-protocol (câblage protocoles hérités -> scripts).
"""
import os
from pathlib import Path

import pytest

os.environ.setdefault('SECRET_KEY', 'test-fix-protocol')
os.environ.setdefault('FLASK_ENV', 'production')

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def client():
    from app import app
    app.config['TESTING'] = True
    return app.test_client()


def _login_admin(c):
    with c.session_transaction() as s:
        s['ad_server'] = 'dc.demo.local'
        s['ad_username'] = 'DEMO\\admin'
        s['ad_password'] = 'x'
        s['ad_base_dn'] = 'DC=demo,DC=local'
        s['user_role'] = 'admin'
        s['user_groups'] = ['Administrateurs du domaine']


# --- Contrôle d'accès -------------------------------------------------------

def test_refuse_sans_connexion(client):
    r = client.post('/api/fix-protocol', json={'item': 'SMBv1'})
    assert r.status_code in (401, 403)


def test_refuse_sans_permission(client):
    """Un utilisateur sans system:execute_script ne doit pas pouvoir déclencher."""
    with client.session_transaction() as s:
        s['ad_server'] = 'dc.demo.local'; s['ad_username'] = 'DEMO\\bob'
        s['ad_password'] = 'x'; s['ad_base_dn'] = 'DC=demo,DC=local'
        s['user_role'] = 'reader'; s['user_groups'] = ['Utilisateurs du domaine']
    r = client.post('/api/fix-protocol', json={'item': 'SMBv1'})
    assert r.status_code == 403


# --- Validation de l'entrée -------------------------------------------------

def test_protocole_inconnu_rejete(client):
    _login_admin(client)
    r = client.post('/api/fix-protocol', json={'item': 'télépathie'})
    assert r.status_code == 400
    assert 'non reconnu' in r.get_json()['error'].lower()


def test_item_vide_rejete(client):
    _login_admin(client)
    r = client.post('/api/fix-protocol', json={})
    assert r.status_code == 400


def test_le_client_ne_choisit_pas_le_script(client):
    """Envoyer un nom de script arbitraire ne doit pas l'exécuter : seul un
    identifiant de protocole connu est accepté (mapping serveur)."""
    _login_admin(client)
    r = client.post('/api/fix-protocol', json={'item': 'fix_smbv1.ps1'})
    # 'fix_smbv1.ps1' n'est PAS une clé de protocole -> rejeté
    assert r.status_code == 400
    assert 'non reconnu' in r.get_json()['error'].lower()


def test_protocole_connu_resout_le_script(client):
    """Un protocole connu passe la validation d'entrée et atteint l'exécution.
    Sous Linux (pas de PowerShell), l'échec attendu est 'prérequis', PAS
    'protocole non reconnu' — ce qui prouve que le mapping a résolu le script."""
    _login_admin(client)
    r = client.post('/api/fix-protocol', json={'item': 'SMBv1'})
    body = r.get_json()
    # soit prérequis non satisfaits (Linux), soit exécution tentée (Windows) :
    # dans tous les cas, ce n'est pas un rejet 'protocole non reconnu'.
    assert 'non reconnu' not in (body.get('error') or '').lower()
