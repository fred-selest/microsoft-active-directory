# -*- coding: utf-8 -*-
"""
Tests de la protection CSRF globale (constat É3).
"""
import os
import re

import pytest

os.environ.setdefault('SECRET_KEY', 'test-csrf-global')
os.environ.setdefault('FLASK_ENV', 'production')


@pytest.fixture
def client():
    from app import app
    app.config['TESTING'] = True
    return app.test_client()


def _token(client):
    r = client.get('/connect')
    m = re.search(rb'name="csrf-token" content="([^"]+)"', r.data)
    return m.group(1).decode() if m else None


def test_meta_token_present(client):
    r = client.get('/connect')
    assert b'name="csrf-token"' in r.data


def test_post_sans_token_refuse(client):
    _token(client)  # établit une session avec un jeton
    r = client.post('/tools/favorites/toggle', json={})
    assert r.status_code == 403
    assert 'csrf' in r.get_json()['error'].lower()


def test_post_avec_header_token_passe_csrf(client):
    tok = _token(client)
    # Le jeton passe le CSRF ; l'auth en aval renvoie 401 (non 403 CSRF).
    r = client.post('/tools/favorites/toggle', json={}, headers={'X-CSRFToken': tok})
    assert r.status_code != 403


def test_login_post_sans_token_refuse(client):
    _token(client)
    r = client.post('/connect', data={'server': 'x', 'username': 'y', 'password': 'z'})
    assert r.status_code == 403


def test_login_post_avec_token_nest_pas_bloque_csrf(client):
    tok = _token(client)
    r = client.post('/connect', data={'csrf_token': tok, 'server': 'x',
                                      'username': 'y', 'password': 'z'})
    # La connexion échoue (serveur bidon) mais ce n'est pas un 403 CSRF.
    assert r.status_code != 403


def test_get_non_protege(client):
    r = client.get('/connect')
    assert r.status_code == 200


def test_json_body_token_accepte(client):
    tok = _token(client)
    r = client.post('/tools/favorites/toggle', json={'csrf_token': tok})
    assert r.status_code != 403
