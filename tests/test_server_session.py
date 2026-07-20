# -*- coding: utf-8 -*-
"""
Tests des sessions côté serveur (constat C4).
"""
import os
from pathlib import Path

import pytest

os.environ.setdefault('SECRET_KEY', 'test-server-session')
os.environ.setdefault('FLASK_ENV', 'production')

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def client():
    from app import app
    app.config['TESTING'] = True
    return app.test_client()


def test_cookie_ne_contient_pas_les_donnees(client):
    r = client.get('/connect')
    cookie = r.headers.get('Set-Cookie', '')
    assert 'ad_session=' in cookie
    val = cookie.split('ad_session=')[1].split(';')[0]
    # Un cookie Flask signé classique embarque les données (base64 long) ;
    # ici c'est un identifiant opaque, donc court.
    assert len(val) < 200
    assert 'password' not in cookie.lower()


def test_fichier_session_cree_cote_serveur(client):
    client.get('/connect')
    sessdir = PROJECT_ROOT / 'data' / 'sessions'
    assert sessdir.exists()
    assert list(sessdir.glob('sess_*')), "aucun fichier de session serveur créé"


def test_persistance_entre_requetes(client):
    """Le jeton CSRF généré à la 1re requête doit être valide à la 2e —
    preuve que la session serveur persiste via le cookie d'identifiant."""
    import re
    r = client.get('/connect')
    tok = re.search(rb'name="csrf-token" content="([^"]+)"', r.data).group(1).decode()
    # 2e requête (même client = même cookie) : le POST avec ce jeton passe le CSRF
    r2 = client.post('/tools/favorites/toggle', json={}, headers={'X-CSRFToken': tok})
    assert r2.status_code != 403  # pas un rejet CSRF -> la session a persisté


def test_cookie_falsifie_rejete(client):
    """Un identifiant de session non signé/falsifié ne doit pas être accepté."""
    client.set_cookie('ad_session', 'valeur-falsifiee-non-signee')
    r = client.get('/connect')
    # L'app repart sur une session vierge (pas d'erreur 500) et pose un nouveau cookie.
    assert r.status_code == 200
