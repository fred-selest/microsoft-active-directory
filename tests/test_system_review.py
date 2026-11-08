# -*- coding: utf-8 -*-
"""
Revue complète du système (v1.52.0) : contrôles d'accès manquants hors du
module Répertoires.

- /connect/fix-ldap-channel-binding exécutait, sans aucun compte, un script
  qui abaisse la sécurité LDAP du domaine et redémarre AD DS.
- Journal d'audit, audit des mots de passe (qui envoie des alertes par
  e-mail), alertes et pages d'outils n'exigeaient qu'une connexion.
- Gestionnaire de scripts : arguments et délai non validés ; nom de script
  non limité à la liste déclarée hors de la route API.
- Redirection vers l'en-tête Referer sans contrôle d'hôte.
"""
import os
import re

import pytest

os.environ.setdefault('SECRET_KEY', 'test-system-review')


@pytest.fixture
def app_client():
    from app import app
    app.config['TESTING'] = True
    return app.test_client()


def _csrf(client, url='/connect'):
    m = re.search(rb'name="csrf-token" content="([^"]+)"', client.get(url).data)
    return m.group(1).decode()


def _session(client, admin):
    from core.session_crypto import encrypt_password
    with client.session_transaction() as s:
        s.update(ad_server='dc', ad_username='CORP\\jdupont', ad_password=encrypt_password('x'),
                 ad_base_dn='DC=corp,DC=local',
                 user_role='admin' if admin else 'user',
                 user_groups=['Domain Admins'] if admin else ['Utilisateurs du domaine'])


class TestFixLdap:
    def _post(self, client, **data):
        tok = _csrf(client)
        return client.post('/connect/fix-ldap-channel-binding', data=dict(csrf_token=tok, **data))

    def test_sans_compte_administrateur_rien_n_est_execute(self, app_client, monkeypatch):
        import subprocess
        import core.windows_auth as wa
        from core import security
        monkeypatch.setattr(security, '_action_attempts', {})
        ran = []
        monkeypatch.setattr(subprocess, 'run', lambda *a, **k: ran.append(a))
        monkeypatch.setattr(wa, 'verify_local_admin', lambda u, p: (False, 'Identifiant ou mot de passe incorrect.'))
        r = self._post(app_client)
        assert r.status_code == 302 and not ran
        r = self._post(app_client, admin_username='CORP\\jdupont', admin_password='mauvais')
        assert not ran

    def test_administrateur_verifie(self, app_client, monkeypatch):
        import subprocess
        import core.windows_auth as wa
        from core import security
        monkeypatch.setattr(security, '_action_attempts', {})
        ran = []

        class Proc:
            returncode = 0
            stdout = 'SUCCESS'
            stderr = ''
        monkeypatch.setattr(subprocess, 'run', lambda *a, **k: ran.append(a) or Proc())
        monkeypatch.setattr(wa, 'verify_local_admin', lambda u, p: (u == 'CORP\\admin', None))
        monkeypatch.setattr(os.path, 'exists', lambda p: True)
        self._post(app_client, admin_username='CORP\\admin', admin_password='ok')
        assert len(ran) == 1

    def test_limitation_des_tentatives(self, app_client, monkeypatch):
        import core.windows_auth as wa
        from core import security
        monkeypatch.setattr(security, '_action_attempts', {})
        checks = []
        monkeypatch.setattr(wa, 'verify_local_admin', lambda u, p: checks.append(u) or (False, 'non'))
        for _ in range(8):
            self._post(app_client, admin_username='CORP\\admin', admin_password='x')
        assert len(checks) == 5

    def test_formulaire_demande_un_compte(self):
        src = open('templates/connect.html', encoding='utf-8').read()
        block = src.split("url_for('main.fix_ldap_channel_binding')")[1].split('</form>')[0]
        assert 'name="admin_username"' in block and 'name="admin_password"' in block

    def test_split_account(self):
        from core.windows_auth import split_account
        assert split_account('CORP\\admin') == ('CORP', 'admin')
        assert split_account('admin@corp.local') == (None, 'admin@corp.local')
        assert split_account('admin') == ('.', 'admin')

    def test_hors_windows(self, monkeypatch):
        import core.windows_auth as wa
        monkeypatch.setattr(wa.os, 'name', 'posix')
        assert wa.verify_local_admin('a', 'b')[0] is False


@pytest.mark.parametrize('method,url', [
    ('get', '/audit'),
    ('get', '/api/password-audit'),
    ('get', '/api/alerts'),
    ('post', '/api/alerts/x/delete'),
    ('post', '/api/alerts/x/acknowledge'),
    ('post', '/api/alerts/check'),
    ('get', '/alerts'),
    ('get', '/tools/locked-accounts'),
    ('get', '/tools/expiring'),
    ('get', '/tools/password-policy'),
    ('get', '/tools/templates'),
])
def test_compte_en_lecture_seule_refuse(app_client, method, url):
    _session(app_client, admin=False)
    headers = {'X-CSRFToken': _csrf(app_client, '/dashboard')} if method == 'post' else {}
    r = getattr(app_client, method)(url, headers=headers)
    assert r.status_code in (302, 403), (url, r.status_code)
    if r.status_code == 302:
        assert '/connect' not in r.headers['Location']     # refus de permission, pas de session


class TestScripts:
    def test_nom_hors_liste(self):
        from core.scripts_manager import get_script_path
        assert get_script_path('..\\..\\Windows\\x.ps1') is None
        assert get_script_path('C:\\Windows\\System32\\x.ps1') is None

    def test_arguments_valides(self, app_client, monkeypatch):
        from core import scripts_manager as sm
        _session(app_client, admin=True)
        name = next(iter(sm.AVAILABLE_SCRIPTS))
        tok = _csrf(app_client, '/dashboard')
        for body in ({'arguments': '-Force'}, {'arguments': [1, 2]}, {'timeout': 'x'}):
            r = app_client.post(f'/api/scripts/{name}/execute', json=body, headers={'X-CSRFToken': tok})
            assert r.status_code == 400, (body, r.status_code)


def test_redirection_referer_externe(app_client):
    r = app_client.get('/toggle-dark-mode', headers={'Referer': 'https://exemple-malveillant.test/'})
    assert r.status_code == 302 and 'exemple-malveillant' not in r.headers['Location']
    r = app_client.get('/toggle-dark-mode', headers={'Referer': 'http://localhost/users/'})
    assert r.headers['Location'].endswith('/users/')
