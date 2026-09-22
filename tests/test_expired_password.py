# -*- coding: utf-8 -*-
"""
Non-regression du parcours « mot de passe expire ».

Avant la v1.50.3, ce parcours etait casse de bout en bout :
- le sous-code AD 532 (mot de passe expire) n'etait pas detecte, et la
  sentinelle PASSWORD_EXPIRED etait noyee dans le message generique par
  get_ad_connection() sur le chemin par defaut (port 389) ;
- le template change_password.html n'existait pas (erreur 500) ;
- le changement se faisait par un bind LDAP avec le mot de passe expire,
  qu'AD refuse toujours, puis forcait pwdLastSet=0 (re-expiration immediate).
"""
import os
import re
from pathlib import Path

import pytest

os.environ.setdefault('SECRET_KEY', 'test-expired-password')

PROJECT_ROOT = Path(__file__).resolve().parent.parent

AD_EXPIRED_532 = ('80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext '
                  'error, data 532, v4563')
AD_MUST_CHANGE_773 = ('80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext '
                      'error, data 773, v4563')
AD_BAD_PASSWORD = ('80090308: LdapErr: DSID-0C090773, comment: AcceptSecurityContext '
                   'error, data 52e, v4563')


class TestExpiredDetection:
    def test_532_and_773_detected(self):
        from routes.core import _is_password_expired_error
        assert _is_password_expired_error(AD_EXPIRED_532)
        assert _is_password_expired_error(AD_MUST_CHANGE_773)

    def test_773_inside_dsid_is_not_expired(self):
        """Un mauvais mot de passe (52e) dont le DSID contient 773 n'est pas un expire."""
        from routes.core import _is_password_expired_error
        assert not _is_password_expired_error(AD_BAD_PASSWORD)

    def test_sentinel_propagated_by_get_ad_connection(self, monkeypatch):
        from app import app
        import routes.core as rc
        monkeypatch.setattr(rc, '_try_connection',
                            lambda *a, **k: (None, 'PASSWORD_EXPIRED'))
        with app.test_request_context('/'):
            conn, err = rc.get_ad_connection('dc.corp.local', 'CORP\\jdoe', 'x', False, 389)
        assert conn is None
        assert err == 'PASSWORD_EXPIRED'


class TestPasswordChangeModule:
    def test_non_windows_returns_clear_error(self, monkeypatch):
        import core.password_change as pc
        monkeypatch.setattr(pc.os, 'name', 'posix')
        ok, err = pc.change_expired_password('dc', 'jdoe', 'old', 'new')
        assert ok is False and 'Windows' in err

    def test_status_mapping(self, monkeypatch):
        import core.password_change as pc
        monkeypatch.setattr(pc.os, 'name', 'nt')
        monkeypatch.setattr(pc, '_net_user_change_password',
                            lambda *a: pc.NERR_PASSWORD_TOO_SHORT)
        ok, err = pc.change_expired_password('dc', 'jdoe', 'old', 'new')
        assert ok is False and 'strategie' in err

        monkeypatch.setattr(pc, '_net_user_change_password', lambda *a: 0)
        assert pc.change_expired_password('dc', 'jdoe', 'old', 'new') == (True, None)


@pytest.fixture
def client():
    from app import app
    app.config['TESTING'] = True
    return app.test_client()


def _prime_session(client):
    from core.session_crypto import encrypt_password
    with client.session_transaction() as sess:
        sess['_pwd_expired_user'] = 'CORP\\jdoe'
        sess['_pwd_expired_server'] = 'dc.corp.local'
        sess['_pwd_expired_password'] = encrypt_password('Ancien-MdP-1')


def _csrf(client):
    r = client.get('/change-password')
    m = re.search(rb'name="csrf-token" content="([^"]+)"', r.data)
    return m.group(1).decode()


class TestChangePasswordRoute:
    def test_get_renders_page(self, client):
        _prime_session(client)
        r = client.get('/change-password')
        assert r.status_code == 200
        assert b'new_password' in r.data

    def test_post_calls_netapi_with_bare_username(self, client, monkeypatch):
        import core.password_change as pc
        calls = []
        monkeypatch.setattr(pc, 'change_expired_password',
                            lambda *a: calls.append(a) or (True, None))
        _prime_session(client)
        tok = _csrf(client)
        r = client.post('/change-password', data={
            'csrf_token': tok, 'new_password': 'Nouveau-MdP-2',
            'confirm_password': 'Nouveau-MdP-2'})
        assert r.status_code == 302 and '/connect' in r.headers['Location']
        assert calls == [('dc.corp.local', 'jdoe', 'Ancien-MdP-1', 'Nouveau-MdP-2')]
        with client.session_transaction() as sess:
            assert '_pwd_expired_password' not in sess

    def test_post_failure_rerenders_with_message(self, client, monkeypatch):
        import core.password_change as pc
        monkeypatch.setattr(pc, 'change_expired_password',
                            lambda *a: (False, 'Refus strategie'))
        _prime_session(client)
        tok = _csrf(client)
        r = client.post('/change-password', data={
            'csrf_token': tok, 'new_password': 'Nouveau-MdP-2',
            'confirm_password': 'Nouveau-MdP-2'})
        assert r.status_code == 200
        assert 'Refus strategie' in r.get_data(as_text=True)
        with client.session_transaction() as sess:
            assert '_pwd_expired_password' in sess

    def test_no_pwdlastset_reset(self):
        """Le mot de passe fraichement change ne doit plus etre re-expire."""
        src = (PROJECT_ROOT / 'routes' / 'main.py').read_text(encoding='utf-8')
        body = src.split('def change_expired_password')[1].split('@main_bp.route')[0]
        assert "'pwdLastSet'" not in body
