# -*- coding: utf-8 -*-
"""
Non-regression des outils de comptes (routes/tools/accounts.py).

- Deverrouillage : conn.modify recevait une liste au lieu d'un dictionnaire
  (ldap3 levait « changes must be a dictionary ») et une valeur de 8 octets
  nuls au lieu de l'entier 0 : aucun compte ne pouvait etre deverrouille.
- Corbeille : la restauration tentait un modDN, refuse par AD sur un objet
  supprime, avec un RDN sans « CN= » et encore suffixe de « DEL:<guid> ».
"""
import os
import urllib.parse

import pytest
from ldap3 import MODIFY_DELETE, MODIFY_REPLACE

os.environ.setdefault('SECRET_KEY', 'test-account-tools')

BASE = 'DC=corp,DC=local'


class _Attr:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)


class _Entry:
    def __init__(self, dn, **attrs):
        self.entry_dn = dn
        self._attrs = {k: _Attr(v) for k, v in attrs.items()}

    def __getattr__(self, name):
        try:
            return self.__dict__['_attrs'][name]
        except KeyError:
            raise AttributeError(name)

    def __contains__(self, name):
        return name in self._attrs


class FakeConn:
    """Connexion LDAP factice qui enregistre les appels et valide leur forme."""

    def __init__(self, entries=None):
        self.calls = []
        self.entries = entries or []
        self.result = {'result': 0, 'description': 'success'}

    def search(self, *a, **k):
        self.calls.append(('search', a, k))

    def modify(self, dn, changes, controls=None):
        # Meme verification que ldap3 : un dictionnaire est obligatoire.
        if not isinstance(changes, dict):
            raise TypeError('changes must be a dictionary')
        self.calls.append(('modify', dn, changes, controls))

    def unbind(self):
        pass


@pytest.fixture
def client(monkeypatch):
    from app import app
    from core.session_crypto import encrypt_password
    app.config['TESTING'] = True
    c = app.test_client()
    with c.session_transaction() as s:
        s.update(ad_server='dc', ad_username='CORP\\admin', ad_password=encrypt_password('x'),
                 ad_base_dn=BASE, user_role='admin', user_groups=['Domain Admins'],
                 csrf_token='t' * 64)
    return c


def _use(monkeypatch, conn):
    import routes.tools.accounts as acc
    monkeypatch.setattr(acc, 'get_ad_connection', lambda *a, **k: (conn, None))


def test_unlock_individuel(client, monkeypatch):
    conn = FakeConn()
    _use(monkeypatch, conn)
    dn = f'CN=Jean Dupont,OU=Paris,{BASE}'
    r = client.post('/tools/locked-accounts/unlock/' + urllib.parse.quote(dn),
                    data={'csrf_token': 't' * 64})
    assert r.status_code == 302
    assert conn.calls == [('modify', dn, {'lockoutTime': [(MODIFY_REPLACE, [0])]}, None)]


def test_unlock_groupe(client, monkeypatch):
    conn = FakeConn()
    _use(monkeypatch, conn)
    dns = [f'CN=A,{BASE}', f'CN=B,{BASE}']
    r = client.post('/tools/locked-accounts/unlock',
                    data={'csrf_token': 't' * 64, 'selected_accounts': dns})
    assert r.status_code == 302
    assert [c[1] for c in conn.calls] == dns
    with client.session_transaction() as s:
        assert any('2 compte' in m for _, m in s.get('_flashes', []))


def test_restauration_corbeille(client, monkeypatch):
    deleted = f'CN=O\'Brien\\, John\\0ADEL:1a2b,CN=Deleted Objects,{BASE}'
    conn = FakeConn([_Entry(deleted, cn="O'Brien, John\nDEL:1a2b",
                            lastKnownParent=f'OU=Paris,{BASE}')])
    _use(monkeypatch, conn)
    r = client.post('/tools/recycle-bin/' + urllib.parse.quote(deleted) + '/restore',
                    data={'csrf_token': 't' * 64})
    assert r.status_code == 302
    op, dn, changes, controls = conn.calls[-1]
    assert op == 'modify' and dn == deleted
    assert changes == {
        'isDeleted': [(MODIFY_DELETE, [])],
        'distinguishedName': [(MODIFY_REPLACE, [f"CN=O'Brien\\, John,OU=Paris,{BASE}"])],
    }
    assert controls and controls[0][0] == '1.2.840.113556.1.4.417'


def test_restauration_erreur_ldap_sans_500(client, monkeypatch):
    class Boom(FakeConn):
        def search(self, *a, **k):
            raise RuntimeError('serveur indisponible')
    _use(monkeypatch, Boom())
    r = client.post('/tools/recycle-bin/' + urllib.parse.quote(f'CN=X,{BASE}') + '/restore',
                    data={'csrf_token': 't' * 64})
    assert r.status_code == 302


def test_nom_d_origine():
    from routes.tools.accounts import _original_name
    assert _original_name('Dupont\nDEL:1a2b-3c') == 'Dupont'
    assert _original_name('Dupont\\0ADEL:1a2b-3c') == 'Dupont'
    assert _original_name('Dupont') == 'Dupont'


# --- LAPS : injection PowerShell dans le rafraichissement force ------------

@pytest.mark.parametrize('nom', ['pc01"; Remove-Item C:\\x; "', 'pc$(calc)', "pc'01", 'pc 01', 'pc;01', ''])
def test_laps_refresh_refuse_nom_invalide(client, monkeypatch, nom):
    import routes.tools.laps as laps
    lance = []
    monkeypatch.setattr(laps.subprocess, 'run', lambda *a, **k: lance.append(a))
    r = client.post('/tools/laps/refresh', data={'csrf_token': 't' * 64, 'computer_name': nom})
    assert r.status_code == 302
    assert lance == [], "aucun PowerShell ne doit etre lance pour un nom invalide"


def test_laps_refresh_nom_transmis_en_base64(client, monkeypatch):
    import base64
    import routes.tools.laps as laps

    class R:
        stdout, stderr, returncode = 'SUCCESS_WINRM\nSUCCESS', '', 0
    lance = []
    monkeypatch.setattr(laps.subprocess, 'run', lambda cmd, **k: lance.append(cmd) or R())
    r = client.post('/tools/laps/refresh', data={'csrf_token': 't' * 64, 'computer_name': 'PC-01'})
    assert r.status_code == 302 and len(lance) == 1
    script = lance[0][-1]
    assert 'PC-01' not in script, "le nom ne doit pas etre interpole en clair"
    fqdn = base64.b64encode('PC-01.corp.local'.encode('utf-16-le')).decode()
    assert fqdn in script


def test_scripts_powershell_sans_interpolation_brute():
    """Dans les scripts PowerShell de laps.py, seules des valeurs base64 sont interpolees."""
    import re
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / 'routes' / 'tools' / 'laps.py').read_text(encoding='utf-8')
    scripts = re.findall(r"ps_script = f'''(.*?)'''", src, re.S)
    assert len(scripts) == 3
    for sc in scripts:
        # {{ }} = accolades PowerShell echappees ; toute autre {x} est une interpolation Python
        champs = set(re.findall(r'(?<!\{)\{([a-z_][a-z0-9_]*)\}(?!\})', sc))
        assert champs <= {'encoded_domain', 'encoded_domain_dn', 'b64_fqdn', 'b64_short'}, champs
