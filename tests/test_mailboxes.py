# -*- coding: utf-8 -*-
"""
Boîtes aux lettres partagées Exchange Online (core/exchange.py,
routes/mailboxes). PowerShell et Microsoft 365 sont simulés : les tests
vérifient ce que l'application demande au script et ses garde-fous.
"""
import json
import os
import re

import pytest

os.environ.setdefault('SECRET_KEY', 'test-mailboxes')

from core import exchange as ex  # noqa: E402

CFG = {'organization': 'laprovidence.onmicrosoft.com', 'app_id': '11111111-2222-3333-4444-555555555555',
       'thumbprint': 'ab' * 20, 'expires': '2028-11-12'}


@pytest.fixture
def cfg(monkeypatch, tmp_path):
    path = tmp_path / 'm365.json'
    path.write_text('﻿' + json.dumps(CFG), encoding='utf-8')
    monkeypatch.setattr(ex, 'CONFIG_FILE', str(path))
    monkeypatch.setattr(ex, '_cache', {'at': 0, 'data': None})
    return path


@pytest.fixture
def ps(cfg, monkeypatch):
    calls = []
    state = {'members': {'compta@laprovidence.fr': (['alice@laprovidence.fr'], ['alice@laprovidence.fr', 'bob@laprovidence.fr'])}}

    def fake(request, timeout=None):
        calls.append(request)
        op = request['op']
        if op == 'list':
            return {'ok': True, 'mailboxes': [
                {'name': 'Comptabilité', 'address': 'Compta@laprovidence.fr', 'alias': 'compta', 'created': '2024-01-02'},
                {'name': 'Accueil', 'address': 'accueil@laprovidence.fr', 'alias': 'accueil', 'created': '2023-05-01'}],
                'domains': ['laprovidence.fr', 'laprovidence.onmicrosoft.com']}
        if op == 'members':
            full, send = state['members'].get(request['mailbox'], ([], []))
            return {'ok': True, 'full_access': full, 'send_as': send}
        return {'ok': True}
    monkeypatch.setattr(ex, 'run_ps', fake)
    return calls


class TestConfig:
    def test_lecture(self, cfg):
        assert ex.get_config()['thumbprint'] == 'AB' * 20

    def test_absente_ou_invalide(self, cfg):
        cfg.write_text(json.dumps(dict(CFG, app_id='x; rm')), encoding='utf-8')
        assert ex.get_config() is None
        os.remove(cfg)
        assert ex.get_config() is None
        with pytest.raises(ex.ExchangeError, match='pas configurée'):
            ex.run_ps({'op': 'list'})

    def test_parametres_sur_stdin(self, cfg, monkeypatch):
        seen = {}

        class Proc:
            returncode = 0
            stdout = 'AVERTISSEMENT du module {x}\n\n{"ok":true,"mailboxes":[],"domains":[]}'
            stderr = ''

        def run(args, **kw):
            seen.update(args=args, kw=kw)
            return Proc()
        monkeypatch.setattr(ex.os, 'name', 'nt')
        monkeypatch.setattr(ex.subprocess, 'run', run)
        assert ex.run_ps({'op': 'grant', 'user': "a'; Remove-Mailbox x; '@b.fr"})['ok'] is True
        assert 'Remove-Mailbox' not in ' '.join(seen['args'])
        sent = json.loads(seen['kw']['input'])
        assert sent['app_id'] == CFG['app_id'] and sent['organization'] == CFG['organization']

    def test_erreur_lisible(self, cfg, monkeypatch):
        class Proc:
            returncode = 0
            stdout = '{"ok":false,"error":"AADSTS700016: Application not found in the directory"}'
            stderr = ''
        monkeypatch.setattr(ex.os, 'name', 'nt')
        monkeypatch.setattr(ex.subprocess, 'run', lambda *a, **k: Proc())
        with pytest.raises(ex.ExchangeError, match='refuse la connexion'):
            ex.run_ps({'op': 'list'})


class TestLogic:
    def test_liste_en_cache(self, ps):
        assert [m['address'] for m in ex.list_mailboxes()['mailboxes']] == ['compta@laprovidence.fr', 'accueil@laprovidence.fr']
        ex.list_mailboxes()
        assert len(ps) == 1
        ex.list_mailboxes(refresh=True)
        assert len(ps) == 2

    def test_membres(self, ps):
        assert ex.members('COMPTA@laprovidence.fr') == [
            {'user': 'alice@laprovidence.fr', 'full_access': True, 'send_as': True},
            {'user': 'bob@laprovidence.fr', 'full_access': False, 'send_as': True}]

    def test_boite_non_partagee_refusee(self, ps):
        """La boîte personnelle du directeur n'est pas dans la liste : aucune écriture."""
        with pytest.raises(ex.ExchangeError, match='pas une boîte partagée'):
            ex.grant('directeur@laprovidence.fr', 'alice@laprovidence.fr')
        assert [c['op'] for c in ps] == ['list', 'list']            # relecture, puis refus

    def test_ajout_et_retrait(self, ps):
        ex.grant('compta@laprovidence.fr', 'Zoe@laprovidence.fr', full_access=True, send_as=False)
        assert ps[-1] == {'op': 'grant', 'mailbox': 'compta@laprovidence.fr', 'user': 'zoe@laprovidence.fr',
                          'full_access': True, 'send_as': False}
        ex.revoke('compta@laprovidence.fr', 'zoe@laprovidence.fr')
        assert ps[-1]['op'] == 'revoke'
        with pytest.raises(ex.ExchangeError):
            ex.grant('compta@laprovidence.fr', 'zoe@laprovidence.fr', False, False)
        with pytest.raises(ex.ExchangeError):
            ex.grant('compta@laprovidence.fr', 'pas une adresse')

    def test_creation(self, ps):
        assert ex.create('Ressources humaines', 'RH', 'laprovidence.fr') == 'rh@laprovidence.fr'
        assert ps[-1] == {'op': 'create', 'name': 'Ressources humaines', 'alias': 'rh', 'address': 'rh@laprovidence.fr'}
        for name, alias, domain in (('X', 'compta', 'laprovidence.fr'),          # existe déjà
                                    ('X', 'rh', 'autre.fr'),                    # domaine non accepté
                                    ('X', 'a b', 'laprovidence.fr'), ('', 'rh2', 'laprovidence.fr'),
                                    ('<b>', 'rh3', 'laprovidence.fr')):
            with pytest.raises(ex.ExchangeError):
                ex.create(name, alias, domain)


class _A:
    def __init__(self, v):
        self.value = v


class _E:
    def __init__(self, **attrs):
        for k, v in attrs.items():
            setattr(self, k, _A(v))

    def __contains__(self, name):
        return hasattr(self, name)


class Conn:
    def __init__(self, entries):
        self._entries, self.entries = entries, []

    def search(self, *a, **k):
        self.entries = self._entries

    def unbind(self):
        pass


def test_adresse_d_un_utilisateur():
    assert ex.user_address(Conn([_E(userPrincipalName='Jean.Dupont@laprovidence.fr', mail='')]), 'DC=x', 'jdupont') \
        == 'jean.dupont@laprovidence.fr'
    # Identifiant en .local : on prend l'adresse e-mail
    assert ex.user_address(Conn([_E(userPrincipalName='jdupont@laprovidence.local', mail='jd@laprovidence.fr')]),
                           'DC=x', 'LAPROVIDENCE\\jdupont') == 'jd@laprovidence.fr'
    with pytest.raises(ex.ExchangeError, match='pas d\'adresse'):
        ex.user_address(Conn([_E(userPrincipalName='jdupont@laprovidence.local', mail='')]), 'DC=x', 'jdupont')
    with pytest.raises(ex.ExchangeError, match='introuvable'):
        ex.user_address(Conn([]), 'DC=x', 'inconnu')


# --- Routes ------------------------------------------------------------------

@pytest.fixture
def client(ps, monkeypatch):
    import routes.mailboxes as rm
    from app import app
    from core.session_crypto import encrypt_password
    conn = Conn([_E(userPrincipalName='zoe@laprovidence.fr', mail='')])
    monkeypatch.setattr(rm, 'get_ad_connection', lambda *a, **k: (conn, None))
    audit = []
    monkeypatch.setattr(rm, 'log_action', lambda *a, **k: audit.append(a))
    app.config['TESTING'] = True
    c = app.test_client()
    with c.session_transaction() as s:
        s.update(ad_server='dc', ad_username='LAPROVIDENCE\\admin', ad_password=encrypt_password('x'),
                 ad_base_dn='DC=laprovidence,DC=local', user_role='admin', user_groups=['Domain Admins'])
    tok = re.search(rb'name="csrf-token" content="([^"]+)"', c.get('/mailboxes/').data).group(1).decode()
    return c, ps, tok, audit


class TestRoutes:
    def test_page_et_liste(self, client):
        c, _, _, _ = client
        assert 'laprovidence.onmicrosoft.com' in c.get('/mailboxes/').get_data(as_text=True)
        d = c.get('/mailboxes/api/list').get_json()
        assert d['success'] and len(d['mailboxes']) == 2 and d['domains'][0] == 'laprovidence.fr'
        assert len(c.get('/mailboxes/api/members?mailbox=compta@laprovidence.fr').get_json()['members']) == 2

    def test_page_non_configuree(self, client, cfg):
        c = client[0]
        os.remove(cfg)
        html = c.get('/mailboxes/').get_data(as_text=True)
        assert 'setup_m365.ps1' in html and 'id="mb-list"' not in html

    def test_ajout_par_identifiant_ad(self, client):
        c, ps, tok, audit = client
        r = c.post('/mailboxes/api/grant', json={'mailbox': 'compta@laprovidence.fr', 'user': 'zoe'},
                   headers={'X-CSRFToken': tok})
        assert r.get_json()['user'] == 'zoe@laprovidence.fr'
        grant = [x for x in ps if x['op'] == 'grant'][0]
        assert grant['user'] == 'zoe@laprovidence.fr' and grant['full_access'] and grant['send_as']
        assert audit[-1][0] == 'mailbox_grant'

    def test_retrait_et_creation(self, client):
        c, ps, tok, _ = client
        c.post('/mailboxes/api/revoke', json={'mailbox': 'compta@laprovidence.fr', 'user': 'bob@laprovidence.fr'},
               headers={'X-CSRFToken': tok})
        assert [x for x in ps if x['op'] == 'revoke'][0]['user'] == 'bob@laprovidence.fr'
        r = c.post('/mailboxes/api/create', json={'name': 'RH', 'alias': 'rh', 'domain': 'laprovidence.fr'},
                   headers={'X-CSRFToken': tok})
        assert r.get_json() == {'success': True, 'address': 'rh@laprovidence.fr'}

    def test_lecture_seule(self, client):
        c, ps, tok, _ = client
        with c.session_transaction() as s:
            s.update(user_role='user', user_groups=['Utilisateurs du domaine'])
        n = len(ps)
        assert c.get('/mailboxes/api/list').status_code in (302, 403)
        r = c.post('/mailboxes/api/grant', json={'mailbox': 'compta@laprovidence.fr', 'user': 'zoe'},
                   headers={'X-CSRFToken': tok})
        assert r.status_code == 403 and len(ps) == n

    def test_sans_csrf(self, client):
        c, ps, _, _ = client
        n = len(ps)
        r = c.post('/mailboxes/api/create', json={'name': 'RH', 'alias': 'rh', 'domain': 'laprovidence.fr'})
        assert r.status_code in (400, 403) and len(ps) == n


def test_scripts():
    run = open(ex.PS_SCRIPT_PATH, 'rb').read()
    text = run.decode('utf-8-sig')
    assert run.startswith(b'\xef\xbb\xbf') and 'Invoke-Expression' not in text
    # Chaque écriture vérifie d'abord que la boîte est partagée
    for op in ("'grant'", "'revoke'"):
        block = text.split(op + ' {')[1].split("\n        '")[0]
        assert block.strip().startswith('$m = Get-Shared $req.mailbox')
    assert 'Disconnect-ExchangeOnline' in text.split('finally')[-1]
    setup = open(os.path.join(os.path.dirname(ex.PS_SCRIPT_PATH), 'setup_m365.ps1'), 'rb').read().decode('utf-8-sig')
    assert 'KeyExportPolicy NonExportable' in setup and 'Exchange.ManageAsApp' in setup
    assert 'Exchange Recipient Administrator' in setup and 'PasswordCredential' not in setup
