# -*- coding: utf-8 -*-
"""
Microsoft 365 rapproché de l'annuaire (core/m365.py, routes/m365) :
lecture mise en cache, rapprochement AD ↔ cloud, écarts, licences, retard
de synchronisation, relevé de taille des boîtes, pages et permission.
"""
import json
import os
import re
import uuid
from datetime import datetime, timezone

import pytest

os.environ.setdefault('SECRET_KEY', 'test-m365')

from core import exchange as ex  # noqa: E402
from core import m365  # noqa: E402

BASE = 'DC=laprovidence,DC=local'
SKU_A1 = '11111111-0000-0000-0000-000000000001'
SKU_BP = '11111111-0000-0000-0000-000000000002'
SKU_FLOW = '11111111-0000-0000-0000-000000000003'
G = {n: str(uuid.UUID(int=i + 1)) for i, n in enumerate(['alice', 'bob', 'chloe', 'denis', 'fantome'])}


def cloud(name, synced=True, enabled=True, licenses=(SKU_A1,), anchor=None, upn=None, kind='Member'):
    return {'name': name.title(), 'upn': upn or f'{name}@laprovidence.fr', 'mail': '', 'enabled': enabled,
            'type': kind, 'synced': synced, 'last_sync': '', 'sam': name if synced else '',
            'anchor': m365.anchor_of(G[name]) if anchor is None and name in G and synced else (anchor or ''),
            'licenses': list(licenses), 'created': '2025-09-01T08:00:00Z'}


RAW = {'ok': True,
       'organization': {'name': 'La Providence', 'sync_enabled': True, 'last_sync': '2026-11-12T09:30:00Z'},
       'skus': [{'id': SKU_A1.upper(), 'code': 'STANDARDWOFFPACK_FACULTY', 'status': 'Enabled',
                 'total': 500, 'warning': 0, 'suspended': 0, 'used': 120},
                {'id': SKU_BP, 'code': 'SPB', 'status': 'Enabled', 'total': 5, 'warning': 0, 'suspended': 0, 'used': 6},
                {'id': SKU_FLOW, 'code': 'FLOW_FREE', 'status': 'Enabled', 'total': 10000, 'used': 3},
                {'id': 'x', 'code': 'REF_INCONNUE', 'status': 'Warning', 'total': 0, 'warning': 2, 'used': 2}],
       'users': [cloud('alice'),                                        # normal
                 cloud('bob', licenses=(SKU_A1, SKU_FLOW)),             # désactivé dans l'AD, licence gardée
                 cloud('chloe', licenses=(SKU_FLOW,), upn='c.martin@laprovidence.fr'),   # UPN différent, sans licence payante
                 cloud('fantome', enabled=False, licenses=(SKU_BP,)),   # synchronisé, plus de compte AD
                 cloud('admin.cloud', synced=False, licenses=()),       # créé dans le cloud
                 cloud('invite', synced=False, licenses=(), kind='Guest',
                       upn='ext_gmail.com#EXT#@laprovidence.onmicrosoft.com')]}

AD = [{'dn': f'CN=Alice,OU=Profs,{BASE}', 'sam': 'alice', 'name': 'Alice', 'upn': 'alice@laprovidence.fr',
       'mail': '', 'enabled': True, 'anchor': m365.anchor_of(G['alice'])},
      {'dn': f'CN=Bob,OU=Profs,{BASE}', 'sam': 'bob', 'name': 'Bob', 'upn': 'bob@laprovidence.fr',
       'mail': '', 'enabled': False, 'anchor': m365.anchor_of(G['bob'])},
      {'dn': f'CN=Chloe,OU=Profs,{BASE}', 'sam': 'chloe', 'name': 'Chloé', 'upn': 'chloe@laprovidence.fr',
       'mail': '', 'enabled': True, 'anchor': m365.anchor_of(G['chloe'])},
      {'dn': f'CN=Denis,OU=Profs,{BASE}', 'sam': 'denis', 'name': 'Denis', 'upn': 'denis@laprovidence.fr',
       'mail': '', 'enabled': True, 'anchor': m365.anchor_of(G['denis'])},
      {'dn': f'CN=svc,OU=Services,{BASE}', 'sam': 'svc', 'name': 'svc', 'upn': 'svc@laprovidence.local',
       'mail': '', 'enabled': True, 'anchor': 'x'}]
NOW = datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc)


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    path = tmp_path / 'm365.json'
    path.write_text(json.dumps({'organization': 'laprovidence.onmicrosoft.com',
                                'app_id': '11111111-2222-3333-4444-555555555555',
                                'thumbprint': 'A' * 40, 'expires': '2028-01-01', 'graph': True}))
    monkeypatch.setattr(ex, 'CONFIG_FILE', str(path))
    monkeypatch.setattr(m365, '_cache', {'at': 0, 'data': None})
    monkeypatch.setattr(m365, '_stats', {'status': 'idle', 'at': 0, 'data': None, 'error': ''})
    return path


@pytest.fixture
def ps(cfg, monkeypatch):
    calls = []
    monkeypatch.setattr(m365, '_run_ps', lambda: calls.append(1) or json.loads(json.dumps(RAW)))
    return calls


class TestConfig:
    def test_etat_de_la_liaison(self, cfg):
        assert m365.status() == 'ready'
        cfg.write_text(json.dumps({'organization': 'x.onmicrosoft.com', 'thumbprint': 'A' * 40,
                                   'app_id': '11111111-2222-3333-4444-555555555555'}))
        assert m365.status() == 'no_graph'             # liaison d'avant la v1.59
        with pytest.raises(m365.M365Error, match='setup_m365'):
            m365.fetch()
        os.remove(cfg)
        assert m365.status() == 'none'

    def test_parametres_sur_l_entree_standard(self, cfg, monkeypatch):
        seen = {}

        class Proc:
            returncode, stderr = 0, ''
            stdout = 'bruit\n' + json.dumps({'ok': True, 'organization': {}, 'skus': [], 'users': []})

        def run(cmd, **kw):
            seen.update(cmd=cmd, input=json.loads(kw['input']))
            return Proc()
        monkeypatch.setattr(m365.os, 'name', 'nt')
        monkeypatch.setattr(m365.subprocess, 'run', run)
        assert m365.fetch()['users'] == []
        assert seen['cmd'][-2:] == ['-File', m365.PS_SCRIPT_PATH] and 'A' * 40 not in ' '.join(seen['cmd'])
        assert seen['input'] == {'organization': 'laprovidence.onmicrosoft.com', 'thumbprint': 'A' * 40,
                                 'app_id': '11111111-2222-3333-4444-555555555555'}

    def test_erreurs_lisibles(self, cfg, monkeypatch):
        class Proc:
            returncode, stderr = 0, ''
            stdout = json.dumps({'ok': False, 'error': 'Authorization_RequestDenied Insufficient privileges'})
        monkeypatch.setattr(m365.os, 'name', 'nt')
        monkeypatch.setattr(m365.subprocess, 'run', lambda *a, **k: Proc())
        with pytest.raises(m365.M365Error, match='lecture des comptes'):
            m365.fetch()
        monkeypatch.setattr(m365.os, 'name', 'posix')
        with pytest.raises(m365.M365Error, match='Windows'):
            m365.fetch()


class TestCompare:
    def test_cache(self, ps):
        m365.fetch()
        m365.fetch()
        assert len(ps) == 1
        m365.fetch(refresh=True)
        assert len(ps) == 2

    def test_ancre(self):
        guid = '{3f2504e0-4f89-11d3-9a0c-0305e82c3301}'
        assert m365.anchor_of(guid) == m365.anchor_of(uuid.UUID(guid).bytes_le) == '4AQlP4lP0xGaDAMF6CwzAQ=='
        assert m365.anchor_of('pas un guid') == '' and m365.anchor_of(None) == ''

    def test_ecarts(self, ps):
        r = m365.compare(m365.fetch(), AD, NOW)
        f = {k: [x['upn'] for x in v] for k, v in r['findings'].items()}
        assert f == {'disabled_licensed': ['bob@laprovidence.fr', 'fantome@laprovidence.fr'],
                     'orphans': ['fantome@laprovidence.fr'],
                     'upn_mismatch': ['c.martin@laprovidence.fr'],
                     'cloud_only': ['admin.cloud@laprovidence.fr'],
                     'unlicensed': ['c.martin@laprovidence.fr'],
                     'ad_only': ['denis@laprovidence.fr']}             # svc (.local) n'est pas attendu dans le cloud
        bob = r['findings']['disabled_licensed'][0]
        assert bob['licenses'] == ['Office 365 A1 (enseignants)'] and 'AD' in bob['detail'] and bob['dn']
        assert 'Microsoft 365' in r['findings']['disabled_licensed'][1]['detail']
        assert r['counts'] == {'cloud': 5, 'guests': 1, 'synced': 4, 'licensed': 3, 'ad': 5, 'wasted': 2}

    def test_licences(self, ps):
        lic = {s['code']: s for s in m365.compare(m365.fetch(), AD, NOW)['licenses']}
        assert lic['STANDARDWOFFPACK_FACULTY']['free'] == 380 and lic['SPB']['over'] == 1 and lic['SPB']['free'] == 0
        assert lic['FLOW_FREE']['free_sku'] and lic['REF_INCONNUE']['name'] == 'REF_INCONNUE'
        assert list(lic)[-1] == 'FLOW_FREE'             # les références gratuites en dernier

    def test_synchronisation(self, ps):
        data = m365.fetch()
        org = m365.compare(data, AD, NOW)['organization']
        assert org['sync_age_minutes'] == 30 and not org['sync_late']
        late = m365.compare(data, AD, datetime(2026, 11, 13, 10, 0, tzinfo=timezone.utc))['organization']
        assert late['sync_late']
        data['organization'].update(sync_enabled=False, last_sync='')
        r = m365.compare(data, AD, NOW)
        assert not r['organization']['sync_late'] and r['findings']['ad_only'] == [] and r['findings']['orphans'] == []

    def test_fiche(self, ps):
        data = m365.fetch()
        s = m365.user_status(data, 'autre@x.fr', m365.anchor_of(G['bob']))
        assert s['upn'] == 'bob@laprovidence.fr' and s['licenses'] == ['Office 365 A1 (enseignants)', 'Power Automate (gratuit)']
        assert m365.user_status(data, 'ALICE@laprovidence.fr')['synced']
        assert m365.user_status(data, 'inconnu@x.fr') is None and m365.user_status(data) is None


class TestBoites:
    def test_tailles(self, monkeypatch):
        monkeypatch.setattr(ex, 'run_ps', lambda req, timeout=0: {'ok': True, 'mailboxes': [
            {'name': 'Petite', 'address': 'P@x.fr', 'size': '512 KB (524,288 bytes)', 'quota': '50 GB (53,687,091,200 bytes)',
             'items': 12, 'shared': True},
            {'name': 'Grosse', 'address': 'g@x.fr', 'size': '48.5 GB (52 076 478 464 bytes)',
             'quota': '50 GB (53,687,091,200 bytes)', 'items': 90000, 'last_logon': '2026-11-10', 'archive': True},
            {'name': 'Cassée', 'address': 'c@x.fr', 'size': '', 'quota': 'Unlimited', 'error': 'introuvable'}]})
        rows = ex.mailbox_stats()
        assert [r['name'] for r in rows] == ['Grosse', 'Petite', 'Cassée']
        assert rows[0]['percent'] == 97 and rows[0]['size'] == 52076478464 and rows[0]['archive']
        assert rows[1]['shared'] and rows[1]['address'] == 'p@x.fr' and rows[2]['percent'] is None and rows[2]['error']

    def test_releve_en_arriere_plan(self, cfg, monkeypatch):
        pending = []

        class Later:                        # le relevé démarre sous verrou : on l'exécute après coup
            def __init__(self, target, daemon=None):
                self.target = target

            def start(self):
                pending.append(self.target)

        def go(**kw):
            state = m365.mailbox_stats(**kw)
            while pending:
                pending.pop()()
            return state
        monkeypatch.setattr(m365.threading, 'Thread', Later)
        runs = []
        monkeypatch.setattr(ex, 'mailbox_stats', lambda: runs.append(1) or [{'name': 'A'}])
        assert go()['status'] == 'idle' and not runs                           # consulter ne lance rien
        assert go(start=True)['status'] == 'running'
        assert go()['status'] == 'done' and len(runs) == 1
        go(start=True)                                                         # encore frais : pas de relance
        assert len(runs) == 1
        go(refresh=True)
        assert len(runs) == 2

        def boom():
            raise ex.ExchangeError('Exchange injoignable')
        monkeypatch.setattr(ex, 'mailbox_stats', boom)
        go(refresh=True)
        state = go()
        assert state['status'] == 'error' and 'injoignable' in state['error'] and state['data'] == [{'name': 'A'}]


# --- Routes ------------------------------------------------------------------

class _Conn:
    def unbind(self):
        pass


@pytest.fixture
def client(ps, monkeypatch):
    import routes.m365 as rm
    from app import app
    from core.session_crypto import encrypt_password
    monkeypatch.setattr(rm, 'get_ad_connection', lambda *a, **k: (_Conn(), None))
    monkeypatch.setattr(m365, 'read_ad_users', lambda conn, base: AD)
    app.config['TESTING'] = True
    c = app.test_client()
    with c.session_transaction() as s:
        s.update(ad_server='dc', ad_username='LAPROVIDENCE\\admin', ad_password=encrypt_password('x'),
                 ad_base_dn=BASE, user_role='admin', user_groups=['Domain Admins'])
    tok = re.search(rb'name="csrf-token" content="([^"]+)"', c.get('/m365/').data).group(1).decode()
    return c, tok


class TestRoutes:
    def test_page_et_donnees(self, client):
        c, _ = client
        html = c.get('/m365/').get_data(as_text=True)
        assert 'm-findings' in html and 'setup_m365' not in html
        d = c.get('/m365/api/overview').get_json()
        assert d['success'] and d['counts']['wasted'] == 2 and len(d['findings']['ad_only']) == 1
        u = c.get('/m365/api/user?upn=alice@laprovidence.fr').get_json()
        assert u['success'] and u['user']['synced']
        assert c.get('/m365/api/user?upn=personne@x.fr').get_json()['user'] is None

    def test_liaison_a_completer(self, client, cfg):
        c, _ = client
        cfg.write_text(json.dumps({'organization': 'x.onmicrosoft.com', 'thumbprint': 'A' * 40,
                                   'app_id': '11111111-2222-3333-4444-555555555555'}))
        html = c.get('/m365/').get_data(as_text=True)
        assert 'Un droit de lecture reste à accorder' in html and 'setup_m365.ps1' in html
        os.remove(cfg)
        assert 'Liaison à mettre en place' in c.get('/m365/').get_data(as_text=True)

    def test_erreur_microsoft(self, client, monkeypatch):
        def boom(refresh=False):
            raise m365.M365Error('Microsoft 365 est injoignable')
        monkeypatch.setattr(m365, 'fetch', boom)
        r = client[0].get('/m365/api/overview')
        assert r.status_code == 400 and 'injoignable' in r.get_json()['error']

    def test_releve_des_boites(self, client, monkeypatch):
        c, tok = client
        seen = []
        monkeypatch.setattr(m365, 'mailbox_stats', lambda start=False, refresh=False: seen.append((start, refresh)) or {
            'status': 'running', 'error': '', 'at': 0, 'data': None})
        assert c.get('/m365/api/mailboxes').get_json()['status'] == 'running'
        assert c.post('/m365/api/mailboxes/start', json={'refresh': True}).status_code in (400, 403)   # sans jeton CSRF
        r = c.post('/m365/api/mailboxes/start', json={'refresh': True}, headers={'X-CSRFToken': tok})
        assert r.get_json()['success'] and seen == [(False, False), (True, True)]

    def test_permission_et_menu(self, client, monkeypatch):
        from core import granular_permissions as gperm
        from core.settings_manager import DEFAULT_SETTINGS
        assert 'm365:read' in gperm.ALL_PERMISSIONS and 'm365:read' not in gperm.SENSITIVE_PERMISSIONS
        assert any(i['endpoint'] == 'm365.index' for i in DEFAULT_SETTINGS['menu']['tool_items'])
        c, _ = client
        with c.session_transaction() as s:
            s.update(user_role='reader', user_groups=[])
        monkeypatch.setattr(gperm, 'has_permission', lambda groups, perm, **k: perm != 'm365:read')
        assert c.get('/m365/api/overview').status_code in (302, 403)


def test_scripts_powershell():
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts')
    for name in ('m365.ps1', 'exchange.ps1', 'setup_m365.ps1'):
        raw = open(os.path.join(root, name), 'rb').read()
        assert raw.startswith(b'\xef\xbb\xbf') and raw.count(b'\r\n') == raw.count(b'\n'), name
    graph = open(os.path.join(root, 'm365.ps1'), encoding='utf-8-sig').read()
    # Lecture seule : aucun appel d'écriture vers Microsoft Graph (le seul POST est la demande de jeton).
    assert graph.count('-Method Post') == 1 and 'oauth2/v2.0/token' in graph
    assert not re.search(r'-Method\s+(Patch|Put|Delete)', graph, re.I)
    setup = open(os.path.join(root, 'setup_m365.ps1'), encoding='utf-8-sig').read()
    assert "'User.Read.All', 'Organization.Read.All'" in setup and 'graph = $true' in setup
    assert 'ReadWrite' not in setup.split('$graphRoles =')[1].split('\n')[0]
    assert "'stats'" in open(os.path.join(root, 'exchange.ps1'), encoding='utf-8-sig').read()
