# -*- coding: utf-8 -*-
"""
Plusieurs domaines (core/domains.py, core/forest.py, routes/domains) :
connexions rangées par domaine, changement de domaine actif (droits
compris), ajout d'un domaine, données propres à chaque domaine (journal,
favoris, audit, Microsoft 365, recherche rapide), lecture de la forêt.
"""
import json
import os
import re

import pytest

os.environ.setdefault('SECRET_KEY', 'test-domains')

from core import domains as dom  # noqa: E402
from core import forest as fo  # noqa: E402

A, B = 'DC=laprovidence,DC=local', 'DC=college,DC=laprovidence,DC=local'


@pytest.fixture(autouse=True)
def known_file(tmp_path, monkeypatch):
    monkeypatch.setattr(dom, 'KNOWN_FILE', str(tmp_path / 'domains.json'))
    return tmp_path / 'domains.json'


def login(s, base_dn, user, groups, port=636):
    from core.session_crypto import encrypt_password
    s.update(ad_server='dc.' + dom.domain_key(base_dn), ad_username=user, ad_password=encrypt_password('pw-' + user),
             ad_use_ssl=port == 636, ad_starttls=False, ad_port=port, ad_base_dn=base_dn,
             ad_domain=dom.domain_key(base_dn), user_role='admin', user_groups=groups)


class TestNoms:
    def test_conversions(self):
        assert dom.domain_key('DC=LaProvidence, DC=local') == 'laprovidence.local'
        assert dom.domain_key('OU=X,DC=a,DC=b') == 'a.b' and dom.domain_key('') == ''
        assert dom.base_dn_of('college.laprovidence.local') == B
        assert dom.netbios_of('COLLEGE\\admin') == 'COLLEGE' and dom.netbios_of('admin@x.fr') == ''


class TestSession:
    def test_ranger_activer_oublier(self):
        from app import app
        with app.test_request_context('/'):
            from flask import session
            login(session, A, 'LAPROVIDENCE\\admin', ['Admins du domaine'])
            assert dom.remember_active() == 'laprovidence.local'
            login(session, B, 'COLLEGE\\gestion', ['Support'], port=389)
            dom.remember_active()
            assert [d['key'] for d in dom.connected()] == ['college.laprovidence.local', 'laprovidence.local']
            dom.activate('LAPROVIDENCE.local')
            assert session['ad_username'] == 'LAPROVIDENCE\\admin' and session['user_groups'] == ['Admins du domaine']
            assert session['ad_port'] == 636 and dom.connected()[0]['key'] == 'laprovidence.local'
            dom.activate('college.laprovidence.local')
            assert session['user_groups'] == ['Support'] and session['ad_port'] == 389     # droits du domaine actif
            with pytest.raises(dom.DomainError):
                dom.activate('inconnu.local')
            assert dom.forget('college.laprovidence.local') is True
            assert session['ad_base_dn'] == A and len(dom.connected()) == 1               # l'autre prend la relève
            dom.forget('laprovidence.local')
            assert not session.get('ad_server') and dom.connected() == []

    def test_limite(self, monkeypatch):
        from app import app
        monkeypatch.setattr(dom, 'MAX_CONNECTED', 1)
        with app.test_request_context('/'):
            from flask import session
            login(session, A, 'a', [])
            dom.remember_active()
            login(session, B, 'b', [])
            with pytest.raises(dom.DomainError):
                dom.remember_active()

    def test_domaines_connus_sans_identifiants(self, known_file):
        dom.remember_known('laprovidence.local', 'srv-dc02', A, 636, True, 'LAPROVIDENCE')
        dom.remember_known('college.laprovidence.local', 'srv-col', B)
        dom.remember_known('../../etc', 'x', 'y')                                          # nom invalide ignoré
        assert [d['key'] for d in dom.known()] == ['college.laprovidence.local', 'laprovidence.local']
        assert 'pw' not in known_file.read_text() and 'password' not in known_file.read_text()
        assert dom.known_entry('laprovidence.local')['port'] == 636
        dom.forget_known('college.laprovidence.local')
        assert [d['key'] for d in dom.known()] == ['laprovidence.local']


class FakeConn:
    def __init__(self, server, port):
        self.server, self.port = server, port

    def open(self):
        pass

    def bind(self):
        return True

    def unbind(self):
        pass


def test_connexion_a_un_autre_domaine_sans_toucher_la_session(monkeypatch):
    import routes.core as rc
    from app import app
    seen = []
    monkeypatch.setattr(rc, 'Connection', lambda srv, **k: seen.append(srv.port) or FakeConn(srv, srv.port))
    with app.test_request_context('/'):
        from flask import session
        login(session, A, 'LAPROVIDENCE\\admin', [], port=636)
        before = dict(session)
        conn, error = rc.get_ad_connection('dc.college', 'COLLEGE\\x', 'pw', False, 3268, remember=False)
        assert conn and error is None and seen == [3268]                    # pas le port ni le SSL du domaine actif
        assert dict(session) == before
        assert rc.get_ad_connection('', 'u', 'p', remember=False) == (None, 'Non connecté')


def test_for_each_un_domaine_en_panne_n_empeche_pas_les_autres(monkeypatch):
    from app import app

    class C:
        def unbind(self):
            pass
    monkeypatch.setattr(dom, 'connect', lambda creds: (C(), None) if 'college' not in creds['key'] else (None, 'injoignable'))
    with app.test_request_context('/'):
        from flask import session
        login(session, A, 'a', [])
        dom.remember_active()
        login(session, B, 'b', [])
        dom.remember_active()
        r = dom.for_each(lambda conn, base, key: base)
    assert r['laprovidence.local'] == {'ok': True, 'result': A, 'error': ''}
    assert r['college.laprovidence.local']['ok'] is False and 'injoignable' in r['college.laprovidence.local']['error']


# --- Routes ------------------------------------------------------------------

@pytest.fixture
def client(monkeypatch, tmp_path):
    import routes.main as rm
    import core.favorites as fav
    from app import app
    monkeypatch.setattr(fav, 'FAVORITES_FILE', str(tmp_path / 'fav.json'))

    class Conn:
        def __init__(self, base):
            self.server = type('S', (), {'info': None})()
            self.base = base

        def unbind(self):
            pass
    bases = {'dc-a': A, 'dc-b': B}

    def fake_connect(server, username, password, use_ssl=False, port=None, remember=True):
        from flask import session
        if password != 'ok':
            return None, 'Identifiants incorrects'
        session['ad_starttls'] = server == 'dc-a'          # appris à la connexion, comme le vrai code
        return Conn(bases[server]), None
    monkeypatch.setattr(rm, 'get_ad_connection', fake_connect)
    monkeypatch.setattr(rm, 'get_user_role_from_groups',
                        lambda conn, user, debug=False: ('admin', {'groups': ['G-' + user.split('\\')[0]]}))
    monkeypatch.setattr(rm, 'check_rate_limit', lambda ip: (True, 0, 5))
    app.config['TESTING'] = True
    c = app.test_client()
    c.get('/connect')
    with c.session_transaction() as s:
        token = s['csrf_token']

    def do_login(server, domain, add=False, password='ok'):
        data = {'csrf_token': token, 'server': server, 'domain': domain, 'username': 'admin', 'password': password,
                'base_dn': bases.get(server, '')}
        if add:
            data['add_domain'] = '1'
        return c.post('/connect', data=data)
    return c, token, do_login


class TestRoutes:
    def test_ajouter_puis_changer_de_domaine(self, client, known_file):
        c, token, do_login = client
        assert do_login('dc-a', 'LAPROVIDENCE').status_code == 200
        r = do_login('dc-b', 'COLLEGE', add=True)
        assert r.status_code == 302 and r.headers['Location'].endswith('/dashboard')
        with c.session_transaction() as s:
            assert sorted(s['domains']) == ['college.laprovidence.local', 'laprovidence.local']
            assert s['ad_base_dn'] == B and s['user_groups'] == ['G-COLLEGE']
            assert s['domains']['laprovidence.local']['ad_starttls'] is True    # pas écrasé par la connexion au 2e domaine
            assert s['ad_starttls'] is False
        html = c.get('/tools/favorites').get_data(as_text=True)
        assert 'domain-switcher' in html and 'college.laprovidence.local' in html and 'Ajouter un domaine' in html
        r = c.post('/domains/switch', data={'csrf_token': token, 'key': 'laprovidence.local',
                                           'next': '/users/CN=X,OU=Y,DC=college,DC=laprovidence,DC=local/overview'})
        assert r.headers['Location'].endswith('/dashboard')                  # une fiche de l'autre domaine n'a pas de sens
        with c.session_transaction() as s:
            assert s['ad_base_dn'] == A and s['user_groups'] == ['G-LAPROVIDENCE'] and s['ad_starttls'] is True
        r = c.post('/domains/switch', data={'csrf_token': token, 'key': 'college.laprovidence.local',
                                           'next': '/tools/locked-accounts'})
        assert r.headers['Location'].endswith('/tools/locked-accounts')
        r = c.post('/domains/switch', data={'csrf_token': token, 'key': 'laprovidence.local', 'next': '/domains/'})
        assert r.headers['Location'].endswith('/domains/')
        for bad in ('https://evil.example/', '//evil.example/x', '/connect', '/domains/x/disconnect'):
            r = c.post('/domains/switch', data={'csrf_token': token, 'key': 'laprovidence.local', 'next': bad})
            assert r.headers['Location'].endswith('/dashboard'), bad
        assert c.post('/domains/switch', data={'key': 'laprovidence.local'}).status_code in (400, 403)   # CSRF
        r = c.post('/domains/switch', json={'key': 'nulle.part'}, headers={'X-CSRFToken': token})
        assert r.status_code == 400
        assert {d['key'] for d in dom.known()} == {'laprovidence.local', 'college.laprovidence.local'}

    def test_connexion_classique_repart_de_zero(self, client):
        c, token, do_login = client
        do_login('dc-a', 'LAPROVIDENCE')
        do_login('dc-b', 'COLLEGE', add=True)
        do_login('dc-b', 'COLLEGE')                     # autre personne au même poste : pas d'héritage des domaines
        with c.session_transaction() as s:
            assert list(s['domains']) == ['college.laprovidence.local']

    def test_echec_d_ajout_garde_le_domaine_actif(self, client):
        c, token, do_login = client
        do_login('dc-a', 'LAPROVIDENCE')
        r = do_login('dc-b', 'COLLEGE', add=True, password='faux')
        assert r.status_code == 200 and 'Ajouter un domaine' in r.get_data(as_text=True)
        with c.session_transaction() as s:
            assert s['ad_base_dn'] == A and s['ad_starttls'] is True and list(s['domains']) == ['laprovidence.local']

    def test_formulaire_d_ajout_prerempli(self, client):
        c, token, do_login = client
        assert 'Ajouter un domaine' not in c.get('/connect?add=1').get_data(as_text=True)   # non connecté : connexion normale
        do_login('dc-a', 'LAPROVIDENCE')
        dom.remember_known('college.laprovidence.local', 'srv-col.college', B, 636, True, 'COLLEGE')
        html = c.get('/connect?add=1&key=college.laprovidence.local').get_data(as_text=True)
        assert 'name="add_domain" value="1"' in html and 'srv-col.college' in html and 'COLLEGE' in html

    def test_deconnecter_un_domaine(self, client):
        c, token, do_login = client
        do_login('dc-a', 'LAPROVIDENCE')
        do_login('dc-b', 'COLLEGE', add=True)
        r = c.post('/domains/college.laprovidence.local/disconnect', data={'csrf_token': token})
        assert r.status_code == 302
        with c.session_transaction() as s:
            assert s['ad_base_dn'] == A and list(s['domains']) == ['laprovidence.local']
        r = c.post('/domains/laprovidence.local/disconnect', data={'csrf_token': token})
        assert '/disconnect' in r.headers['Location']                 # dernier domaine : fin de session

    def test_favoris_et_audit_par_domaine(self, client):
        from core import favorites as fav
        from core.audit import log_action
        from app import app
        c, token, do_login = client
        do_login('dc-a', 'LAPROVIDENCE')
        fav.add('admin', f'CN=Alice,OU=Profs,{A}', 'user', 'Alice')
        fav.add('admin', f'CN=Bob,OU=Profs,{B}', 'user', 'Bob')
        assert [f['name'] for f in fav.load('admin', A)] == ['Alice']   # Bob est dans le sous-domaine
        assert [f['name'] for f in fav.load('admin', B)] == ['Bob'] and len(fav.load('admin')) == 2
        with app.test_request_context('/'):
            from flask import session
            assert 'domain' not in log_action('x', 'u', {'a': 1})['details']    # un seul domaine : rien ne change
            session['domains'] = {'a': {}, 'b': {}}
            session['ad_base_dn'] = B
            assert log_action('x', 'u', {'a': 1})['details'] == {'a': 1, 'domain': 'college.laprovidence.local'}
            assert log_action('x', 'u', {'domain': 'autre'})['details'] == {'domain': 'autre'}


# --- Journal du domaine : une série de photos par domaine -------------------------

def test_journal_separe_par_domaine(tmp_path, monkeypatch):
    import gzip
    from core import domain_history as dh
    monkeypatch.setattr(dh, 'SNAP_DIR', str(tmp_path / 'snapshots'))
    monkeypatch.setattr(dh, '_owners', {})
    legacy_a = dh.save({'base_dn': A, 'users': {}}, 'admin')                  # photo d'avant la v1.62 (racine)
    with gzip.open(os.path.join(dh.SNAP_DIR, legacy_a + '.json.gz'), 'rt') as f:
        assert json.load(f)['base_dn'] == A
    os.rename(os.path.join(dh.SNAP_DIR, legacy_a + '.json.gz'), os.path.join(dh.SNAP_DIR, '20200101-000000.json.gz'))
    os.rename(os.path.join(dh.SNAP_DIR, legacy_a + '.meta.json'), os.path.join(dh.SNAP_DIR, '20200101-000000.meta.json'))
    name_b = dh.save({'base_dn': B, 'users': {}}, 'admin', base_dn=B)
    assert [s['name'] for s in dh.list_snapshots(B)] == [name_b]
    assert [s['name'] for s in dh.list_snapshots(A)] == ['20200101-000000']      # rangée dans son domaine
    assert os.path.isfile(os.path.join(dh.SNAP_DIR, 'laprovidence.local', '20200101-000000.json.gz'))
    assert dh.load('20200101-000000', A)['base_dn'] == A
    with pytest.raises(dh.HistoryError):
        dh.load(name_b, A)                                                       # pas de mélange entre domaines


# --- Forêt ---------------------------------------------------------------------

class _A:
    def __init__(self, v):
        self.values = v if isinstance(v, list) else [v]
        self.value = v


class _E:
    def __init__(self, dn, **attrs):
        self.entry_dn = dn
        for k, v in attrs.items():
            setattr(self, k, _A(v))

    def __contains__(self, name):
        return hasattr(self, name)


CONFIG = f'CN=Configuration,{A}'


def ntds(server, site, options=0):
    return _E(f'CN=NTDS Settings,CN={server},CN=Servers,CN={site},CN=Sites,{CONFIG}', options=options)


class ForestConn:
    def __init__(self, dcs=None, trusts=None, level='6'):
        self.server = type('S', (), {})()
        self.server.info = type('I', (), {'other': {
            'configurationNamingContext': [CONFIG], 'rootDomainNamingContext': [A], 'defaultNamingContext': [A],
            'domainFunctionality': [level], 'forestFunctionality': ['6'], 'dnsHostName': ['SRV-DC02.laprovidence.local']}})()
        self.dcs = dcs
        self.trusts = trusts
        self.entries, self.result = [], {'result': 0}

    def unbind(self):
        pass

    def search(self, base, flt, scope=None, attributes=None, **k):
        owner = lambda s: [_E(base, fSMORoleOwner=f'CN=NTDS Settings,CN={s},CN=Servers,CN=Lyon,CN=Sites,{CONFIG}')]
        if base == f'CN=Partitions,{CONFIG}' and 'crossRef' in flt:
            self.entries = [_E('CN=LAPROVIDENCE,' + base, nETBIOSName='LAPROVIDENCE', dnsRoot='laprovidence.local',
                               nCName=A, systemFlags=3),
                            _E('CN=COLLEGE,' + base, nETBIOSName='COLLEGE', dnsRoot='college.laprovidence.local',
                               nCName=B, systemFlags=3),
                            _E('CN=Enterprise Configuration,' + base, nCName=CONFIG, systemFlags=1)]
        elif base == f'CN=System,{A}':
            self.entries = self.trusts if self.trusts is not None else [
                _E(f'CN=college.laprovidence.local,CN=System,{A}', trustPartner='college.laprovidence.local',
                   flatName='COLLEGE', trustDirection=3, trustType=2, trustAttributes=0x20),
                _E(f'CN=partenaire.fr,CN=System,{A}', trustPartner='partenaire.fr', flatName='PARTENAIRE',
                   trustDirection=3, trustType=2, trustAttributes=0)]
        elif base == f'CN=Sites,{CONFIG}':
            self.entries = [ntds('SRV-DC02', 'Lyon', 1), ntds('SRV-DC01', 'Paris')]
        elif base == f'CN=Schema,{CONFIG}' or base == f'CN=Partitions,{CONFIG}':
            self.entries = owner('SRV-DC02')
        elif base in (A, f'CN=RID Manager$,CN=System,{A}', f'CN=Infrastructure,{A}') and 'fSMORoleOwner' in (attributes or []):
            self.entries = owner('SRV-DC02' if base == A else 'SRV-DC01')
        elif flt == '(objectClass=computer)':
            self.entries = self.dcs if self.dcs is not None else [
                _E(f'CN=SRV-DC02,OU=Domain Controllers,{A}', cn='SRV-DC02', dNSHostName='SRV-DC02.laprovidence.local',
                   operatingSystem='Windows Server 2022 Standard', userAccountControl=0x82000, primaryGroupID=516),
                _E(f'CN=SRV-DC01,OU=Domain Controllers,{A}', cn='SRV-DC01', dNSHostName='SRV-DC01.laprovidence.local',
                   operatingSystem='Windows Server 2012 R2 Standard', userAccountControl=0x82000, primaryGroupID=516),
                _E(f'CN=PC-01,OU=Postes,{A}', cn='PC-01', userAccountControl=0x1000, primaryGroupID=515)]
        else:
            self.entries = []
        return True


def test_lecture_de_la_foret(monkeypatch):
    import routes.core as rc
    monkeypatch.setattr(rc, 'paged_search', lambda conn, base, flt, attributes=None, **k:
                        (conn.search(base, flt, attributes=attributes), conn.entries)[1])
    data = fo.read(ForestConn(), A)
    assert data['dns'] == 'laprovidence.local' and data['forest_root'] == 'laprovidence.local'
    assert data['domain_level']['label'] == 'Windows Server 2012 R2' and not data['notes']
    assert [(d['dns'], d['root'], d['current']) for d in data['domains']] == [
        ('laprovidence.local', True, True), ('college.laprovidence.local', False, False)]
    trusts = {t['partner']: t for t in data['trusts']}
    assert trusts['college.laprovidence.local']['within_forest'] and trusts['college.laprovidence.local']['transitive']
    assert trusts['partenaire.fr']['category'] == 'Approbation externe' and not trusts['partenaire.fr']['sid_filtering']
    dcs = {d['name']: d for d in data['dcs']}
    assert set(dcs) == {'SRV-DC01', 'SRV-DC02'} and dcs['SRV-DC02']['gc'] and not dcs['SRV-DC01']['gc']
    assert dcs['SRV-DC02']['site'] == 'Lyon' and dcs['SRV-DC02']['current']
    assert 'Émulateur PDC' in dcs['SRV-DC02']['roles'] and 'Maître RID' in dcs['SRV-DC01']['roles']
    keys = {f['key']: f for f in fo.findings(data)}
    assert keys['trust_sid_filtering']['items'][0]['name'] == 'partenaire.fr'
    assert keys['dc_old_os']['items'][0]['name'] == 'SRV-DC01' and 'single_dc' not in keys
    assert keys['functional_level']['severity'] == 'info' and 'trust_not_selective' in keys


def test_foret_saine_et_lectures_en_echec(monkeypatch):
    import routes.core as rc
    monkeypatch.setattr(rc, 'paged_search', lambda conn, base, flt, attributes=None, **k:
                        (conn.search(base, flt, attributes=attributes), conn.entries)[1])
    one = [_E(f'CN=SRV-DC02,OU=Domain Controllers,{A}', cn='SRV-DC02', operatingSystem='Windows Server 2022',
              userAccountControl=0x82000, primaryGroupID=516)]
    data = fo.read(ForestConn(dcs=one, trusts=[], level='7'), A)
    assert [f['key'] for f in fo.findings(data)] == ['single_dc']

    class Broken(ForestConn):
        def search(self, base, flt, *a, **k):
            raise RuntimeError('refusé')
    data = fo.read(Broken(), A)
    assert data['domains'] == [] and data['dcs'] == [] and len(data['notes']) >= 3
    assert all(r['server'] == 'Inconnu' for r in data['roles'])


def test_api_foret_et_consolidation(client, monkeypatch):
    import routes.domains as rd
    c, token, do_login = client
    do_login('dc-a', 'LAPROVIDENCE')
    monkeypatch.setattr(rd, 'get_ad_connection', lambda *a, **k: (ForestConn(), None))
    import routes.core as rc
    monkeypatch.setattr(rc, 'paged_search', lambda conn, base, flt, attributes=None, **k:
                        (conn.search(base, flt, attributes=attributes), conn.entries)[1])
    d = c.get('/domains/api/forest').get_json()
    assert d['success'] and d['findings'] and d['domains'][0]['connected'] is True
    college = d['domains'][1]
    assert not college['connected'] and 'add=1' in college['connect_url'] and 'COLLEGE' in college['connect_url']
    monkeypatch.setattr(dom, 'for_each', lambda func, keys=None, timeout=0: {
        'laprovidence.local': {'ok': True, 'result': {'users': 10, 'active': 8, 'disabled': 2, 'locked': 1, 'groups': 6,
                                                     'computers': 4, 'dcs': 1, 'level': 'Windows Server 2016'}, 'error': ''}})
    s = c.get('/domains/api/summary').get_json()
    assert s['domains'][0]['active'] == 8 and s['domains'][0]['ok']
    r = c.get('/domains/')
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and 'Domaines connectés' in html and 'domain-switcher' in html
    assert html.count('data-domain="laprovidence.local"') == 1


def test_recherche_rapide_sur_tous_les_domaines(client, monkeypatch):
    import routes.api as api
    c, token, do_login = client
    do_login('dc-a', 'LAPROVIDENCE')
    do_login('dc-b', 'COLLEGE', add=True)

    class Conn:
        def unbind(self):
            pass
    monkeypatch.setattr(api, 'get_ad_connection', lambda *a, **k: (Conn(), None))
    monkeypatch.setattr(api, '_quick_rows', lambda conn, base, q: [
        {'kind': 'user', 'label': 'Martin ' + dom.domain_key(base), 'detail': '', 'dn': f'CN=Martin,{base}'}])
    monkeypatch.setattr(dom, 'for_each', lambda func, keys=None, timeout=0: {
        k: {'ok': True, 'result': func(Conn(), dom.base_dn_of(k), k), 'error': ''} for k in keys})
    rows = c.get('/api/quick-search?q=mart').get_json()
    assert [r.get('domain') for r in rows] == [None, 'laprovidence.local']                # domaine actif d'abord
    assert rows[1]['switch'] == 'laprovidence.local' and 'DC=laprovidence' in rows[1]['url']
    assert all('dn' not in r for r in rows)


def test_microsoft_365_lit_tous_les_domaines(client, monkeypatch):
    from core import m365
    c, token, do_login = client
    do_login('dc-a', 'LAPROVIDENCE')
    do_login('dc-b', 'COLLEGE', add=True)
    monkeypatch.setattr(m365, 'fetch', lambda refresh=False: {
        'organization': {'name': 'x', 'sync_enabled': True, 'last_sync': ''}, 'skus': {}, 'at': 0,
        'users': [{'name': 'Bob', 'upn': 'bob@college.fr', 'mail': '', 'enabled': True, 'guest': False, 'synced': True,
                   'sam': 'bob', 'anchor': 'B1', 'last_sync': '', 'created': '', 'licenses': []}]})
    monkeypatch.setattr(dom, 'for_each', lambda func, keys=None, timeout=0: {
        'laprovidence.local': {'ok': True, 'error': '', 'result': []},
        'college.laprovidence.local': {'ok': True, 'error': '', 'result': [
            {'dn': f'CN=Bob,{B}', 'sam': 'bob', 'name': 'Bob', 'upn': 'bob@college.fr', 'mail': '', 'enabled': True,
             'anchor': 'B1'}]}})
    d = c.get('/m365/api/overview').get_json()
    assert d['success'] and d['findings']['orphans'] == [] and sorted(d['domains']) == [
        'college.laprovidence.local', 'laprovidence.local']
    assert d['findings']['unlicensed'][0]['domain'] == 'college.laprovidence.local'


def test_permission_et_menu():
    from core import granular_permissions as gperm
    from core.settings_manager import DEFAULT_SETTINGS
    assert 'domains:read' in gperm.ALL_PERMISSIONS
    assert any(i['endpoint'] == 'domains.index' for i in DEFAULT_SETTINGS['menu']['admin_items'])
    assert re.search(r"'domains:read'", (os.path.join and open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), 'templates', 'partials', '_sidebar.html'), encoding='utf-8').read()))
