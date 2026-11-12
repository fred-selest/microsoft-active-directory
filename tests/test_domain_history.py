# -*- coding: utf-8 -*-
"""
Journal du domaine (core/domain_history.py, routes/history) : photos,
comparaison en événements classés par gravité, annulation, alerte e-mail,
photo quotidienne et compte de lecture.
"""
import copy
import os
import re

import pytest

os.environ.setdefault('SECRET_KEY', 'test-history')

from core import domain_history as dh  # noqa: E402

BASE = 'DC=corp,DC=local'
G = '{AAAAAAAA-0000-0000-0000-000000000001}'


def link(guid, options=0):
    return f'[LDAP://cn={guid},cn=policies,cn=system,{BASE};{options}]'


def state():
    return {
        'base_dn': BASE, 'notes': [],
        'users': {
            'u1': dict(dn='CN=Alice,OU=Siege,' + BASE, name='alice', display='Alice', upn='alice@corp.local',
                       mail='', enabled=True, pwd_never_expires=False, admin=False),
            'u2': dict(dn='CN=Bob,OU=Siege,' + BASE, name='bob', display='Bob', upn='bob@corp.local',
                       mail='', enabled=True, pwd_never_expires=False, admin=False),
        },
        'groups': {
            'g-da': dict(dn='CN=Admins du domaine,CN=Users,' + BASE, name='Admins du domaine', privileged=True,
                         members=['CN=Administrateur,CN=Users,' + BASE]),
            'g-compta': dict(dn='CN=Compta,OU=Siege,' + BASE, name='Compta', privileged=False,
                             members=['CN=Alice,OU=Siege,' + BASE, 'CN=Bob,OU=Siege,' + BASE]),
        },
        'computers': {'c1': dict(dn='CN=PC1,OU=Siege,' + BASE, name='PC1', os='Windows 11', enabled=True)},
        'ous': {'o1': dict(dn='OU=Siege,' + BASE, name='Siege', gplink=link(G), block=False)},
        'gpos': {G: dict(dn=f'CN={G},CN=Policies,CN=System,{BASE}', name='Pare-feu', flags=0, user_version=1,
                         computer_version=4, filtering=['Utilisateurs authentifiés'], denied=[])},
        'shares': {r'\\SRV\Partages': dict(protected=False, aces=['S-1-5-32-544|Administrateurs|Autoriser|Contrôle total|Tout']),
                   r'\\SRV\Partages\Paie': dict(protected=True, aces=['S-1-5-21-1-1200|Compta|Autoriser|Modification|Tout'])},
    }


def titles(events, severity=None):
    return [e['title'] for e in events if severity is None or e['severity'] == severity]


class TestDiff:
    def test_aucun_changement(self):
        assert dh.diff(state(), state()) == []

    def test_ajout_a_un_groupe_privilegie(self):
        new = state()
        new['groups']['g-da']['members'].append('CN=Bob,OU=Siege,' + BASE)
        events = dh.diff(state(), new)
        assert titles(events, 'critical') == ['bob ajouté à Admins du domaine']
        assert events[0]['revert'] == {'op': 'remove_member', 'group': 'CN=Admins du domaine,CN=Users,' + BASE,
                                       'member': 'CN=Bob,OU=Siege,' + BASE}

    def test_deplacement_sans_faux_changement(self):
        """Un compte déplacé reste le même objet : pas de « retiré / ajouté » dans ses groupes."""
        new = state()
        new['users']['u1']['dn'] = 'CN=Alice,OU=Paris,' + BASE
        new['groups']['g-compta']['members'][0] = 'CN=Alice,OU=Paris,' + BASE
        events = dh.diff(state(), new)
        assert titles(events) == ['Compte déplacé : alice']

    def test_comptes(self):
        new = state()
        new['users']['u2']['enabled'] = False
        new['users']['u1']['pwd_never_expires'] = True
        new['users']['u1']['admin'] = True
        del new['computers']['c1']
        new['users']['u3'] = dict(dn='CN=Eve,CN=Users,' + BASE, name='eve', display='', upn='', mail='',
                                  enabled=True, pwd_never_expires=False, admin=False)
        events = dh.diff(state(), new)
        assert titles(events, 'critical') == ['Compte devenu privilégié : alice']
        assert 'Mot de passe sans expiration : alice' in titles(events, 'warning')
        assert {'Compte créé : eve', 'Compte désactivé : bob', 'Ordinateur supprimé : PC1'} <= set(titles(events, 'info'))
        disabled = [e for e in events if e['title'] == 'Compte désactivé : bob'][0]
        assert disabled['revert'] == {'op': 'set_enabled', 'dn': 'CN=Bob,OU=Siege,' + BASE, 'enabled': True}

    def test_strategies(self):
        new = state()
        new['gpos'][G]['computer_version'] = 5
        new['gpos'][G]['flags'] = 3
        new['ous']['o1']['gplink'] = ''
        new['ous']['o1']['block'] = True
        events = dh.diff(state(), new)
        assert set(titles(events, 'warning')) == {
            'Paramètres modifiés : Pare-feu', 'État changé : Pare-feu',
            'Stratégies liées modifiées sur Siege', 'Héritage des stratégies bloqué sur Siege'}
        links = [e for e in events if 'liées' in e['title']][0]
        assert links['detail'] == 'déliée : Pare-feu' and links['revert']['value'] == link(G)
        del new['gpos'][G]
        assert 'Stratégie supprimée : Pare-feu' in titles(dh.diff(state(), new), 'critical')

    def test_partages(self):
        new = state()
        new['shares'][r'\\SRV\Partages\Paie']['aces'].append('S-1-1-0|Tout le monde|Autoriser|Modification|Tout')
        new['shares'][r'\\SRV\Partages']['aces'].append('S-1-5-21-1-1300|RH|Autoriser|Lecture et exécution|Tout')
        events = dh.diff(state(), new)
        crit = [e for e in events if e['severity'] == 'critical'][0]
        assert 'ouvert à tous les comptes' in crit['detail'] and crit['revert'] == {'op': 'folder', 'path': r'\\SRV\Partages\Paie'}
        assert len(titles(events, 'warning')) == 1

    def test_photo_sans_partages_ne_signale_rien(self):
        """Photo nocturne sans droits des partages : pas de « tout a disparu »."""
        new = state()
        new['shares'] = {}
        assert dh.diff(state(), new) == []


# --- Stockage, annulation, alerte -------------------------------------------

@pytest.fixture
def store(monkeypatch, tmp_path):
    monkeypatch.setattr(dh, 'SNAP_DIR', str(tmp_path / 'snapshots'))
    names = iter(['20261110-020000', '20261111-020000', '20261112-020000'])

    class FakeDatetime(dh.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.strptime(next(names), '%Y%m%d-%H%M%S')
    monkeypatch.setattr(dh, 'datetime', FakeDatetime)
    return tmp_path


class Conn:
    def __init__(self):
        self.modified, self.entries, self.result = [], [], {'result': 0}

    def search(self, base, flt, scope=None, attributes=None, **k):
        class A:
            value = 514
        class E:
            userAccountControl = A()
        self.entries = [E()]

    def modify(self, dn, changes):
        self.modified.append((dn, changes))
        return True

    def unbind(self):
        pass


def two_snapshots(change):
    old, new = state(), state()
    change(new)
    a = dh.save(old, 'CORP\\admin')
    b = dh.save(new, 'CORP\\admin', dh.diff(old, new))
    return a, b, dh.diff(old, new)


class TestStoreAndRevert:
    def test_liste_et_compteurs(self, store):
        a, b, _ = two_snapshots(lambda n: n['groups']['g-da']['members'].append('CN=Bob,OU=Siege,' + BASE))
        snaps = dh.list_snapshots()
        assert [s['name'] for s in snaps] == [b, a]
        assert snaps[0]['changes'] == {'critical': 1, 'warning': 0, 'info': 0} and snaps[0]['counts']['users'] == 2
        with pytest.raises(dh.HistoryError):
            dh.load('..\\..\\x')

    def test_annuler_un_ajout(self, store):
        a, b, events = two_snapshots(lambda n: n['groups']['g-da']['members'].append('CN=Bob,OU=Siege,' + BASE))
        conn = Conn()
        dh.revert(conn, BASE, a, b, events[0]['id'])
        dn, changes = conn.modified[0]
        assert dn == 'CN=Admins du domaine,CN=Users,' + BASE
        assert changes['member'][0][1] == ['CN=Bob,OU=Siege,' + BASE] and 'DELETE' in str(changes['member'][0][0])

    def test_annuler_une_desactivation(self, store):
        a, b, events = two_snapshots(lambda n: n['users']['u2'].update(enabled=False))
        conn = Conn()
        dh.revert(conn, BASE, a, b, events[0]['id'])
        assert conn.modified[0][1]['userAccountControl'][0][1] == [512]

    def test_annuler_des_liens(self, store):
        a, b, events = two_snapshots(lambda n: n['ous']['o1'].update(gplink=''))
        conn = Conn()
        dh.revert(conn, BASE, a, b, events[0]['id'])
        assert conn.modified[0] == ('OU=Siege,' + BASE, {'gPLink': [(conn.modified[0][1]['gPLink'][0][0], [link(G)])]})

    def test_refus(self, store):
        a, b, events = two_snapshots(lambda n: n['gpos'][G].update(computer_version=9))
        conn = Conn()
        with pytest.raises(dh.HistoryError):                 # restauration de GPO : pas automatique
            dh.revert(conn, BASE, a, b, events[0]['id'])
        with pytest.raises(dh.HistoryError):
            dh.revert(conn, BASE, a, b, 'inconnu')
        assert not conn.modified

    def test_alerte(self, store, monkeypatch):
        import core.mailer as mailer
        sent = []
        monkeypatch.setattr(mailer, 'is_configured', lambda *a: True)
        monkeypatch.setattr(mailer, 'default_recipient', lambda *a: 'it@corp.local')
        monkeypatch.setattr(mailer, 'send_mail', lambda to, subject, text, **k: sent.append((to, subject, text)))
        _, b, events = two_snapshots(lambda n: n['groups']['g-da']['members'].append('CN=Bob,OU=Siege,' + BASE))
        assert dh.notify(events, b) is True
        assert sent[0][0] == 'it@corp.local' and 'bob ajouté à Admins du domaine' in sent[0][2]
        assert dh.notify([e for e in events if e['severity'] != 'critical'], b) is False


# --- Collecte ----------------------------------------------------------------

class _A:
    def __init__(self, v):
        self.value = v
        self.values = v if isinstance(v, list) else [v]


class _E:
    def __init__(self, dn, **attrs):
        self.entry_dn = dn
        for k, v in attrs.items():
            setattr(self, k, _A(v))

    def __contains__(self, name):
        return hasattr(self, name)


def test_collecte(monkeypatch):
    import routes.core as rc
    from core import gpo as gp

    def paged(conn, base, flt, attributes=None, **k):
        if 'objectCategory=person' in flt:
            return [_E('CN=Alice,' + BASE, objectGUID='{11111111-1111-1111-1111-111111111111}',
                       sAMAccountName='alice', userAccountControl=66050, adminCount=1)]
        if 'objectClass=group' in flt:
            return [_E('CN=Admins du domaine,CN=Users,' + BASE, objectGUID='{22222222-2222-2222-2222-222222222222}',
                       sAMAccountName='Admins du domaine', objectSid='S-1-5-21-1-2-3-512',
                       member=['CN=Alice,' + BASE]),
                    _E('CN=Compta,' + BASE, objectGUID='{33333333-3333-3333-3333-333333333333}',
                       sAMAccountName='Compta', objectSid='S-1-5-21-1-2-3-1200')]
        return []
    monkeypatch.setattr(rc, 'paged_search', paged)
    monkeypatch.setattr(gp, 'load_all', lambda c, b: {'gpos': []})
    data = dh.collect(object(), BASE)
    user = data['users']['11111111-1111-1111-1111-111111111111']
    assert user == dict(dn='CN=Alice,' + BASE, name='alice', display='', upn='', mail='', enabled=False,
                        pwd_never_expires=True, admin=True)
    groups = {g['name']: g for g in data['groups'].values()}
    assert groups['Admins du domaine']['privileged'] and not groups['Compta']['privileged']
    assert groups['Compta']['members'] == [] and data['shares'] == {}


# --- Routes ------------------------------------------------------------------

@pytest.fixture
def client(store, monkeypatch):
    import routes.history as rh
    from app import app
    from core.session_crypto import encrypt_password
    import core.settings_manager as sm
    monkeypatch.setattr(sm, 'SETTINGS_FILE', str(store / 'settings.json'))
    conn = Conn()
    monkeypatch.setattr(rh, 'get_ad_connection', lambda *a, **k: (conn, None))
    monkeypatch.setattr(rh, '_state', {'day': None, 'scheduler': True, 'last_error': None})
    app.config['TESTING'] = True
    c = app.test_client()
    with c.session_transaction() as s:
        s.update(ad_server='dc', ad_username='CORP\\admin', ad_password=encrypt_password('Secret-1'),
                 ad_base_dn=BASE, user_role='admin', user_groups=['Domain Admins'])
    tok = re.search(rb'name="csrf-token" content="([^"]+)"', c.get('/history/').data).group(1).decode()
    return c, conn, tok, rh


class TestRoutes:
    def test_page_vide_puis_comparaison(self, client):
        c, _, _, _ = client
        assert 'Aucune photo du domaine' in c.get('/history/').get_data(as_text=True)
        two_snapshots(lambda n: n['groups']['g-da']['members'].append('CN=Bob,OU=Siege,' + BASE))
        html = c.get('/history/').get_data(as_text=True)
        assert 'bob ajouté à Admins du domaine' in html and 'Retirer du groupe' in html and 'Critique' in html

    def test_annulation_par_formulaire(self, client):
        c, conn, tok, _ = client
        a, b, events = two_snapshots(lambda n: n['users']['u2'].update(enabled=False))
        r = c.post('/history/revert', data={'csrf_token': tok, 'a': a, 'b': b, 'event': events[0]['id']})
        assert r.status_code == 302 and conn.modified

    def test_lecture_seule(self, client):
        c, conn, tok, _ = client
        a, b, events = two_snapshots(lambda n: n['users']['u2'].update(enabled=False))
        with c.session_transaction() as s:
            s.update(user_role='user', user_groups=['Utilisateurs du domaine'])
        assert c.get('/history/').status_code in (302, 403)
        c.post('/history/revert', data={'csrf_token': tok, 'a': a, 'b': b, 'event': events[0]['id']})
        assert not conn.modified

    def test_photo_en_arriere_plan(self, client, monkeypatch):
        c, _, tok, rh = client
        started = []
        monkeypatch.setattr(rh, '_start', lambda creds, by, notify: started.append((creds, by, notify)))
        c.post('/history/snapshot', data={'csrf_token': tok})
        creds, by, _ = started[0]
        assert by == 'CORP\\admin' and creds['password'] == 'Secret-1' and creds['base_dn'] == BASE

    def test_photo_quotidienne_une_seule_fois(self, client, monkeypatch):
        c, _, _, rh = client
        started = []
        monkeypatch.setattr(rh, '_start', lambda *a: started.append(a))
        c.application.config['HISTORY_AUTO_IN_TESTS'] = True
        try:
            c.get('/dashboard')
            c.get('/dashboard')
        finally:
            c.application.config['HISTORY_AUTO_IN_TESTS'] = False
        assert len(started) == 1

    def test_compte_de_lecture(self, client):
        import core.settings_manager as sm
        c, _, tok, rh = client
        c.post('/history/settings', data={'csrf_token': tok, 'auto_daily': 'on', 'hour': '3',
                                          'service_username': 'CORP\\svc-lecture', 'service_password': 'Tr3s-Long!'})
        raw = sm.load_settings()['history']
        assert raw['service']['username'] == 'CORP\\svc-lecture' and raw['hour'] == 3
        assert 'Tr3s-Long!' not in str(raw) and raw['service']['password_enc']
        from core.session_crypto import decrypt_password
        assert decrypt_password(raw['service']['password_enc']) == 'Tr3s-Long!'
        assert 'Tr3s-Long!' not in c.get('/history/').get_data(as_text=True)

    def test_run_snapshot_hors_requete(self, client, monkeypatch):
        c, _, _, rh = client
        seen = {}

        def fake_take(conn, base, by, share_creds):
            seen.update(base=base, by=by, share=share_creds)
            return '20261112-020000', []
        monkeypatch.setattr(dh, 'take_snapshot', fake_take)
        name = rh.run_snapshot(c.application, {'server': 'dc', 'username': 'svc', 'password': 'p',
                                               'base_dn': 'OU=X,' + BASE}, 'planification')
        assert name == '20261112-020000' and seen['share'] == ('svc@corp.local', 'p')


def test_photo_plus_recente_signalee(client):
    """Une comparaison ancienne restée dans l'adresse ne doit pas masquer la dernière photo."""
    c, _, _, _ = client
    a = dh.save(state(), 'CORP\\admin')
    b = dh.save(state(), 'CORP\\admin')
    new = state()
    new['users']['u2']['enabled'] = False
    last = dh.save(new, 'CORP\\admin', dh.diff(state(), new))
    html = c.get(f'/history/?a={a}&b={b}').get_data(as_text=True)
    assert 'Une photo plus récente existe' in html and '1 changement(s)' in html
    html = c.get('/history/').get_data(as_text=True)
    assert 'Une photo plus récente existe' not in html and 'Compte désactivé : bob' in html
    status = c.get('/history/api/status').get_json()
    assert status == {'running': False, 'latest': last, 'error': None}


def test_photo_en_cours_visible_tout_de_suite(client, monkeypatch):
    import threading
    c, _, tok, rh = client
    gate = threading.Event()
    monkeypatch.setattr(rh, '_run_snapshot', lambda *a: gate.wait(5))
    c.post('/history/snapshot', data={'csrf_token': tok})
    assert c.get('/history/api/status').get_json()['running'] is True
    assert 'Photo en cours' in c.get('/history/').get_data(as_text=True)
    gate.set()
    for _ in range(100):
        if not c.get('/history/api/status').get_json()['running']:
            break
        import time
        time.sleep(0.02)
    assert c.get('/history/api/status').get_json()['running'] is False
