# -*- coding: utf-8 -*-
"""
Fiche 360° et départ d'un collaborateur (core/offboarding.py,
routes/users/overview.py) : aperçu, étapes indépendantes, rapport,
annulation, conversion de la boîte, droits.
"""
import os
import re

import pytest

os.environ.setdefault('SECRET_KEY', 'test-offboarding')

from core import offboarding as ob  # noqa: E402

BASE = 'DC=laprovidence,DC=local'
OU = 'OU=Compta,' + BASE
OU_OUT = 'OU=Departs,' + BASE
USER = 'CN=Jean Dupont,' + OU
G1 = 'CN=GG_Compta,OU=Groupes,' + BASE
G2 = 'CN=LIC_M365,OU=Groupes,' + BASE


class _A:
    def __init__(self, v):
        self.values = v if isinstance(v, list) else [v]
        self.value = v

    def __str__(self):
        return str(self.value)


class _E:
    def __init__(self, dn, **attrs):
        self.entry_dn = dn
        for k, v in attrs.items():
            setattr(self, k, _A(v))

    def __contains__(self, name):
        return hasattr(self, name)


class Conn:
    """Annuaire minimal avec état : un utilisateur, deux groupes."""

    def __init__(self, sam='jdupont', admin=False):
        self.dn, self.sam, self.admin = USER, sam, admin
        self.uac, self.description = 512, 'Comptable'
        self.groups = {G1: True, G2: True}
        self.hidden, self.password = False, None
        self.fail = set()                 # attributs (ou 'move', ou DN de groupe) dont l'écriture échoue
        self.result = {'result': 0}
        self.entries = []

    def search(self, base, flt, scope=None, attributes=None, **k):
        self.entries = []
        if base.lower() == self.dn.lower() and 'user' in flt:
            self.entries = [_E(self.dn, sAMAccountName=self.sam, displayName='Jean Dupont', cn='Jean Dupont',
                               userPrincipalName='jean.dupont@laprovidence.fr',
                               mail='jean.dupont@laprovidence.fr',
                               memberOf=[g for g, m in self.groups.items() if m],
                               userAccountControl=self.uac, description=self.description,
                               adminCount=1 if self.admin else 0, homeDirectory=r'\\srv\perso\jdupont',
                               proxyAddresses=['SMTP:jean.dupont@laprovidence.fr', 'smtp:jd@laprovidence.fr'],
                               otherMailbox=['jean@perso.fr'], title='Comptable', department='Compta')]
        return bool(self.entries)

    def _done(self, ok):
        self.result = {'result': 0} if ok else {'result': 50, 'message': 'accès refusé'}
        return ok

    def modify(self, dn, changes):
        if dn in self.groups:
            if dn in self.fail:
                return self._done(False)
            self.groups[dn] = changes['member'][0][0] == 'MODIFY_ADD'
            return self._done(True)
        if dn.lower() != self.dn.lower() or self.fail & set(changes):
            return self._done(False)
        for attr, ((_, vals),) in changes.items():
            if attr == 'userAccountControl':
                self.uac = vals[0]
            elif attr == 'description':
                self.description = vals[0] if vals else ''
            elif attr == 'unicodePwd':
                self.password = vals[0]
            elif attr == 'msExchHideFromAddressLists':
                self.hidden = bool(vals)
        return self._done(True)

    def modify_dn(self, dn, rdn, new_superior=None):
        if 'move' in self.fail:
            return self._done(False)
        self.dn = f'{rdn},{new_superior}'
        return self._done(True)

    def unbind(self):
        pass


@pytest.fixture(autouse=True)
def reports(tmp_path, monkeypatch):
    monkeypatch.setattr(ob, 'REPORT_DIR', str(tmp_path / 'offboarding'))
    return tmp_path / 'offboarding'


class TestPlan:
    def test_apercu(self):
        info = ob.plan(Conn(), BASE, USER, 'LAPROVIDENCE\\admin')
        assert info['sam'] == 'jdupont' and info['enabled'] and info['ou'] == OU
        assert [g['name'] for g in info['groups']] == ['GG_Compta', 'LIC_M365'] and not info['warnings']

    def test_avertissements(self):
        info = ob.plan(Conn(admin=True), BASE, USER, 'LAPROVIDENCE\\JDupont')
        assert len(info['warnings']) == 2

    def test_refus(self):
        with pytest.raises(ob.OffboardingError):
            ob.plan(Conn(), BASE, 'CN=X,DC=autre,DC=local')
        with pytest.raises(ob.OffboardingError):
            ob.plan(Conn(), BASE, 'CN=Inconnu,' + OU)
        with pytest.raises(ob.OffboardingError):
            ob.plan(Conn(sam='Administrateur'), BASE, USER)


class TestExecute:
    def test_depart_complet(self, reports):
        conn = Conn()
        r = ob.execute(conn, BASE, USER, ['disable', 'password', 'groups', 'hide', 'move'],
                       'LAPROVIDENCE\\admin', target_ou=OU_OUT)
        assert [s['step'] for s in r['steps']] == ['disable', 'password', 'groups', 'hide', 'move']
        assert all(s['ok'] for s in r['steps'])
        assert conn.uac & 2 and conn.description.startswith('Départ le ') and 'Comptable' in conn.description
        assert not any(conn.groups.values()) and conn.hidden and conn.password
        assert conn.dn == 'CN=Jean Dupont,' + OU_OUT == r['dn']
        assert r['original'] == {'dn': USER, 'ou': OU, 'enabled': True, 'description': 'Comptable',
                                 'groups': [G1, G2]}
        saved = (reports / (r['id'] + '.json')).read_text(encoding='utf-8')
        assert conn.password.decode('utf-16-le').strip('"') not in saved       # mot de passe jamais conservé
        assert ob.load(r['id'])['sam'] == 'jdupont' and len(ob.list_reports('JDUPONT')) == 1
        assert ob.list_reports('autre') == []

    def test_etapes_independantes(self):
        conn = Conn()
        conn.fail = {'msExchHideFromAddressLists', G2, 'move'}
        r = ob.execute(conn, BASE, USER, list(ob.STEPS)[:4] + ['move'], 'admin', target_ou=OU_OUT)
        ok = {s['step']: s['ok'] for s in r['steps']}
        assert ok == {'disable': True, 'password': True, 'groups': False, 'hide': False, 'move': False}
        assert conn.groups == {G1: False, G2: True} and r['dn'] == USER
        assert 'LIC_M365' in next(s['detail'] for s in r['steps'] if s['step'] == 'groups')

    def test_sans_ldaps_pas_de_mot_de_passe(self):
        conn = Conn()
        r = ob.execute(conn, BASE, USER, ['disable', 'password'], 'admin', can_set_password=False)
        assert [s['ok'] for s in r['steps']] == [True, False] and conn.password is None

    def test_exception_ldap_ne_bloque_pas_la_suite(self):
        conn = Conn()
        real = conn.modify

        def modify(dn, changes):
            if 'msExchHideFromAddressLists' in changes:
                raise ValueError('invalid attribute type msExchHideFromAddressLists')
            return real(dn, changes)
        conn.modify = modify
        r = ob.execute(conn, BASE, USER, ['hide', 'move'], 'admin', target_ou=OU_OUT)
        assert [s['ok'] for s in r['steps']] == [False, True] and 'Microsoft 365' in r['steps'][0]['detail']

    def test_garde_fous(self):
        with pytest.raises(ob.OffboardingError):
            ob.execute(Conn(), BASE, USER, [], 'admin')
        with pytest.raises(ob.OffboardingError):
            ob.execute(Conn(), BASE, USER, ['move'], 'admin', target_ou='')
        with pytest.raises(ob.OffboardingError):
            ob.execute(Conn(), BASE, USER, ['move'], 'admin', target_ou='OU=X,DC=autre,DC=local')
        conn = Conn()                                    # déjà dans l'OU des départs : pas de déplacement
        r = ob.execute(conn, BASE, USER, ['disable', 'move'], 'admin', target_ou=OU.lower())
        assert [s['step'] for s in r['steps']] == ['disable']

    def test_boite_partagee(self, monkeypatch):
        from core import exchange as ex
        calls = []
        monkeypatch.setattr(ex, 'convert_to_shared', lambda a: calls.append(('shared', a)) or a)
        monkeypatch.setattr(ex, 'grant', lambda a, u, full, send: calls.append(('grant', a, u, full, send)) or (a, u))
        r = ob.execute(Conn(), BASE, USER, ['mailbox'], 'admin', mailbox_delegate='chef@laprovidence.fr')
        assert r['steps'][0]['ok'] and 'chef@laprovidence.fr' in r['steps'][0]['detail']
        assert calls == [('shared', 'jean.dupont@laprovidence.fr'),
                         ('grant', 'jean.dupont@laprovidence.fr', 'chef@laprovidence.fr', True, False)]

        def boom(a):
            raise ex.ExchangeError('Exchange Online injoignable')
        monkeypatch.setattr(ex, 'convert_to_shared', boom)
        r = ob.execute(Conn(), BASE, USER, ['disable', 'mailbox'], 'admin')
        assert [s['ok'] for s in r['steps']] == [True, False]


class TestUndo:
    def test_annulation(self):
        conn = Conn()
        r = ob.execute(conn, BASE, USER, list(ob.DEFAULT_STEPS), 'admin', target_ou=OU_OUT)
        u = ob.undo(conn, BASE, r['id'], 'LAPROVIDENCE\\chef')
        assert all(x['ok'] for x in u['undone']['results']) and len(u['undone']['results']) == 4
        assert not conn.hidden and conn.dn == USER and conn.uac == 512 and conn.description == 'Comptable'
        assert conn.groups == {G1: True, G2: True}
        assert ob.load(r['id'])['undone']['by'] == 'LAPROVIDENCE\\chef'
        with pytest.raises(ob.OffboardingError):
            ob.undo(conn, BASE, r['id'], 'admin')

    def test_compte_deja_desactive_reste_desactive(self):
        conn = Conn()
        conn.uac = 514
        r = ob.execute(conn, BASE, USER, ['disable', 'groups'], 'admin')
        ob.undo(conn, BASE, r['id'], 'admin')
        assert conn.uac == 514 and all(conn.groups.values())

    def test_echec_partiel_et_compte_disparu(self):
        conn = Conn()
        r = ob.execute(conn, BASE, USER, ['groups', 'move'], 'admin', target_ou=OU_OUT)
        conn.fail = {G1}
        u = ob.undo(conn, BASE, r['id'], 'admin')
        assert [x['ok'] for x in u['undone']['results']] == [True, True, False]
        r2 = ob.execute(conn, BASE, USER, ['disable'], 'admin')
        conn.dn = 'CN=Ailleurs,' + BASE
        with pytest.raises(ob.OffboardingError):
            ob.undo(conn, BASE, r2['id'], 'admin')

    def test_identifiant_de_rapport(self):
        for bad in ('', '../../etc/passwd', '20260101-000000-..\\x', 'abc'):
            with pytest.raises(ob.OffboardingError):
                ob.load(bad)


# --- Routes ------------------------------------------------------------------

@pytest.fixture
def client(monkeypatch):
    import routes.core as rc
    import routes.users.overview as ro
    from app import app
    from core import gpo as gp
    from core.session_crypto import encrypt_password
    conn = Conn()
    monkeypatch.setattr(ro, 'get_ad_connection', lambda *a, **k: (conn, None))
    monkeypatch.setattr(rc, 'paged_search', lambda *a, **k: [_E(OU), _E(OU_OUT)])
    monkeypatch.setattr(gp, 'applied_gpos', lambda *a, **k: {'applied': [
        {'guid': '{AAAAAAAA-0000-0000-0000-000000000001}', 'name': 'Verrouillage écran',
         'source_name': 'Compta', 'via': 'Utilisateurs authentifiés'}], 'skipped': []})
    audit = []
    monkeypatch.setattr(ro, 'log_action', lambda *a, **k: audit.append(a))
    app.config['TESTING'] = True
    c = app.test_client()
    with c.session_transaction() as s:
        s.update(ad_server='dc', ad_username='LAPROVIDENCE\\admin', ad_password=encrypt_password('x'),
                 ad_base_dn=BASE, ad_use_ssl=True, user_role='admin', user_groups=['Domain Admins'])
    page = c.get(f'/users/{USER}/overview')
    tok = re.search(rb'name="csrf-token" content="([^"]+)"', page.data).group(1).decode()
    return c, conn, tok, audit


class TestRoutes:
    def test_fiche(self, client):
        c = client[0]
        html = c.get(f'/users/{USER}/overview').get_data(as_text=True)
        for needle in ('Jean Dupont', 'jdupont', 'GG_Compta', 'jd@laprovidence.fr', 'jean@perso.fr',
                       'Verrouillage écran', '/offboard', 'perso\\jdupont'):
            assert needle in html, needle
        assert c.get('/users/CN=X,DC=autre,DC=local/overview').status_code == 302

    def test_depart_puis_annulation(self, client):
        c, conn, tok, audit = client
        html = c.get(f'/users/{USER}/offboard').get_data(as_text=True)
        assert 'step_disable' in html and OU_OUT in html and 'GG_Compta, LIC_M365' in html
        assert 'step_mailbox' not in html                # Microsoft 365 non configuré dans ce test
        r = c.post(f'/users/{USER}/offboard', data={'csrf_token': tok, 'step_disable': 'on',
                                                    'step_groups': 'on', 'step_move': 'on',
                                                    'target_ou': OU_OUT})
        assert r.status_code == 302 and '/users/offboarding/' in r.headers['Location']
        assert conn.uac & 2 and conn.dn.endswith(OU_OUT) and audit[0][0] == 'offboard_user'
        report_url = r.headers['Location']
        html = c.get(report_url).get_data(as_text=True)
        assert 'Annuler le départ' in html and html.count('✅ Fait') == 3
        assert 'Départs enregistrés' in c.get(f'/users/{conn.dn}/overview').get_data(as_text=True)
        from core.settings_manager import get_setting
        assert get_setting('offboarding.ou') == OU_OUT
        r = c.post(report_url + '/undo', data={'csrf_token': tok})
        assert r.status_code == 302 and conn.dn == USER and conn.uac == 512
        assert 'Départ annulé le' in c.get(report_url).get_data(as_text=True)

    def test_sans_action(self, client):
        c, conn, tok, _ = client
        r = c.post(f'/users/{USER}/offboard', data={'csrf_token': tok})
        assert r.status_code == 302 and '/overview' in r.headers['Location'] and conn.uac == 512

    def test_droit_dedie(self, client, monkeypatch):
        from core import granular_permissions as gperm
        assert 'users:offboard' in gperm.ALL_PERMISSIONS and 'users:offboard' in gperm.SENSITIVE_PERMISSIONS
        c, conn, tok, _ = client
        with c.session_transaction() as s:
            s.update(user_role='reader', user_groups=[])
        monkeypatch.setattr(gperm, 'has_permission',
                            lambda groups, perm, **k: perm != 'users:offboard')
        r = c.post(f'/users/{USER}/offboard', data={'csrf_token': tok, 'step_disable': 'on'})
        assert r.status_code in (302, 403) and conn.uac == 512
        assert '🚪 Départ' not in c.get(f'/users/{USER}/overview').get_data(as_text=True)


def test_script_exchange_conversion():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts', 'exchange.ps1')
    raw = open(path, 'rb').read()
    assert raw.startswith(b'\xef\xbb\xbf') and b"'to_shared'" in raw and raw.count(b'\r\n') == raw.count(b'\n')
