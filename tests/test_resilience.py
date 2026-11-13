# -*- coding: utf-8 -*-
"""
Résistance au rançongiciel (core/resilience.py, routes/resilience) :
chemins vers les droits d'administration, comptes fragiles, partages
ouverts à tous, sauvegardes et clichés instantanés, note, pages.
"""
import json
import os
import re
from datetime import datetime, timedelta

import pytest

os.environ.setdefault('SECRET_KEY', 'test-resilience')

from core import resilience as rs  # noqa: E402

BASE = 'DC=laprovidence,DC=local'
DOM = 'S-1-5-21-111-222-333'
NOW = datetime(2026, 11, 13, 10, 0)


def user(name, rid, uac=512, pwd_days=30, logon_days=1, spn=(), admin_count=False, primary=513):
    dn = f'CN={name},OU=Comptes,{BASE}'
    return dn.lower(), {'dn': dn, 'sam': name.lower(), 'name': name, 'uac': uac,
                        'pwd_last_set': NOW - timedelta(days=pwd_days) if pwd_days is not None else None,
                        'last_logon': NOW - timedelta(days=logon_days) if logon_days is not None else None,
                        'spn': list(spn), 'admin_count': admin_count, 'primary_group': primary,
                        'sid': f'{DOM}-{rid}', 'member_of': []}


def group(name, sid, members=()):
    dn = f'CN={name},OU=Groupes,{BASE}'
    return dn.lower(), {'dn': dn, 'name': name, 'sid': sid, 'members': [m.lower() for m in members]}


def directory(**changes):
    users = dict([user('Chef', 1101), user('Adjoint', 1102), user('Service', 1103, spn=['HTTP/intranet']),
                  user('Ancien', 1104, uac=514), user('Dormeur', 1105, logon_days=200, uac=512 | rs.UF_DONT_EXPIRE,
                                                       pwd_days=900),
                  user('Operateur', 1106), user('Eleve', 1107), user('Roast', 1108, uac=512 | rs.UF_DONT_REQ_PREAUTH),
                  user('Vide', 1109, uac=512 | rs.UF_PASSWD_NOTREQD), user('ExAdmin', 1110, admin_count=True),
                  user('krbtgt', 502, uac=514, pwd_days=400), user('Principal', 1111, primary=512)])
    dn = {u['name']: u['dn'] for u in users.values()}
    groups = dict([group('Admins du domaine', f'{DOM}-512', [dn['Chef'], dn['Service'], dn['Ancien'], dn['Dormeur'],
                                                             f'CN=GG_Informatique,OU=Groupes,{BASE}']),
                   group('GG_Informatique', f'{DOM}-1201', [f'CN=GG_Stagiaires,OU=Groupes,{BASE}']),
                   group('GG_Stagiaires', f'{DOM}-1202', [dn['Adjoint']]),
                   group('Administrateurs', 'S-1-5-32-544', [f'CN=Admins du domaine,OU=Groupes,{BASE}']),
                   group('Opérateurs de sauvegarde', 'S-1-5-32-551', [dn['Operateur']]),
                   group('Protected Users', f'{DOM}-525', [dn['Chef']]),
                   group('GG_Eleves', f'{DOM}-1203', [dn['Eleve']])])
    data = {'users': users, 'groups': groups, 'recycle_bin': False,
            'computers': [{'dn': '', 'name': 'SRV-DC02', 'uac': 0x82000, 'primary_group': 516},
                          {'dn': '', 'name': 'SRV-DC03', 'uac': 0x82000, 'primary_group': 0},
                          {'dn': '', 'name': 'SRV-APPLI', 'uac': 0x81000, 'primary_group': 515}]}
    data.update(changes)
    return data


def by_key(result):
    return {f['key']: f for f in result['findings']}


class TestAnnuaire:
    def test_chemins(self):
        accounts = rs.privileged_accounts(directory())
        paths = {a['user']['name']: [rs._path_text(p) for p in a['paths']] for a in accounts.values()}
        assert paths['Chef'] == ['Admins du domaine', 'Admins du domaine → Administrateurs']
        assert 'GG_Informatique → GG_Stagiaires → Admins du domaine' in paths['Adjoint']      # imbrication sur 2 niveaux
        assert paths['Operateur'] == ['Opérateurs de sauvegarde']
        assert paths['Principal'] == ['Admins du domaine']                                    # par le groupe principal
        assert 'Eleve' not in paths and 'ExAdmin' not in paths

    def test_boucle_de_groupes(self):
        data = directory()
        a, b = f'cn=gg_informatique,ou=groupes,{BASE.lower()}', f'cn=gg_stagiaires,ou=groupes,{BASE.lower()}'
        data['groups'][b]['members'].append(a)                 # A contient B qui contient A
        assert 'Adjoint' in {x['user']['name'] for x in rs.privileged_accounts(data).values()}

    def test_constats(self):
        r = rs.analyse_directory(directory(), NOW)
        f = by_key(r)
        names = {k: sorted(i['name'] for i in v['items']) for k, v in f.items()}
        assert names['nested_admins'] == ['Adjoint']
        assert names['operators'] == ['Operateur'] and f['operators']['severity'] == 'high'
        assert names['admin_spn'] == ['Service'] and f['admin_spn']['severity'] == 'critical'
        assert names['no_preauth'] == ['Roast'] and f['no_preauth']['severity'] == 'high'
        assert names['unconstrained_delegation'] == ['SRV-APPLI']            # le contrôleur de domaine est normal
        assert names['admin_old_password'] == ['Dormeur'] and 'sans expiration' in f['admin_old_password']['items'][0]['detail']
        assert names['admin_inactive'] == ['Dormeur']
        assert names['admin_disabled'] == ['Ancien']
        assert 'Chef' not in names['admin_delegable'] and 'Adjoint' in names['admin_delegable']   # Protected Users
        assert f['krbtgt']['count'] == 1 and '400 jours' in f['krbtgt']['title']
        assert names['passwd_notreqd'] == ['Vide'] and names['admin_count'] == ['ExAdmin']
        assert 'recycle_bin' in f and 'too_many_admins' not in f
        assert r['counts'] == {'admins': 5, 'operators': 1, 'users': 12, 'groups': 7}
        assert [x['severity'] for x in r['findings']] == sorted((x['severity'] for x in r['findings']),
                                                                key=rs.SEVERITY_ORDER.get)

    def test_tableau_des_administrateurs(self):
        admins = {a['name']: a for a in rs.analyse_directory(directory(), NOW)['admins']}
        assert 'krbtgt' not in admins and not admins['Ancien']['enabled']
        assert admins['Adjoint']['nested'] and not admins['Chef']['nested']
        assert not admins['Operateur']['critical'] and admins['Dormeur']['pwd_age_days'] == 900

    def test_domaine_sain(self):
        users = dict([user('Chef', 1101, uac=512 | rs.UF_NOT_DELEGATED), user('Eleve', 1107),
                      user('krbtgt', 502, uac=514, pwd_days=30)])
        groups = dict([group('Admins du domaine', f'{DOM}-512', [f'CN=Chef,OU=Comptes,{BASE}'])])
        r = rs.analyse_directory({'users': users, 'groups': groups, 'computers': [], 'recycle_bin': True}, NOW)
        assert r['findings'] == [] and rs.score(r['findings']) == 100

    def test_preauth_sur_un_administrateur_est_critique(self):
        data = directory()
        data['users'][f'cn=chef,ou=comptes,{BASE.lower()}']['uac'] |= rs.UF_DONT_REQ_PREAUTH
        assert by_key(rs.analyse_directory(data, NOW))['no_preauth']['severity'] == 'critical'

    def test_trop_d_administrateurs(self):
        data = directory()
        extra = dict(user(f'Admin{i}', 1300 + i) for i in range(4))
        data['users'].update(extra)
        data['groups'][f'cn=admins du domaine,ou=groupes,{BASE.lower()}']['members'] += list(extra)
        assert by_key(rs.analyse_directory(data, NOW))['too_many_admins']['count'] == 9


def ace(sid, level, inherited=False, deny=False):
    return {'sid': sid, 'name': sid, 'level': level, 'deny': deny, 'inherited': inherited, 'type': '', 'applies': ''}


class TestPartages:
    TREE = {'path': r'\\SRV\Commun', 'truncated': False, 'folders': [
        {'path': r'\\SRV\Commun', 'level': 0, 'aces': [ace('S-1-1-0', 'Lecture et exécution'),
                                                       ace(f'{DOM}-513', 'Modification', inherited=True)]},
        {'path': r'\\SRV\Commun\Scans', 'level': 1, 'aces': [ace('S-1-1-0', 'Contrôle total'),
                                                             ace(f'{DOM}-513', 'Modification', inherited=True)]},
        {'path': r'\\SRV\Commun\Direction', 'level': 1, 'aces': [ace(f'{DOM}-1201', 'Modification'),
                                                                 ace('S-1-5-11', 'Modification', deny=True)]},
        {'path': r'\\SRV\Commun\Profs', 'level': 1, 'aces': [ace('S-1-5-11', 'Écriture')]}]}

    def test_dossiers_ouverts(self):
        r = rs.analyse_shares([self.TREE], ['\\\\SRV\\Autre : Accès refusé'])
        f = by_key(r)
        assert [i['name'] for i in f['share_everyone_write']['items']] == [r'\\SRV\Commun\Scans']
        # Droit hérité : signalé une seule fois, sur le dossier qui le porte (ici la racine).
        assert sorted(i['name'] for i in f['share_all_users_write']['items']) == [r'\\SRV\Commun', r'\\SRV\Commun\Profs']
        assert [i['name'] for i in f['share_everyone_read']['items']] == [r'\\SRV\Commun']
        assert r['scanned'] == 4 and r['errors'] and r['shares'] == [r'\\SRV\Commun']
        assert 'Tout le monde : Contrôle total' in f['share_everyone_write']['items'][0]['detail']

    def test_partage_ferme(self):
        tree = {'path': r'\\SRV\RH', 'folders': [{'path': r'\\SRV\RH', 'level': 0,
                                                  'aces': [ace(f'{DOM}-1201', 'Modification')]}]}
        assert rs.analyse_shares([tree])['findings'] == []


class TestSauvegardes:
    RAW = {'ok': True, 'computer': 'SRV-DC02', 'other_software': [], 'notes': [],
           'wsb': {'installed': True, 'last_success': '2026-11-13T01:00:00Z', 'last_result': 0,
                   'next': '2026-11-14T01:00:00Z', 'versions': 14, 'target': 'E:'},
           'volumes': [{'letter': 'C:', 'label': 'Système', 'size': 10 ** 11, 'free': 4 * 10 ** 10, 'copies': 6,
                        'newest': '2026-11-13T06:00:00Z', 'oldest': '2026-11-01T06:00:00Z'},
                       {'letter': 'D:', 'label': 'Données', 'size': 10 ** 12, 'free': 10 ** 11, 'copies': 0}]}

    def test_serveur_bien_sauvegarde(self):
        r = rs.analyse_backups(self.RAW, NOW)
        assert [f['key'] for f in r['findings']] == ['vss_none'] and r['findings'][0]['items'][0]['name'] == 'D: Données'
        assert r['wsb']['last_success'] == '13/11/2026 01:00' and r['wsb']['versions'] == 14 and len(r['volumes']) == 2

    def test_sauvegarde_ancienne_absente_ou_en_echec(self):
        raw = json.loads(json.dumps(self.RAW))
        raw['wsb'].update(last_success='2026-11-01T01:00:00Z', last_result=-2147024891)
        f = by_key(rs.analyse_backups(raw, NOW))
        assert f['wsb_old']['severity'] == 'critical' and '12 jours' in f['wsb_old']['title'] and 'wsb_failed' in f
        raw['wsb'].update(last_success='2026-11-10T01:00:00Z', last_result=0)
        assert by_key(rs.analyse_backups(raw, NOW))['wsb_late']['severity'] == 'medium'
        raw['wsb'] = {'installed': False}
        assert by_key(rs.analyse_backups(raw, NOW))['wsb_missing']['severity'] == 'critical'
        raw['other_software'] = ['Veeam Backup Service']         # un autre logiciel : on ne crie pas au loup
        missing = by_key(rs.analyse_backups(raw, NOW))['wsb_missing']
        assert missing['severity'] == 'medium' and 'Veeam' in missing['why']
        raw['wsb'] = {'installed': True, 'last_success': ''}
        assert 'wsb_never' in by_key(rs.analyse_backups(raw, NOW))

    def test_cliches_anciens(self):
        raw = json.loads(json.dumps(self.RAW))
        raw['volumes'][0]['newest'] = '2026-11-05T06:00:00Z'
        assert by_key(rs.analyse_backups(raw, NOW))['vss_old']['items'][0]['name'] == 'C: Système'

    def test_note(self):
        f = [{'severity': s} for s in ('critical', 'critical', 'high', 'medium', 'info')]
        assert rs.score(f) == 100 - 25 - 25 - 12 - 5 and rs.score(f * 5) == 0

    def test_hors_windows(self, monkeypatch):
        monkeypatch.setattr(rs.os, 'name', 'posix')
        with pytest.raises(rs.ResilienceError, match='Windows'):
            rs.run_ps()

    def test_analyse_longue_ne_plante_jamais(self, monkeypatch):
        def boom(*a):
            raise RuntimeError('partage injoignable')
        monkeypatch.setattr(rs, 'scan_shares', boom)
        monkeypatch.setattr(rs, 'run_ps', lambda: self.RAW)
        r = rs.scan_server(('u', 'p'))
        assert r['shares'] is None and r['backups']['computer'] == 'SRV-DC02' and 'injoignable' in r['errors'][0]


# --- Routes ------------------------------------------------------------------

class _Conn:
    def unbind(self):
        pass


@pytest.fixture
def client(monkeypatch):
    import routes.resilience as rr
    from app import app
    from core.session_crypto import encrypt_password
    monkeypatch.setattr(rr, 'get_ad_connection', lambda *a, **k: (_Conn(), None))
    monkeypatch.setattr(rs, 'read_directory', lambda conn, base: directory())
    app.config['TESTING'] = True
    c = app.test_client()
    with c.session_transaction() as s:
        s.update(ad_server='dc', ad_username='LAPROVIDENCE\\admin', ad_password=encrypt_password('x'),
                 ad_base_dn=BASE, user_role='admin', user_groups=['Domain Admins'])
    tok = re.search(rb'name="csrf-token" content="([^"]+)"', c.get('/resilience/').data).group(1).decode()
    return c, tok


class TestRoutes:
    def test_page_et_annuaire(self, client):
        c, _ = client
        assert 'Qui peut prendre la main' in c.get('/resilience/').get_data(as_text=True)
        d = c.get('/resilience/api/directory').get_json()
        assert d['success'] and d['counts']['admins'] == 5 and any(f['key'] == 'admin_spn' for f in d['findings'])

    def test_annuaire_injoignable(self, client, monkeypatch):
        def boom(conn, base):
            raise RuntimeError('connexion coupée')
        monkeypatch.setattr(rs, 'read_directory', boom)
        r = client[0].get('/resilience/api/directory')
        assert r.status_code == 502 and 'connexion coupée' in r.get_json()['error']

    def test_analyse_en_arriere_plan(self, client, monkeypatch):
        import routes.resilience as rr
        c, tok = client
        seen = {}
        monkeypatch.setattr(rs, 'scan_server', lambda creds: seen.update(creds=creds) or {
            'shares': rs.analyse_shares([TestPartages.TREE]), 'backups': rs.analyse_backups(TestSauvegardes.RAW, NOW),
            'errors': []})
        assert c.post('/resilience/api/scan', json={}).status_code in (400, 403)          # sans jeton CSRF
        r = c.post('/resilience/api/scan', json={'refresh': True}, headers={'X-CSRFToken': tok})
        assert r.status_code == 202
        job = r.get_json()['job']
        for _ in range(200):
            d = c.get(f'/resilience/api/scan/{job}').get_json()
            if d.get('status') != 'running':
                break
        assert d['status'] == 'done' and d['backups']['computer'] == 'SRV-DC02' and d['shares']['scanned'] == 4
        assert seen['creds'][1] == 'x' and 'creds' not in d and 'password' not in json.dumps(d)
        assert c.get('/resilience/api/scan/inconnu').status_code == 404
        with c.session_transaction() as s:
            s['ad_username'] = 'LAPROVIDENCE\\autre'
        assert c.get(f'/resilience/api/scan/{job}').status_code == 404                     # résultat réservé à son auteur
        assert rr.fs is not None

    def test_permission_et_menu(self, client, monkeypatch):
        from core import granular_permissions as gperm
        from core.settings_manager import DEFAULT_SETTINGS
        assert 'tools:resilience' in gperm.ALL_PERMISSIONS and 'tools:resilience' in gperm.SENSITIVE_PERMISSIONS
        assert any(i['endpoint'] == 'resilience.index' for i in DEFAULT_SETTINGS['menu']['tool_items'])
        c, _ = client
        with c.session_transaction() as s:
            s.update(user_role='reader', user_groups=[])
        monkeypatch.setattr(gperm, 'has_permission', lambda groups, perm, **k: perm != 'tools:resilience')
        assert c.get('/resilience/api/directory').status_code in (302, 403)


def test_script_en_lecture_seule():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts', 'resilience.ps1')
    raw = open(path, 'rb').read()
    assert raw.startswith(b'\xef\xbb\xbf') and raw.count(b'\r\n') == raw.count(b'\n')
    text = raw.decode('utf-8-sig')
    assert 'Get-WBSummary' in text and 'Win32_ShadowCopy' in text
    # Aucune commande qui modifie le serveur.
    assert not re.search(r'\b(Remove|Set|New|Start|Stop|Restart|Clear|Disable|Enable|Invoke)-\w+',
                         text.replace('New-Object', ''))
    assert 'vssadmin' not in text and 'wbadmin' not in text
