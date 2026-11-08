# -*- coding: utf-8 -*-
"""
Répertoires partagés : droits NTFS, accès d'un compte, dossiers AGDLP,
dossiers personnels (core/folders.py, routes/folders).

PowerShell n'est pas disponible en CI : run_ps est remplacé par un faux qui
enregistre les requêtes. Les tests vérifient ce que l'application demande
au script (opération, chemin, SID, droits) et ce qu'elle en affiche.
"""
import base64
import json
import os
import re

import pytest

os.environ.setdefault('SECRET_KEY', 'test-folders')

from core import folders as fs  # noqa: E402

ROOT = r'\\SRV-FIC\Partages'
HOME = r'\\SRV-FIC\Users$'
DOMAIN_SID = 'S-1-5-21-111-222-333'


# --- Chemins -----------------------------------------------------------------

class TestPaths:
    @pytest.mark.parametrize('path', [r'\\srv\share', r'\\srv.corp.local\Données\Compta 2026',
                                      '//srv/share/sub/', r'\\SRV-DC02\Partages$\RH'])
    def test_unc_valides(self, path):
        assert fs.normalize_unc(path).startswith('\\\\')

    @pytest.mark.parametrize('path', [r'C:\Windows', r'srv\share', r'\\srv', r'\\srv\share\..\autre',
                                      r'\\srv\share\.', r'\\srv\share\a:b', r'\\srv\share\fin.',
                                      r'\\srv\share\a*', '', r'\\srv\share' + '\x00x'])
    def test_unc_refuses(self, path):
        with pytest.raises(fs.FolderError):
            fs.normalize_unc(path)

    def test_sous_racine(self):
        assert fs.is_under(r'\\srv\share\a\b', r'\\SRV\Share')
        assert fs.is_under(r'\\srv\share', r'\\srv\share')
        # Un partage dont le nom commence comme la racine n'est pas dessous
        assert not fs.is_under(r'\\srv\share2\a', r'\\srv\share')

    def test_check_allowed(self, monkeypatch):
        monkeypatch.setattr(fs, 'get_folder_settings', lambda: {'roots': [ROOT], 'home_root': HOME,
                                                                'home_drive': 'H:', 'scan_depth': 3})
        assert fs.check_allowed(ROOT + r'\Compta') == ROOT + r'\Compta'
        with pytest.raises(fs.FolderError):
            fs.check_allowed(r'\\SRV-FIC\C$\Windows')
        with pytest.raises(fs.FolderError):
            fs.check_allowed(HOME + r'\jdupont')          # racine perso : seulement sur demande
        assert fs.check_allowed(HOME + r'\jdupont', extra_roots=[HOME])

    @pytest.mark.parametrize('name', ['Compta', 'RH 2026', 'Projet [A]'])
    def test_nom_valide(self, name):
        assert fs.validate_folder_name(name) == name

    @pytest.mark.parametrize('name', ['', '..', 'a\\b', 'a/b', 'x:', 'fin.', 'fin. ', 'a' * 121])
    def test_nom_refuse(self, name):
        with pytest.raises(fs.FolderError):
            fs.validate_folder_name(name)


class TestRights:
    def test_libelles(self):
        assert fs.rights_label(fs.FULL_CONTROL) == 'Contrôle total'
        assert fs.rights_label(fs.MODIFY) == 'Modification'
        assert fs.rights_label(fs.READ_AND_EXECUTE) == 'Lecture et exécution'
        assert fs.rights_label(fs.READ) == 'Lecture'
        assert fs.rights_label(0x1) == 'Spéciale'

    def test_droits_generiques(self):
        """ACE héritables (CREATOR OWNER…) : droits génériques."""
        assert fs.rights_label(fs.GENERIC_ALL) == 'Contrôle total'
        assert fs.rights_label(fs.GENERIC_READ | fs.GENERIC_EXECUTE) == 'Lecture et exécution'
        assert fs.rights_label(0xE0010000) == 'Modification'

    def test_portee(self):
        assert fs.applies_label(3, 0) == 'Ce dossier, les sous-dossiers et les fichiers'
        assert fs.applies_label(0, 0) == 'Ce dossier seulement'
        assert fs.applies_label(3, 2) == 'Les sous-dossiers et les fichiers seulement'
        assert fs.applies_label(1, 0) == 'Ce dossier, les sous-dossiers'

    def test_sid_binaire(self):
        raw = bytes([1, 5, 0, 0, 0, 0, 0, 5]) + b''.join(
            v.to_bytes(4, 'little') for v in (21, 111, 222, 333, 1105))
        assert fs.sid_to_str(raw) == DOMAIN_SID + '-1105'
        assert fs.sid_to_str('S-1-5-32-544') == 'S-1-5-32-544'
        assert fs.sid_to_str(b'') == ''


# --- Exécution PowerShell ----------------------------------------------------

class TestRunPs:
    def test_parametres_sur_stdin_pas_sur_la_ligne_de_commande(self, monkeypatch):
        calls = {}

        class Proc:
            returncode = 0
            stdout = '\ufeff{"ok":true,"aces":[]}'
            stderr = ''

        def fake_run(args, **kw):
            calls['args'], calls['kw'] = args, kw
            return Proc()
        monkeypatch.setattr(fs.os, 'name', 'nt')
        monkeypatch.setattr(fs.subprocess, 'run', fake_run)
        secret = "P@ss'; Remove-Item C:\\ -Recurse; '"
        result = fs.run_ps({'op': 'acl', 'path': ROOT, 'password': secret})
        assert result['ok'] is True
        cmdline = ' '.join(calls['args'])
        assert secret not in cmdline and 'Remove-Item C:' not in cmdline
        assert json.loads(calls['kw']['input'])['password'] == secret
        # Le script exécuté est la constante, sans aucune valeur insérée
        encoded = calls['args'][calls['args'].index('-EncodedCommand') + 1]
        assert base64.b64decode(encoded).decode('utf-16-le') == fs.PS_SCRIPT

    def test_erreur_du_script(self, monkeypatch):
        class Proc:
            returncode = 0
            stdout = '{"ok":false,"error":"Access to the path is denied."}'
            stderr = ''
        monkeypatch.setattr(fs.os, 'name', 'nt')
        monkeypatch.setattr(fs.subprocess, 'run', lambda *a, **k: Proc())
        with pytest.raises(fs.FolderError, match='Accès refusé'):
            fs.run_ps({'op': 'acl'})

    def test_hors_windows(self, monkeypatch):
        monkeypatch.setattr(fs.os, 'name', 'posix')
        with pytest.raises(fs.FolderError, match='Windows'):
            fs.run_ps({'op': 'acl'})

    def test_script(self):
        s = fs.PS_SCRIPT
        assert 'Invoke-Expression' not in s and 'iex ' not in s.lower()
        # Session « nouveaux identifiants » propre au processus, pas de
        # connexion partagée par tout le service (New-PSDrive -Credential)
        assert 'LogonUser($user, $domain, $req.password, 9, 3' in s
        assert 'New-PSDrive' not in s and 'net use' not in s.lower()
        assert '$impersonation.Undo()' in s.split('finally')[-1]
        assert 'New-Item -ItemType' not in s                 # -Path interpréterait [ ]
        assert '{0}' not in s and '%s' not in s


# --- Routes ------------------------------------------------------------------

class _A:
    def __init__(self, v):
        self.value = v[0] if isinstance(v, list) and len(v) == 1 else v
        self.values = v if isinstance(v, list) else ([] if v in (None, '') else [v])

    def __str__(self):
        return str(self.value)


class _E:
    def __init__(self, dn, **attrs):
        self.entry_dn = dn
        for k, v in attrs.items():
            setattr(self, k, _A(v))

    def __contains__(self, name):
        return hasattr(self, name)


class FakeConn:
    """Annuaire minimal : comptes, groupes, OU ; enregistre add/modify."""

    def __init__(self):
        self.objects = {
            'CN=Jean Dupont,OU=Users,DC=corp,DC=local': dict(
                sam='jdupont', cls=['top', 'person', 'user'], sid=DOMAIN_SID + '-1105', pgid=513),
            'CN=Compta,OU=Groupes,DC=corp,DC=local': dict(
                sam='GRP-Compta', cn='Compta', cls=['top', 'group'], sid=DOMAIN_SID + '-1200'),
        }
        self.member_of = {'CN=Jean Dupont,OU=Users,DC=corp,DC=local': ['CN=Compta,OU=Groupes,DC=corp,DC=local']}
        self.added, self.modified, self.deleted = [], [], []
        self.entries = []
        self.result = {'result': 0}
        self.next_rid = 3000

    def _entry(self, dn):
        o = self.objects[dn]
        attrs = dict(objectSid=o['sid'], sAMAccountName=o['sam'], cn=o.get('cn', o['sam']),
                     objectClass=o['cls'], primaryGroupID=o.get('pgid'), name='x')
        if o.get('home'):
            attrs['homeDirectory'] = o['home']
        return _E(dn, **attrs)

    def delete(self, dn):
        self.deleted.append(dn)
        self.objects.pop(dn, None)
        return True

    def search(self, base, flt, scope=None, attributes=None, **k):
        self.entries = []
        if scope == 'BASE' or (scope is not None and str(scope).upper() == 'BASE'):
            if base in self.objects:
                self.entries = [self._entry(base)]
            return
        if 'organizationalUnit' in flt:
            self.entries = [_E('OU=Groupes,DC=corp,DC=local', name='Groupes')]
            return
        names = re.findall(r'(?:sAMAccountName|cn)=([^)]+)', flt)
        for dn, o in self.objects.items():
            if o['sam'] in names or o.get('cn') in names:
                if 'objectClass=group' in flt and 'group' not in o['cls'] and 'objectCategory=person' not in flt:
                    continue
                self.entries.append(self._entry(dn))

    def add(self, dn, classes, attrs):
        self.added.append((dn, attrs))
        self.next_rid += 1
        self.objects[dn] = dict(sam=attrs['sAMAccountName'], cls=['top', 'group'],
                                sid=f'{DOMAIN_SID}-{self.next_rid}')
        self.result = {'result': 0}
        return True

    def modify(self, dn, changes):
        self.modified.append((dn, changes))
        self.result = {'result': 0}
        return True

    def unbind(self):
        pass


@pytest.fixture
def env(monkeypatch, tmp_path):
    import core.settings_manager as sm
    import routes.core as rc
    import routes.folders as rf
    from app import app
    monkeypatch.setattr(sm, 'SETTINGS_FILE', str(tmp_path / 'settings.json'))
    sm.set_setting('folders.roots', [ROOT])
    sm.set_setting('folders.home_root', HOME)
    sm.set_setting('folders.home_drive', 'H:')

    conn = FakeConn()
    calls = []

    def fake_run_ps(data, timeout=None):
        calls.append(data)
        if data['op'] == 'acl':
            return {'ok': True, 'owner': 'BUILTIN\\Administrateurs', 'protected': False,
                    'children': ['Compta', 'RH'],
                    'aces': [{'sid': 'S-1-5-32-544', 'name': 'BUILTIN\\Administrateurs',
                              'rights': fs.FULL_CONTROL, 'type': 'Allow', 'inherited': True,
                              'inheritance': 3, 'propagation': 0},
                             {'sid': DOMAIN_SID + '-1200', 'name': 'CORP\\GRP-Compta',
                              'rights': fs.MODIFY, 'type': 'Allow', 'inherited': False,
                              'inheritance': 3, 'propagation': 0},
                             {'sid': DOMAIN_SID + '-1105', 'name': 'CORP\\jdupont',
                              'rights': fs.WRITE, 'type': 'Deny', 'inherited': False,
                              'inheritance': 0, 'propagation': 0}]}
        if data['op'] == 'scan':
            return {'ok': True, 'scanned': 12, 'truncated': False, 'errors': [],
                    'found': [{'sid': DOMAIN_SID + '-1200', 'name': 'CORP\\GRP-Compta',
                               'rights': fs.MODIFY, 'type': 'Allow', 'inherited': False,
                               'inheritance': 3, 'propagation': 0, 'path': ROOT + r'\Compta'},
                              {'sid': 'S-1-5-11', 'name': 'AUTORITE NT\\Utilisateurs authentifiés',
                               'rights': fs.READ_AND_EXECUTE, 'type': 'Allow', 'inherited': True,
                               'inheritance': 3, 'propagation': 0, 'path': ROOT}]}
        return {'ok': True, 'existed': False}

    def fake_paged(c, base, flt, attributes=None, **k):
        if '1.2.840.113556.1.4.1941' in flt:
            dn = flt.split(':=', 1)[1].rstrip(')')
            return [c._entry(g) for g in c.member_of.get(dn, [])]
        if 'objectSid=' in flt:
            return [_E('CN=Utilisateurs du domaine,CN=Users,DC=corp,DC=local', cn='Utilisateurs du domaine')]
        return []

    monkeypatch.setattr(fs, 'run_ps', fake_run_ps)
    monkeypatch.setattr(rc, 'paged_search', fake_paged)
    monkeypatch.setattr(rf, 'get_ad_connection', lambda *a, **k: (conn, None))
    app.config['TESTING'] = True
    client = app.test_client()
    from core.session_crypto import encrypt_password
    with client.session_transaction() as s:
        s.update(ad_server='dc', ad_username='CORP\\admin', ad_password=encrypt_password('Secret-1'),
                 ad_base_dn='DC=corp,DC=local', user_role='admin', user_groups=['Domain Admins'])
    m = re.search(rb'name="csrf-token" content="([^"]+)"', client.get('/folders/').data)
    return client, conn, calls, m.group(1).decode()


class TestBrowse:
    def test_affiche_les_droits(self, env):
        client, _, calls, _ = env
        html = client.get('/folders/?path=' + ROOT).get_data(as_text=True)
        assert 'CORP\\GRP-Compta' in html and 'Modification' in html
        assert 'Refuser' in html and 'ace-deny' in html
        assert 'Compta' in html and 'RH' in html                       # sous-dossiers
        req = [c for c in calls if c['op'] == 'acl'][-1]
        assert req['path'] == ROOT
        assert req['user'] == 'CORP\\admin' and req['password'] == 'Secret-1'
        # Un droit hérité n'a pas de bouton « Retirer »
        assert html.count('name="sid"') == 2

    def test_chemin_hors_racine(self, env):
        client, _, calls, _ = env
        n = len(calls)
        html = client.get('/folders/?path=\\\\SRV-FIC\\C$').get_data(as_text=True)
        assert 'racine autorisée' in html and len(calls) == n

    def test_fonction_desactivee(self, env, monkeypatch):
        import core.features as cf
        client = env[0]
        monkeypatch.setitem(cf.FEATURES, 'folders', False) if hasattr(cf, 'FEATURES') else None
        monkeypatch.setattr(cf, 'is_feature_enabled', lambda name: name != 'folders')
        assert client.get('/folders/').status_code == 503


class TestGrantRevoke:
    def test_grant_par_sid(self, env):
        client, _, calls, tok = env
        r = client.post('/folders/grant', data={'csrf_token': tok, 'path': ROOT + r'\Compta',
                                                'principal': 'jdupont', 'level': 'modify', 'applies': 'all'})
        assert r.status_code == 302
        req = calls[-1]
        assert req['op'] == 'grant' and req['sid'] == DOMAIN_SID + '-1105'
        assert req['rights'] == fs.MODIFY and req['applies'] == 'all'

    def test_grant_groupe_par_cn(self, env):
        """L'autocomplétion propose le cn du groupe (Compta), distinct du sAMAccountName."""
        client, _, calls, tok = env
        client.post('/folders/grant', data={'csrf_token': tok, 'path': ROOT, 'principal': 'Compta',
                                            'level': 'read', 'applies': 'this'})
        assert calls[-1]['sid'] == DOMAIN_SID + '-1200' and calls[-1]['rights'] == fs.READ_AND_EXECUTE

    def test_grant_hors_racine_refuse(self, env):
        client, _, calls, tok = env
        n = len(calls)
        client.post('/folders/grant', data={'csrf_token': tok, 'path': r'\\SRV-FIC\C$\Windows',
                                            'principal': 'jdupont', 'level': 'full'})
        assert len(calls) == n

    def test_niveau_invalide(self, env):
        client, _, calls, tok = env
        n = len(calls)
        client.post('/folders/grant', data={'csrf_token': tok, 'path': ROOT, 'principal': 'jdupont',
                                            'level': 'owner'})
        assert len(calls) == n

    def test_revoke(self, env):
        client, _, calls, tok = env
        client.post('/folders/revoke', data={'csrf_token': tok, 'path': ROOT, 'sid': DOMAIN_SID + '-1105'})
        assert calls[-1]['op'] == 'revoke' and calls[-1]['sid'] == DOMAIN_SID + '-1105'

    def test_revoke_sid_forge(self, env):
        client, _, calls, tok = env
        n = len(calls)
        client.post('/folders/revoke', data={'csrf_token': tok, 'path': ROOT, 'sid': "x'; rm"})
        assert len(calls) == n

    def test_sans_csrf(self, env):
        client, _, calls, _ = env
        n = len(calls)
        r = client.post('/folders/grant', data={'path': ROOT, 'principal': 'jdupont', 'level': 'read'})
        assert r.status_code in (302, 400, 403) and len(calls) == n


class TestCreateShared:
    def test_agdlp(self, env):
        client, conn, calls, tok = env
        r = client.post('/folders/create', data={
            'csrf_token': tok, 'parent': ROOT, 'name': 'Comptabilité', 'ou': 'OU=Groupes,DC=corp,DC=local',
            'with_global': 'on', 'protect': 'on', 'members_modify': 'jdupont'})
        assert r.status_code == 302
        added = {attrs['sAMAccountName']: attrs['groupType'] for _, attrs in conn.added}
        assert added == {'DL_Comptabilité_L': fs.GROUP_DOMAIN_LOCAL_SECURITY,
                         'DL_Comptabilité_M': fs.GROUP_DOMAIN_LOCAL_SECURITY,
                         'GG_Comptabilité_L': fs.GROUP_GLOBAL_SECURITY,
                         'GG_Comptabilité_M': fs.GROUP_GLOBAL_SECURITY}
        members = [(dn.split(',')[0], ch['member'][0][1][0].split(',')[0]) for dn, ch in conn.modified]
        assert ('CN=DL_Comptabilité_L', 'CN=GG_Comptabilité_L') in members
        assert ('CN=DL_Comptabilité_M', 'CN=GG_Comptabilité_M') in members
        assert ('CN=GG_Comptabilité_M', 'CN=Jean Dupont') in members
        req = calls[-1]
        assert req['op'] == 'mkdir' and req['path'] == ROOT + r'\Comptabilité' and req['protect'] is True
        sids = {o['sam']: o['sid'] for o in conn.objects.values()}
        assert {(g['sid'], g['rights']) for g in req['grants']} == {
            (sids['DL_Comptabilité_L'], fs.READ_AND_EXECUTE), (sids['DL_Comptabilité_M'], fs.MODIFY)}

    def test_groupe_existant_reutilise(self, env):
        client, conn, calls, tok = env
        conn.objects['CN=DL_RH_L,OU=Groupes,DC=corp,DC=local'] = dict(
            sam='DL_RH_L', cls=['top', 'group'], sid=DOMAIN_SID + '-1500')
        client.post('/folders/create', data={'csrf_token': tok, 'parent': ROOT, 'name': 'RH',
                                             'ou': 'OU=Groupes,DC=corp,DC=local', 'reuse_groups': 'on'})
        assert [a['sAMAccountName'] for _, a in conn.added] == ['DL_RH_M']
        assert DOMAIN_SID + '-1500' in [g['sid'] for g in calls[-1]['grants']]

    def test_groupe_existant_refuse_sans_accord(self, env):
        """Deux dossiers « RH » dans des parents différents ne partagent pas leurs groupes en silence."""
        client, conn, calls, tok = env
        conn.objects['CN=DL_RH_L,OU=Groupes,DC=corp,DC=local'] = dict(
            sam='DL_RH_L', cls=['top', 'group'], sid=DOMAIN_SID + '-1500')
        r = client.post('/folders/create', data={'csrf_token': tok, 'parent': ROOT, 'name': 'RH',
                                                 'ou': 'OU=Groupes,DC=corp,DC=local',
                                                 'members_modify': 'jdupont'})
        html = client.get(r.headers['Location']).get_data(as_text=True)
        assert 'DL_RH_L existe déjà' in html
        assert not conn.added and not conn.modified
        assert not [c for c in calls if c['op'] == 'mkdir']

    def test_nom_de_groupes_personnalise(self, env):
        client, conn, calls, tok = env
        client.post('/folders/create', data={'csrf_token': tok, 'parent': ROOT, 'name': 'Compta',
                                             'group_base': 'Compta 2026', 'ou': 'OU=Groupes,DC=corp,DC=local'})
        assert sorted(a['sAMAccountName'] for _, a in conn.added) == ['DL_Compta_2026_L', 'DL_Compta_2026_M']

    def test_echec_du_dossier_annule_les_groupes(self, env, monkeypatch):
        client, conn, calls, tok = env
        real = fs.run_ps

        def failing(data, timeout=None):
            if data['op'] == 'mkdir':
                raise fs.FolderError('Le dossier existe déjà')
            return real(data, timeout)
        monkeypatch.setattr(fs, 'run_ps', failing)
        client.post('/folders/create', data={'csrf_token': tok, 'parent': ROOT, 'name': 'Projet',
                                             'ou': 'OU=Groupes,DC=corp,DC=local', 'with_global': 'on',
                                             'members_read': 'jdupont'})
        assert len(conn.added) == 4 and sorted(conn.deleted) == sorted(dn for dn, _ in conn.added)
        assert not conn.modified          # aucune appartenance modifiée

    def test_membre_inconnu(self, env):
        client, conn, calls, tok = env
        r = client.post('/folders/create', data={
            'csrf_token': tok, 'parent': ROOT, 'name': 'X', 'ou': 'OU=Groupes,DC=corp,DC=local',
            'members_read': 'inconnu'})
        html = client.get(r.headers['Location']).get_data(as_text=True)
        assert 'introuvable : inconnu' in html
        assert not conn.added and not [c for c in calls if c['op'] == 'mkdir']


class TestAccess:
    def test_resolution_et_scan(self, env):
        client, _, calls, tok = env
        r = client.post('/folders/api/access', json={'principal': 'jdupont'},
                        headers={'X-CSRFToken': tok})
        assert r.status_code == 202
        job = r.get_json()['job']
        data = _wait(client, job)
        assert data['success'] and data['status'] == 'done', data
        req = calls[-1]
        assert req['op'] == 'scan' and req['roots'] == [ROOT] and req['depth'] == 3
        assert set(req['sids']) >= {DOMAIN_SID + '-1105', DOMAIN_SID + '-1200', DOMAIN_SID + '-513',
                                    'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545'}
        rows = {r['path']: r for r in data['found']}
        assert rows[ROOT + r'\Compta']['via'] == 'Compta' and not rows[ROOT + r'\Compta']['direct']
        assert rows[ROOT]['via'] == 'Utilisateurs authentifiés'

    def test_resultat_reserve_au_demandeur(self, env):
        client, _, _, tok = env
        job = client.post('/folders/api/access', json={'principal': 'jdupont'},
                          headers={'X-CSRFToken': tok}).get_json()['job']
        _wait(client, job)
        with client.session_transaction() as s:
            s['ad_username'] = 'CORP\\autre'
        assert client.get('/folders/api/access/' + job).status_code == 404

    def test_page(self, env):
        client = env[0]
        html = client.get('/folders/access?dn=CN=Compta,OU=Groupes,DC=corp,DC=local').get_data(as_text=True)
        assert '"CN=Compta,OU=Groupes,DC=corp,DC=local"' in html     # dn injecté via tojson

    def test_dn_hors_domaine(self, env):
        client, _, _, tok = env
        r = client.post('/folders/api/access', json={'dn': 'CN=x,DC=autre,DC=com'},
                        headers={'X-CSRFToken': tok})
        assert r.status_code == 400


def _wait(client, job):
    import time
    for _ in range(200):
        data = client.get('/folders/api/access/' + job).get_json()
        if data.get('status') != 'running':
            return data
        time.sleep(0.02)
    raise AssertionError('analyse jamais terminée')


class TestHome:
    def test_dossier_existant_hors_racine_intouche(self, env):
        """Rediriger H: vers un dossier vide laisserait les données à l'ancien emplacement."""
        import routes.folders as rf
        client, conn, calls, _ = env
        dn = 'CN=Jean Dupont,OU=Users,DC=corp,DC=local'
        conn.objects[dn]['home'] = r'\\ANCIEN\Homes\jdupont'
        n = len(calls)
        with client.application.test_request_context('/'):
            with pytest.raises(fs.FolderError, match='pas sous la racine'):
                rf.provision_home_folder(conn, dn)
        assert len(calls) == n and not conn.modified

    def test_reparation_du_dossier_existant(self, env):
        client, conn, calls, tok = env
        dn = 'CN=Jean Dupont,OU=Users,DC=corp,DC=local'
        conn.objects[dn]['home'] = HOME + r'\jean.dupont'
        client.post('/folders/home/' + dn, data={'csrf_token': tok})
        req = calls[-1]
        assert req['path'] == HOME + r'\jean.dupont'          # pas \jdupont : le dossier existant
        assert req['reset'] is True and req['protect'] is True

    def test_dossier_personnel(self, env):
        client, conn, calls, tok = env
        dn = 'CN=Jean Dupont,OU=Users,DC=corp,DC=local'
        client.post('/folders/home/' + dn, data={'csrf_token': tok})
        req = calls[-1]
        assert req['op'] == 'mkdir' and req['path'] == HOME + r'\jdupont'
        assert req['protect'] is True and req['allow_existing'] is True and req['reset'] is True
        assert req['grants'] == [{'sid': DOMAIN_SID + '-1105', 'rights': fs.MODIFY}]
        dn_mod, changes = conn.modified[-1]
        assert dn_mod == dn
        assert changes['homeDirectory'][0][1] == [HOME + r'\jdupont']
        assert changes['homeDrive'][0][1] == ['H:']


class TestSettings:
    def test_enregistrement(self, env):
        client, _, _, tok = env
        r = client.post('/folders/settings', data={
            'csrf_token': tok, 'roots': '\\\\srv1\\a\r\n\\\\SRV1\\A\n\n//srv2/b/', 'home_root': '',
            'home_drive': 'p', 'scan_depth': '2'})
        assert r.status_code == 302
        settings = fs.get_folder_settings()
        assert settings['roots'] == [r'\\srv1\a', r'\\srv2\b']
        assert settings['home_drive'] == 'P:' and settings['scan_depth'] == 2 and settings['home_root'] == ''

    def test_racine_invalide(self, env):
        client, _, _, tok = env
        html = client.post('/folders/settings', data={'csrf_token': tok, 'roots': 'C:\\Partages',
                                                     'home_drive': 'H:', 'scan_depth': '3'}).get_data(as_text=True)
        assert 'Chemin invalide' in html
        assert fs.get_folder_settings()['roots'] == [ROOT]


def test_menu_complete_les_anciens_reglages(monkeypatch, tmp_path):
    """Un settings.json d'une version antérieure reçoit les nouvelles entrées."""
    import core.settings_manager as sm
    path = tmp_path / 'settings.json'
    old = {'menu': {'tool_items': [i for i in sm.DEFAULT_SETTINGS['menu']['tool_items']
                                   if i['id'] != 'folders']}}
    old['menu']['tool_items'][0] = dict(old['menu']['tool_items'][0], enabled=False)
    path.write_text(json.dumps(old), encoding='utf-8')
    monkeypatch.setattr(sm, 'SETTINGS_FILE', str(path))
    ids = [i['id'] for i in sm.get_tool_items()]
    assert 'folders' in ids
    assert old['menu']['tool_items'][0]['id'] not in ids              # choix de l'admin respecté


def test_creation_utilisateur_avec_dossier_personnel(env, monkeypatch):
    import routes.folders as rf
    import routes.users.create as uc
    client, conn, calls, tok = env
    done = []
    monkeypatch.setattr(rf, 'provision_home_folder', lambda c, dn: done.append(dn) or HOME + r'\x')
    html = uc.__name__ and open('templates/create_user.html', encoding='utf-8').read()
    assert 'name="create_home"' in html and '{% if home_folder_root %}' in html
    with client.application.test_request_context('/'):
        from flask import session
        session.update(user_role='admin', user_groups=['Domain Admins'], ad_username='CORP\\admin')
        assert uc._home_folder_root() == HOME
        uc._create_home_folder(conn, 'CN=Jean Dupont,OU=Users,DC=corp,DC=local')
    assert done == ['CN=Jean Dupont,OU=Users,DC=corp,DC=local']


def test_script_tient_sur_la_ligne_de_commande():
    """-EncodedCommand : la ligne de commande Windows est limitée à 32 767 caractères."""
    assert len(fs._encoded_script()) < 30000


@pytest.mark.parametrize('template,ctx', [
    ('edit_user.html', {'user': {'dn': 'CN=Jean Dupont,OU=Users,DC=corp,DC=local', 'cn': 'Jean Dupont',
                                 'sAMAccountName': 'jdupont', 'homeDirectory': HOME + r'\jdupont',
                                 'homeDrive': 'H:', 'current_groups': [], 'current_ou': ''},
                        'ous': []}),
    ('group_details.html', {'group': {'dn': 'CN=Compta,OU=Groupes,DC=corp,DC=local', 'cn': 'Compta',
                                      'description': '', 'members': []}}),
])
def test_liens_depuis_les_fiches(env, template, ctx):
    from flask import render_template
    client = env[0]
    with client.application.test_request_context('/'):
        from flask import session
        session.update(user_role='admin', user_groups=['Domain Admins'], ad_username='CORP\\admin',
                       ad_server='dc', ad_password='x')
        html = render_template(template, connected=True, **ctx)
    assert '/folders/access?dn=CN%3D' in html
    if template == 'edit_user.html':
        assert '/folders/home/CN=Jean' in html and HOME + r'\jdupont' in html


def test_identifiants_base_limitee_a_une_ou(env):
    from flask import session
    from core.session_crypto import encrypt_password
    client = env[0]
    with client.application.test_request_context('/'):
        session.update(ad_username='admin', ad_password=encrypt_password('x'),
                       ad_base_dn='OU=Paris,DC=corp,DC=local')
        assert fs._credentials() == ('admin@corp.local', 'x')
        session['ad_username'] = 'CORP\\admin'
        assert fs._credentials()[0] == 'CORP\\admin'


def test_editeur_de_menu_voit_les_nouvelles_entrees(monkeypatch, tmp_path):
    """Les entrées ajoutées sont fusionnées au chargement : /admin peut les modifier."""
    import core.settings_manager as sm
    path = tmp_path / 'settings.json'
    path.write_text(json.dumps({'menu': {'tool_items': [{'id': 'laps', 'label': 'LAPS',
                                                         'endpoint': 'tools.laps_passwords'}]}}),
                    encoding='utf-8')
    monkeypatch.setattr(sm, 'SETTINGS_FILE', str(path))
    ids = [i['id'] for i in sm.load_settings()['menu']['tool_items']]
    assert ids[0] == 'laps' and 'folders' in ids and ids.count('laps') == 1


def test_trop_d_analyses_simultanees(monkeypatch):
    import threading
    gate = threading.Event()
    monkeypatch.setattr(fs, 'scan_access', lambda p: gate.wait(5) and {'found': []})
    monkeypatch.setattr(fs, '_JOBS', {})
    jobs = [fs.start_scan_job('a', {'credentials': ('u', 'p')}) for _ in range(fs.MAX_RUNNING_JOBS)]
    with pytest.raises(fs.FolderError, match='Trop'):
        fs.start_scan_job('a', {'credentials': ('u', 'p')})
    gate.set()
    assert all(fs.get_scan_job(j, 'a') for j in jobs) and fs.get_scan_job(jobs[0], 'b') is None
