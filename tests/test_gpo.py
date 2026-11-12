# -*- coding: utf-8 -*-
"""
Stratégies de groupe (core/gpo.py, routes/gpo) : lecture des liens et du
filtrage de sécurité, calcul des stratégies reçues (ordre, héritage bloqué,
liens « appliqués », filtrage), portée, écritures et sauvegardes.
"""
import os
import re
import uuid

import pytest

os.environ.setdefault('SECRET_KEY', 'test-gpo')

from core import gpo as gp  # noqa: E402

BASE = 'DC=corp,DC=local'
DOM = 'S-1-5-21-111-222-333'
G_DEFAULT = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
G_COMPTA = '{AAAAAAAA-0000-0000-0000-000000000001}'
G_VERROU = '{AAAAAAAA-0000-0000-0000-000000000002}'
G_VIDE = '{AAAAAAAA-0000-0000-0000-000000000003}'
G_FANTOME = '{AAAAAAAA-0000-0000-0000-00000000DEAD}'


def sid_bytes(sid):
    parts = sid.split('-')[1:]
    subs = [int(p) for p in parts[2:]]
    return (bytes([int(parts[0]), len(subs)]) + int(parts[1]).to_bytes(6, 'big') +
            b''.join(s.to_bytes(4, 'little') for s in subs))


def ace(sid, ace_type=5, mask=0x100, object_type=gp.APPLY_GROUP_POLICY, flags=0):
    body = mask.to_bytes(4, 'little')
    if ace_type in (5, 6):
        if object_type:
            body += (1).to_bytes(4, 'little') + uuid.UUID(object_type).bytes_le
        else:
            body += (0).to_bytes(4, 'little')
    body += sid_bytes(sid)
    return bytes([ace_type, flags]) + (len(body) + 4).to_bytes(2, 'little') + body


def sd(*aces):
    acl_body = b''.join(aces)
    acl = bytes([4, 0]) + (len(acl_body) + 8).to_bytes(2, 'little') + len(aces).to_bytes(2, 'little') + b'\x00\x00'
    return bytes([1, 0, 4, 0x80]) + bytes(12) + (20).to_bytes(4, 'little') + acl + acl_body


class TestSecurityDescriptor:
    def test_droit_appliquer(self):
        allow, deny = gp.parse_apply_rights(sd(
            ace('S-1-5-11'),                                                   # Appliquer : oui
            ace(DOM + '-512', ace_type=0, mask=0xF00FF, object_type=None),     # admins : pas le droit étendu
            ace(DOM + '-1200', ace_type=0, mask=0xF01FF, object_type=None),    # tous les droits étendus
            ace(DOM + '-1300', ace_type=6),                                    # refus
            ace(DOM + '-1400', object_type='00000000-0000-0000-0000-00000000abcd'),   # autre droit
            ace(DOM + '-1500', flags=gp.INHERIT_ONLY_ACE)))                    # ne vise pas la GPO elle-même
        assert allow == {'S-1-5-11', DOM + '-1200'} and deny == {DOM + '-1300'}

    def test_illisible(self):
        assert gp.parse_apply_rights(None) == (None, None)
        assert gp.parse_apply_rights(b'\x01\x00') == (None, None)


def test_gplink():
    raw = f'[LDAP://cn={G_DEFAULT},cn=policies,cn=system,{BASE};0][LDAP://CN={G_COMPTA.lower()},CN=Policies,CN=System,{BASE};2]'
    links = gp.parse_gplink(raw)
    assert [(g, o) for _, g, o in links] == [(G_DEFAULT, 0), (G_COMPTA, 2)]
    assert gp.parse_gplink(' ') == [] and gp.format_gplink(links) == raw
    with pytest.raises(gp.GpoError):
        gp.norm_guid('../x')


# --- Annuaire factice --------------------------------------------------------

class _A:
    def __init__(self, v):
        self.value = v
        self.values = v if isinstance(v, list) else ([] if v is None else [v])

    def __str__(self):
        return str(self.value)


class _E:
    def __init__(self, dn, **attrs):
        self.entry_dn = dn
        for k, v in attrs.items():
            setattr(self, k, _A(v))

    def __contains__(self, name):
        return hasattr(self, name)


def link(guid, options=0):
    return f'[LDAP://cn={guid},cn=policies,cn=system,{BASE};{options}]'


class FakeConn:
    def __init__(self):
        self.result = {'result': 0}
        self.entries = []
        self.modified = []
        self.gpos = {
            G_DEFAULT: dict(name='Default Domain Policy', flags=0, version=(3 << 16) | 7, sd=sd(ace('S-1-5-11'))),
            G_COMPTA: dict(name='Compta - Lecteurs réseau', flags=0, version=2 << 16,
                           sd=sd(ace(DOM + '-1200'), ace(DOM + '-1105', ace_type=6))),
            G_VERROU: dict(name='Verrouillage écran', flags=2, version=1 << 16, sd=sd(ace('S-1-5-11'))),
            G_VIDE: dict(name='Ancienne stratégie', flags=3, version=0, sd=sd()),
        }
        self.containers = {
            BASE: dict(name='corp', gPLink=link(G_DEFAULT) + link(G_VERROU, 2), gPOptions=0),
            'OU=Siege,' + BASE: dict(name='Siege', gPLink=link(G_FANTOME) + link(G_COMPTA), gPOptions=0),
            'OU=Labo,OU=Siege,' + BASE: dict(name='Labo', gPLink=' ', gPOptions=1),
        }
        self.objects = {
            'CN=Alice,OU=Siege,' + BASE: dict(cls=['top', 'person', 'user'], sam='alice', sid=DOM + '-1101'),
            'CN=Jean,OU=Siege,' + BASE: dict(cls=['top', 'person', 'user'], sam='jdupont', sid=DOM + '-1105'),
            'CN=Zoe,OU=Labo,OU=Siege,' + BASE: dict(cls=['top', 'person', 'user'], sam='zoe', sid=DOM + '-1102'),
            'CN=PC1,OU=Siege,' + BASE: dict(cls=['top', 'user', 'computer'], sam='PC1$', sid=DOM + '-2001'),
            'CN=GRP-Compta,OU=Siege,' + BASE: dict(cls=['top', 'group'], sam='GRP-Compta', sid=DOM + '-1200'),
        }
        self.members = {DOM + '-1200': ['CN=Alice,OU=Siege,' + BASE, 'CN=Jean,OU=Siege,' + BASE,
                                         'CN=Zoe,OU=Labo,OU=Siege,' + BASE]}

    def _obj(self, dn):
        o = self.objects[dn]
        return _E(dn, objectClass=o['cls'], sAMAccountName=o['sam'], cn=o['sam'], name=o['sam'],
                  objectSid=o['sid'], primaryGroupID=513)

    def _container(self, dn):
        c = self.containers[dn]
        return _E(dn, name=c['name'], gPLink=c['gPLink'], gPOptions=c['gPOptions'],
                  objectClass=['top', 'organizationalUnit'])

    def search(self, base, flt, scope=None, attributes=None, controls=None, **k):
        self.entries = []
        if base.startswith('CN=Policies'):
            self.entries = [_E(f'CN={g},CN=Policies,CN=System,{BASE}', cn=g, displayName=v['name'],
                               flags=v['flags'], versionNumber=v['version'], nTSecurityDescriptor=v['sd'],
                               whenChanged=None, whenCreated=None, gPCWQLFilter=None)
                            for g, v in self.gpos.items()]
        elif str(scope).upper() == 'BASE':
            if base in self.containers:
                self.entries = [self._container(base)]
            elif base in self.objects and 'organizationalUnit' not in flt:
                self.entries = [self._obj(base)]
        elif 'objectSid=' in flt:
            sids = re.findall(r'objectSid=([^)]+)', flt)
            self.entries = [self._obj(dn) for dn, o in self.objects.items() if o['sid'] in sids]
        elif 'sAMAccountName=' in flt:
            names = re.findall(r'sAMAccountName=([^)]+)', flt)
            self.entries = [self._obj(dn) for dn, o in self.objects.items() if o['sam'] in names]

    def modify(self, dn, changes):
        self.modified.append((dn, changes))
        for attr, ops in changes.items():
            if dn in self.containers and attr in ('gPLink', 'gPOptions'):
                self.containers[dn][attr] = ops[0][1][0] if ops[0][1] else ' '
            for g, v in self.gpos.items():
                if dn.startswith(f'CN={g}') and attr == 'flags':
                    v['flags'] = ops[0][1][0]
        self.result = {'result': 0}
        return True

    def unbind(self):
        pass


@pytest.fixture
def conn(monkeypatch):
    import routes.core as rc
    c = FakeConn()

    def paged(cn, base, flt, attributes=None, **k):
        low = base.lower()
        if 'gPLink=*' in flt:
            return [cn._container(dn) for dn in cn.containers]
        if 'objectClass=organizationalUnit' in flt:
            return [cn._container(dn) for dn in cn.containers if dn != BASE]
        if 'objectClass=group' in flt and 'member:' in flt:      # groupes d'un compte
            dn = flt.split(':=', 1)[1].rstrip(')')
            return [cn._obj(g) for g, o in cn.objects.items()
                    if 'group' in o['cls'] and dn in cn.members.get(o['sid'], [])]
        if 'objectSid=' in flt and 'objectClass=group' in flt:   # groupe principal
            return []
        kind_computer = 'objectCategory=computer' in flt
        out = []
        for dn, o in cn.objects.items():
            if 'group' in o['cls'] or ('computer' in o['cls']) != kind_computer:
                continue
            if not dn.lower().endswith(',' + low):
                continue
            if 'memberOf:' in flt:
                groups = re.findall(r'memberOf:[^=]+=([^)]+)\)', flt)
                sids = [x['sid'] for g, x in cn.objects.items() if g in groups]
                if not any(dn in cn.members.get(s, []) for s in sids):
                    continue
            if f'(!(objectSid={o["sid"]}))' in flt:
                continue
            out.append(cn._obj(dn))
        return out
    monkeypatch.setattr(rc, 'paged_search', paged)
    return c


class TestLoad:
    def test_gpos_et_constats(self, conn):
        data = gp.load_all(conn, BASE)
        by = data['by_guid']
        assert by[G_DEFAULT]['user_version'] == 3 and by[G_DEFAULT]['computer_version'] == 7
        assert [f['name'] for f in by[G_COMPTA]['filtering']] == ['GRP-Compta']
        assert [f['name'] for f in by[G_COMPTA]['denied']] == ['jdupont']
        assert by[G_DEFAULT]['filtering'][0]['name'] == 'Utilisateurs authentifiés'
        assert {c for c, _ in by[G_VIDE]['issues']} == {'unlinked', 'disabled', 'empty', 'no_filtering'}
        assert by[G_VERROU]['links'][0]['enforced'] and by[G_VERROU]['links'][0]['order'] == 1
        assert [l['guid'] for l in data['orphan_links']] == [G_FANTOME]
        siege = [c for c in data['containers'] if c['name'] == 'Siege'][0]
        assert [(g['order'], g['missing']) for g in siege['gpos']] == [(1, False), (2, True)]


class TestApplied:
    def test_utilisateur(self, conn):
        r = gp.applied_gpos(conn, BASE, 'CN=Alice,OU=Siege,' + BASE)
        # Le lien « appliqué » du domaine passe devant la GPO de l'OU
        assert [g['name'] for g in r['applied']] == ['Verrouillage écran', 'Compta - Lecteurs réseau',
                                                      'Default Domain Policy']
        assert r['applied'][1]['via'] == 'GRP-Compta'
        assert any('n\'existe plus' in e['reason'] for e in r['excluded'])

    def test_refus_de_securite(self, conn):
        r = gp.applied_gpos(conn, BASE, 'CN=Jean,OU=Siege,' + BASE)
        assert 'Compta - Lecteurs réseau' not in [g['name'] for g in r['applied']]
        assert any('refus pour jdupont' in e['reason'] for e in r['excluded'])

    def test_heritage_bloque(self, conn):
        r = gp.applied_gpos(conn, BASE, 'CN=Zoe,OU=Labo,OU=Siege,' + BASE)
        # Seule la stratégie « appliquée » traverse le blocage
        assert [g['name'] for g in r['applied']] == ['Verrouillage écran']
        reasons = {e['name']: e['reason'] for e in r['excluded']}
        assert reasons['Default Domain Policy'] == 'Héritage bloqué par Labo'
        assert reasons['Compta - Lecteurs réseau'] == 'Héritage bloqué par Labo'

    def test_ordinateur(self, conn):
        r = gp.applied_gpos(conn, BASE, 'CN=PC1,OU=Siege,' + BASE)
        names = [g['name'] for g in r['applied']]
        assert names == ['Default Domain Policy']               # Verrouillage : partie ordinateur désactivée
        assert any(e['reason'] == 'Paramètres ordinateur désactivés' for e in r['excluded'])

    def test_ou(self, conn):
        r = gp.applied_gpos(conn, BASE, 'OU=Siege,' + BASE)
        assert r['target']['kind'] == 'ou' and len(r['applied']) == 3

    def test_hors_domaine(self, conn):
        with pytest.raises(gp.GpoError):
            gp.applied_gpos(conn, BASE, 'CN=x,DC=autre,DC=com')


class TestScope:
    def test_filtrage_par_groupe(self, conn):
        data = gp.load_all(conn, BASE)
        scope = gp.gpo_scope(conn, BASE, data['by_guid'][G_COMPTA], data)
        # Jean : refus ; Zoe : héritage bloqué sur Labo
        assert [u['name'] for u in scope['users']] == ['alice'] and scope['computers'] == []

    def test_lien_applique_traverse_le_blocage(self, conn):
        data = gp.load_all(conn, BASE)
        scope = gp.gpo_scope(conn, BASE, data['by_guid'][G_VERROU], data)
        assert [u['name'] for u in scope['users']] == ['alice', 'jdupont', 'zoe']
        assert scope['computers'] == []                          # partie ordinateur désactivée


class TestWrites:
    def test_lier_puis_delier(self, conn):
        target = 'OU=Labo,OU=Siege,' + BASE
        gp.change_link(conn, BASE, G_COMPTA, target, 'add')
        assert gp.parse_gplink(conn.containers[target]['gPLink'])[-1][1:] == (G_COMPTA, 0)
        with pytest.raises(gp.GpoError, match='déjà liée'):
            gp.change_link(conn, BASE, G_COMPTA, target, 'add')
        gp.change_link(conn, BASE, G_COMPTA, target, 'enforce')
        gp.change_link(conn, BASE, G_COMPTA, target, 'disable')
        assert gp.parse_gplink(conn.containers[target]['gPLink'])[0][2] == 3
        gp.change_link(conn, BASE, G_COMPTA, target, 'remove')
        assert conn.modified[-1][1]['gPLink'][0][1] == []        # attribut vidé, pas de chaîne vide

    def test_priorite(self, conn):
        gp.change_link(conn, BASE, G_DEFAULT, BASE, 'up')
        assert [g for _, g, _ in gp.parse_gplink(conn.containers[BASE]['gPLink'])] == [G_VERROU, G_DEFAULT]

    def test_nettoyer_un_lien_orphelin(self, conn):
        gp.change_link(conn, BASE, G_FANTOME, 'OU=Siege,' + BASE, 'remove')
        assert G_FANTOME not in conn.containers['OU=Siege,' + BASE]['gPLink']

    def test_refus(self, conn):
        with pytest.raises(gp.GpoError):
            gp.change_link(conn, BASE, G_FANTOME, BASE, 'add')              # GPO inexistante
        with pytest.raises(gp.GpoError):
            gp.change_link(conn, BASE, G_COMPTA, 'OU=x,DC=autre,DC=com', 'add')
        with pytest.raises(gp.GpoError):
            gp.change_link(conn, BASE, G_COMPTA, 'CN=Alice,OU=Siege,' + BASE, 'add')   # pas une OU
        with pytest.raises(gp.GpoError):
            gp.set_status(conn, BASE, G_COMPTA, 7)

    def test_etat_et_heritage(self, conn):
        gp.set_status(conn, BASE, G_COMPTA, 3)
        assert conn.gpos[G_COMPTA]['flags'] == 3
        gp.set_block_inheritance(conn, BASE, 'OU=Siege,' + BASE, True)
        assert conn.containers['OU=Siege,' + BASE]['gPOptions'] == 1


# --- Routes ------------------------------------------------------------------

@pytest.fixture
def client(conn, monkeypatch, tmp_path):
    import routes.gpo as rg
    from app import app
    from core.session_crypto import encrypt_password
    monkeypatch.setattr(rg, 'get_ad_connection', lambda *a, **k: (conn, None))
    monkeypatch.setattr(gp, 'BACKUP_ROOT', str(tmp_path / 'gpo_backups'))
    app.config['TESTING'] = True
    c = app.test_client()
    with c.session_transaction() as s:
        s.update(ad_server='dc', ad_username='CORP\\admin', ad_password=encrypt_password('x'),
                 ad_base_dn=BASE, user_role='admin', user_groups=['Domain Admins'])
    tok = re.search(rb'name="csrf-token" content="([^"]+)"', c.get('/gpo/').data).group(1).decode()
    return c, conn, tok


class TestRoutes:
    def test_pages(self, client):
        c, _, _ = client
        html = c.get('/gpo/').get_data(as_text=True)
        assert 'Compta - Lecteurs réseau' in html and 'GPO supprimée' in html and 'Bloqué' in html
        html = c.get('/gpo/view/' + G_COMPTA).get_data(as_text=True)
        assert 'GRP-Compta' in html and 'Refusé : jdupont' in html and 'Siege' in html
        html = c.get('/gpo/applied?name=alice').get_data(as_text=True)
        assert '3 stratégie(s) reçue(s)' in html and 'GRP-Compta' in html
        d = c.get('/gpo/api/scope/' + G_COMPTA).get_json()
        assert d['success'] and d['users_count'] == 1

    def test_lier_par_formulaire(self, client):
        c, conn, tok = client
        r = c.post('/gpo/link', data={'csrf_token': tok, 'guid': G_COMPTA, 'action': 'add',
                                      'target': 'OU=Labo,OU=Siege,' + BASE})
        assert r.status_code == 302 and G_COMPTA in conn.containers['OU=Labo,OU=Siege,' + BASE]['gPLink']

    def test_lecture_seule(self, client):
        c, conn, tok = client
        with c.session_transaction() as s:
            s.update(user_role='user', user_groups=['Utilisateurs du domaine'])
        assert c.get('/gpo/').status_code in (302, 403)
        c.post('/gpo/link', data={'csrf_token': tok, 'guid': G_COMPTA, 'action': 'remove',
                                  'target': 'OU=Siege,' + BASE})
        assert not conn.modified

    def test_sauvegarde_et_restauration(self, client, monkeypatch):
        c, _, tok = client
        calls = []

        def fake_ps(request, timeout=600):
            calls.append(request)
            if request['op'] == 'backup':
                return {'ok': True, 'gpos': [{'id': '11111111-2222-3333-4444-555555555555',
                                              'guid': G_COMPTA.strip('{}'), 'name': 'Compta - Lecteurs réseau'}]}
            return {'ok': True}
        monkeypatch.setattr(gp, '_run_ps', fake_ps)
        c.post('/gpo/backup', data={'csrf_token': tok})
        backups = gp.list_backups()
        assert len(backups) == 1 and backups[0]['gpos'][0]['guid'] == G_COMPTA and calls[0]['domain'] == 'corp.local'
        c.post('/gpo/restore', data={'csrf_token': tok, 'guid': G_COMPTA, 'backup': backups[0]['name']})
        assert calls[-1]['op'] == 'restore' and calls[-1]['backup_id'] == '11111111-2222-3333-4444-555555555555'
        n = len(calls)
        c.post('/gpo/restore', data={'csrf_token': tok, 'guid': G_DEFAULT, 'backup': backups[0]['name']})
        c.post('/gpo/restore', data={'csrf_token': tok, 'guid': G_COMPTA, 'backup': '..\\..\\x'})
        assert len(calls) == n                                   # GPO absente de la sauvegarde, nom forgé

    def test_script(self):
        raw = open(gp.PS_SCRIPT_PATH, 'rb').read()
        text = raw.decode('utf-8-sig')
        assert raw.startswith(b'\xef\xbb\xbf') and 'Backup-GPO -All' in text and 'Restore-GPO -BackupId' in text
        assert 'Invoke-Expression' not in text and '$impersonation.Undo()' in text.split('finally')[-1]
