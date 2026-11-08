# -*- coding: utf-8 -*-
"""
Dates AD et comptes verrouilles / expirants.

Avec le schema charge (get_info=ALL), ldap3 renvoie les FILETIME en datetime
UTC et maxPwdAge / lockoutDuration en timedelta. Le code faisait
int(str(valeur)) : l'exception etait avalee, si bien que sur un vrai AD
- les « mots de passe expirant » de la page Alertes valaient toujours 0 ;
- seuls les comptes sans lastLogon etaient comptes inactifs ;
- la colonne « dernier changement de mot de passe » des utilisateurs etait vide ;
- l'alerte automatique de mots de passe expirant ne se declenchait jamais.

Page Comptes verrouilles : le deblocage groupe lisait un champ que la page
n'envoyait pas, et le bouton individuel etait un formulaire imbrique.
"""
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

os.environ.setdefault('SECRET_KEY', 'test-account-dates')

from core.ad_dates import (ad_datetime, ad_interval, get_account_policy,  # noqa: E402
                           is_locked_out, last_logon, password_expiry, utcnow)

UTC = timezone.utc
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def filetime(dt):
    return int((dt - datetime(1601, 1, 1)).total_seconds() * 10_000_000)


class _A:
    def __init__(self, v):
        self.value = v
        self.values = v if isinstance(v, list) else ([] if v in (None, '') else [v])


class _E:
    def __init__(self, dn='CN=x,DC=corp,DC=local', **attrs):
        self.entry_dn = dn
        for k, v in attrs.items():
            setattr(self, k, _A(v))

    def __contains__(self, name):
        return hasattr(self, name)


class TestAdDates:
    def test_datetime_schema_values(self):
        """Formes renvoyees par ldap3 avec schema (vrai AD)."""
        assert ad_datetime(datetime(1601, 1, 1, tzinfo=UTC)) is None      # 0
        assert ad_datetime(datetime(9999, 12, 31, 23, 59, tzinfo=UTC)) is None  # jamais
        d = ad_datetime(_A(datetime(2026, 3, 1, 12, 0, tzinfo=UTC)))
        assert d == datetime(2026, 3, 1, 12, 0) and d.tzinfo is None

    def test_datetime_raw_values(self):
        """Formes sans schema : entier, chaine FILETIME, GeneralizedTime."""
        ref = datetime(2026, 3, 1, 12, 0)
        assert ad_datetime(filetime(ref)) == ref
        assert ad_datetime(str(filetime(ref))) == ref
        assert ad_datetime(b'20260301120000.0Z') == ref
        assert ad_datetime(0) is None
        assert ad_datetime(0x7FFFFFFFFFFFFFFF) is None
        assert ad_datetime('n/a') is None

    def test_interval(self):
        assert ad_interval(timedelta(days=42)) == timedelta(days=42)
        assert ad_interval(timedelta.max) is None                        # jamais
        assert ad_interval(-36288000000000) == timedelta(days=42)
        assert ad_interval(-0x8000000000000000) is None
        assert ad_interval(0) == timedelta(0)

    def test_last_logon_prend_la_plus_recente(self):
        """lastLogon est propre au DC : avec 2 DC il peut etre plus ancien."""
        recent = datetime(2026, 10, 1, tzinfo=UTC)
        e = _E(lastLogon=datetime(2025, 1, 1, tzinfo=UTC), lastLogonTimestamp=recent)
        assert last_logon(e) == recent.replace(tzinfo=None)
        assert last_logon(_E(lastLogon=datetime(1601, 1, 1, tzinfo=UTC))) is None

    def test_lockout(self):
        now = utcnow()
        thirty = timedelta(minutes=30)
        assert is_locked_out(now - timedelta(minutes=5), thirty, now)
        # Verrou expire : lockoutTime reste renseigne jusqu'a la connexion suivante
        assert not is_locked_out(now - timedelta(hours=2), thirty, now)
        # Duree 0 : verrouille jusqu'au deblocage par un administrateur
        assert is_locked_out(now - timedelta(days=30), timedelta(0), now)
        assert not is_locked_out(datetime(1601, 1, 1, tzinfo=UTC), thirty, now)

    def test_password_expiry(self):
        set_at = datetime(2026, 1, 1, tzinfo=UTC)
        assert password_expiry(set_at, timedelta(days=42)) == datetime(2026, 2, 12)
        assert password_expiry(set_at, timedelta(days=42), uac=0x10200) is None  # n'expire jamais
        assert password_expiry(set_at, None) is None                             # strategie : jamais
        assert password_expiry(0, timedelta(days=42)) is None                    # changement impose

    def test_policy(self):
        class Conn:
            entries = [_E(maxPwdAge=timedelta(days=60), lockoutDuration=timedelta(minutes=10))]

            def search(self, *a, **k):
                pass
        assert get_account_policy(Conn(), 'DC=corp,DC=local') == {
            'max_pwd_age': timedelta(days=60), 'lockout_duration': timedelta(minutes=10)}


# --- Statistiques (centre des alertes) -------------------------------------

def _users(now):
    def u(sam, **kw):
        base = dict(cn=sam, sAMAccountName=sam, userAccountControl=512, primaryGroupID=513,
                    whenCreated=now - timedelta(days=400))
        base.update(kw)
        return _E(dn=f'CN={sam},OU=U,DC=corp,DC=local', **base)
    return [
        u('pwd_soon', pwdLastSet=now - timedelta(days=35), lastLogonTimestamp=now),
        u('pwd_ok', pwdLastSet=now - timedelta(days=2), lastLogonTimestamp=now),
        u('pwd_never', pwdLastSet=now - timedelta(days=35), userAccountControl=0x10200,
          lastLogonTimestamp=now),
        u('inactive', lastLogonTimestamp=now - timedelta(days=200)),
        u('never_old'),                                                # jamais connecte, ancien
        u('never_new', whenCreated=now - timedelta(days=3)),           # jamais connecte, recent
        u('locked', lockoutTime=now - timedelta(minutes=5), lastLogonTimestamp=now),
        u('lock_expired', lockoutTime=now - timedelta(hours=3), lastLogonTimestamp=now),
        u('expiring', accountExpires=now + timedelta(days=10), lastLogonTimestamp=now),
        u('disabled', userAccountControl=514, pwdLastSet=now - timedelta(days=35)),
        u('krbtgt', userAccountControl=514),
    ]


class _StatsConn:
    def __init__(self, policy):
        self.entries = [policy]

    def search(self, *a, **k):
        pass

    def unbind(self):
        pass


def test_compute_account_alerts(monkeypatch):
    import core.account_stats as st
    import routes.core as rc
    now = datetime.now(UTC)
    users = _users(now)
    groups = [
        _E(dn='CN=Admins du domaine,CN=Users,DC=corp,DC=local', objectSid='S-1-5-21-1-2-3-512',
           member=['CN=a'], isCriticalSystemObject=True),
        _E(dn='CN=Utilisateurs du domaine,CN=Users,DC=corp,DC=local',
           objectSid='S-1-5-21-1-2-3-513', member=[]),                 # primaire, pas vide
        _E(dn='CN=Utilisateurs,CN=Builtin,DC=corp,DC=local', objectSid='S-1-5-32-545', member=[]),
        _E(dn='CN=Vide1,OU=G,DC=corp,DC=local', objectSid='S-1-5-21-1-2-3-1201', member=[]),
        _E(dn='CN=Vide2,OU=G,DC=corp,DC=local', objectSid='S-1-5-21-1-2-3-1202', member=[]),
        _E(dn='CN=Plein,OU=G,DC=corp,DC=local', objectSid='S-1-5-21-1-2-3-1203', member=['CN=b']),
    ]
    filters = []

    def fake_paged(conn, base, flt, attributes=None, **k):
        filters.append(flt)
        if 'objectClass=group' in flt:
            return groups
        if '1.2.840.113556.1.4.1941' in flt:
            return [object(), object()]
        return users
    monkeypatch.setattr(rc, 'paged_search', fake_paged)
    policy = _E(maxPwdAge=timedelta(days=42), lockoutDuration=timedelta(minutes=30))

    data = st.compute_account_alerts(_StatsConn(policy), 'DC=corp,DC=local')

    assert data['password_expiring'] == 1          # pwd_soon (le compte desactive est ignore)
    assert data['inactive_accounts'] == 2          # inactive + never_old (pas never_new, pas krbtgt)
    assert data['locked_accounts'] == 1            # lock_expired n'est plus verrouille
    assert data['expiring_accounts'] == 1
    assert data['disabled_accounts'] == 2
    assert data['empty_groups'] == 2               # Vide1, Vide2
    assert data['privileged_accounts'] == 2
    # Groupe admin trouve par SID (nom francais), appartenance imbriquee
    admin_filter = [f for f in filters if '1.2.840.113556.1.4.1941' in f][0]
    assert 'CN=Admins du domaine' in admin_filter


# --- Routes ------------------------------------------------------------------

def _session(c):
    from core.session_crypto import encrypt_password
    with c.session_transaction() as s:
        s.update(ad_server='dc', ad_username='CORP\\admin', ad_password=encrypt_password('x'),
                 ad_base_dn='DC=corp,DC=local', user_role='admin', user_groups=['Domain Admins'])


class _RouteConn:
    """Connexion factice : renvoie la strategie puis les comptes verrouilles."""
    def __init__(self, now):
        self.now = now
        self.entries = []
        self.modified = []
        self.result = {'result': 0}

    def search(self, base, flt, scope=None, attributes=None, **k):
        if 'maxPwdAge' in (attributes or []):
            self.entries = [_E(maxPwdAge=timedelta(days=42), lockoutDuration=timedelta(minutes=30))]
        elif 'lockoutTime>=1' in flt:
            self.entries = [
                _E(dn='CN=Bloque,OU=U,DC=corp,DC=local', cn='Bloque', sAMAccountName='bloque',
                   mail='b@corp.local', lockoutTime=self.now - timedelta(minutes=2)),
                _E(dn='CN=Ancien,OU=U,DC=corp,DC=local', cn='Ancien', sAMAccountName='ancien',
                   mail='', lockoutTime=self.now - timedelta(days=3)),
            ]
        else:
            self.entries = []

    def modify(self, dn, changes):
        self.modified.append(dn)

    def unbind(self):
        pass


@pytest.fixture
def locked_client(monkeypatch):
    import routes.tools.accounts as acc
    from app import app
    conn = _RouteConn(datetime.now(UTC))
    monkeypatch.setattr(acc, 'get_ad_connection', lambda *a, **k: (conn, None))
    app.config['TESTING'] = True
    c = app.test_client()
    _session(c)
    return c, conn


def _csrf(c, url):
    m = re.search(rb'name="csrf-token" content="([^"]+)"', c.get(url).data)
    return m.group(1).decode()


class TestLockedAccounts:
    def test_seuls_les_verrous_actifs_sont_listes(self, locked_client):
        c, _ = locked_client
        html = c.get('/tools/locked-accounts').get_data(as_text=True)
        assert 'bloque' in html and 'ancien' not in html
        assert '1 compte(s) verrouillé(s)' in html

    def test_pas_de_formulaire_imbrique(self, locked_client):
        c, _ = locked_client
        html = c.get('/tools/locked-accounts').get_data(as_text=True)
        body = re.sub(r'<script.*?</script>', '', html, flags=re.S)
        depth = 0
        for m in re.finditer(r'<(/?)form\b', body):
            depth += -1 if m.group(1) else 1
            assert depth <= 1, 'formulaire imbrique : le bouton soumet le mauvais formulaire'
        assert 'formaction="/tools/locked-accounts/unlock/CN=Bloque' in html

    def test_deblocage_groupe_lit_les_cases_cochees(self, locked_client):
        c, conn = locked_client
        tok = _csrf(c, '/tools/locked-accounts')
        r = c.post('/tools/locked-accounts/unlock', data={
            'csrf_token': tok, 'dns': ['CN=Bloque,OU=U,DC=corp,DC=local']})
        assert r.status_code == 302
        assert conn.modified == ['CN=Bloque,OU=U,DC=corp,DC=local']


def test_page_comptes_expirants(monkeypatch):
    import routes.core as rc
    import routes.tools.accounts as acc
    from app import app
    now = datetime.now(UTC)
    users = _users(now)
    monkeypatch.setattr(rc, 'paged_search', lambda *a, **k: users)
    monkeypatch.setattr(acc, 'get_ad_connection',
                        lambda *a, **k: (_StatsConn(_E(maxPwdAge=timedelta(days=42))), None))
    app.config['TESTING'] = True
    c = app.test_client()
    _session(c)
    html = c.get('/tools/expiring').get_data(as_text=True)
    assert 'Mots de passe expirant (1)' in html and 'pwd_soon' in html
    assert 'pwd_ok' not in html                      # l'ancien filtre listait tout le monde
    assert 'Comptes inactifs (2)' in html and 'never_old' in html and 'never_new' not in html
    assert 'Comptes expirants (1)' in html
    assert 'durée maximale du domaine : 42 jours' in html
    assert '>None<' not in html

    r = c.get('/tools/expiring/export-pdf')
    assert r.status_code == 200 and r.mimetype == 'application/pdf'
    assert r.data.startswith(b'%PDF')


def test_page_alertes(monkeypatch):
    import routes.admin_tools as at
    import routes.core as rc
    from app import app
    now = datetime.now(UTC)
    users = _users(now)
    monkeypatch.setattr(rc, 'paged_search',
                        lambda c, b, flt, **k: [] if 'group' in flt or '1941' in flt else users)
    policy = _E(maxPwdAge=timedelta(days=42), lockoutDuration=timedelta(minutes=30))
    monkeypatch.setattr(at, 'get_ad_connection', lambda *a, **k: (_StatsConn(policy), None))
    app.config['TESTING'] = True
    c = app.test_client()
    _session(c)
    html = c.get('/alerts').get_data(as_text=True)
    assert '1 mot(s) de passe expirant' in html
    assert '1 compte(s) verrouillé(s)' in html
    assert '1 compte(s) expirant' in html
