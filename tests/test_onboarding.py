# -*- coding: utf-8 -*-
"""
Arrivée d'un utilisateur : adresse pro synchronisée avec Entra ID, groupe de
licence, mail de bienvenue sur l'adresse personnelle ; envoi SMTP commun.

Avant la v1.53.0, la configuration SMTP de la page Admin était enregistrée
mais jamais lue : rapports d'audit et alertes ne partaient pas.
"""
import json
import os
import re

import pytest

os.environ.setdefault('SECRET_KEY', 'test-onboarding')

from core import onboarding as ob  # noqa: E402

SMTP = {'enabled': True, 'server': 'smtp.office365.com', 'port': 587, 'use_tls': True,
        'use_auth': True, 'username': 'noreply@laprovidence.fr', 'password': 'smtp-secret',
        'from_email': 'noreply@laprovidence.fr', 'from_name': 'Informatique'}


# --- Adresses ----------------------------------------------------------------

@pytest.mark.parametrize('first,last,pattern,expected', [
    ('Élodie', 'Le Gall', 'prenom.nom', 'elodie.le-gall@laprovidence.fr'),
    ('Jean-Pierre', "O'Brien", 'prenom.nom', 'jean-pierre.obrien@laprovidence.fr'),
    ('Chloé', 'Dupont', 'p.nom', 'c.dupont@laprovidence.fr'),
    ('Jean-Pierre', 'Dupont', 'prenomnom', 'jeanpierredupont@laprovidence.fr'),
    ('Zoë', 'Lætitia', 'nom.prenom', 'laetitia.zoe@laprovidence.fr'),
    ('  ', 'Dupont', 'prenom.nom', ''),
])
def test_build_address(first, last, pattern, expected):
    assert ob.build_address(first, last, 'laprovidence.fr', pattern) == expected


def test_identity_attributes():
    attrs = ob.identity_attributes('jean.dupont@laprovidence.fr', 'jean@gmail.com', True)
    assert attrs == {'mail': 'jean.dupont@laprovidence.fr',
                     'proxyAddresses': ['SMTP:jean.dupont@laprovidence.fr'],
                     'userPrincipalName': 'jean.dupont@laprovidence.fr',
                     'otherMailbox': ['jean@gmail.com']}
    assert 'userPrincipalName' not in ob.identity_attributes('a@b.fr', '', False)


@pytest.mark.parametrize('value,ok', [('jean.dupont@laprovidence.fr', True), ("o'brien@x.fr", True),
                                      ('a@b', False), ('a b@c.fr', False), ('a@@b.fr', False),
                                      ('a..b@c.fr', False), ('x@y.fr\nBcc: z@w.fr', False)])
def test_valid_email(value, ok):
    assert ob.valid_email(value) is ok


# --- Modèle du mail ----------------------------------------------------------

class TestTemplate:
    def test_champs_inconnus_refuses(self):
        for bad in ('{inconnu}', '{mot_de_passe.__class__}', '{prenom[0]}', '{prenom!r}', '{prenom:>10}', '{'):
            with pytest.raises(ob.OnboardingError):
                ob.check_template(bad)
        ob.check_template('Bonjour {prenom}, {{accolades}}')

    def test_rendu_echappe(self):
        settings = {'welcome_subject': 'Bienvenue {prenom}', 'welcome_body': 'Mot de passe : {mot_de_passe}\n<b>fixe</b>'}
        subject, text, html = ob.render_welcome(settings, {'prenom': 'Jean', 'mot_de_passe': '<script>x</script>&'})
        assert subject == 'Bienvenue Jean'
        assert '<script>x</script>&' in text
        assert '<script>' not in html and '&lt;script&gt;x&lt;/script&gt;&amp;' in html
        assert '&lt;b&gt;fixe' in html            # le HTML du modèle n'est pas interprété


# --- Envoi SMTP --------------------------------------------------------------

class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.calls = host, port, []
        FakeSMTP.instances.append(self)

    def starttls(self):
        self.calls.append('starttls')

    def login(self, user, password):
        self.calls.append(('login', user, password))

    def send_message(self, msg):
        self.calls.append(('send', msg))

    def quit(self):
        self.calls.append('quit')


@pytest.fixture
def smtp(monkeypatch, tmp_path):
    import core.settings_manager as sm
    import core.mailer as mailer
    monkeypatch.setattr(sm, 'SETTINGS_FILE', str(tmp_path / 'settings.json'))
    sm.set_setting('smtp', dict(SMTP))
    FakeSMTP.instances = []
    monkeypatch.setattr(mailer.smtplib, 'SMTP', FakeSMTP)
    monkeypatch.setattr(mailer.smtplib, 'SMTP_SSL', FakeSMTP)
    return FakeSMTP


class TestMailer:
    def test_envoi_starttls(self, smtp):
        from core.mailer import send_mail
        send_mail('jean@gmail.com', 'Sujet', 'Texte', html='<p>Texte</p>')
        s = smtp.instances[-1]
        assert (s.host, s.port) == ('smtp.office365.com', 587)
        assert s.calls[0] == 'starttls' and s.calls[1] == ('login', 'noreply@laprovidence.fr', 'smtp-secret')
        msg = s.calls[2][1]
        assert msg['To'] == 'jean@gmail.com' and 'Informatique' in msg['From']

    def test_injection_en_tete_refusee(self, smtp):
        from core.mailer import MailError, send_mail
        with pytest.raises(MailError):
            send_mail('jean@gmail.com\nBcc: x@y.fr', 'S', 'T')
        assert not smtp.instances

    def test_non_configure(self, smtp):
        import core.settings_manager as sm
        from core.mailer import MailError, send_mail
        sm.set_setting('smtp', dict(SMTP, enabled=False))
        with pytest.raises(MailError, match='pas configuré'):
            send_mail('a@b.fr', 'S', 'T')

    def test_alertes_utilisent_la_page_admin(self, smtp):
        """L'ancien code lisait des SMTP_* absents de config.py : rien ne partait."""
        import core.settings_manager as sm
        from core.email_notifications import send_alert_email
        sm.set_setting('smtp.alert_recipient', 'it@laprovidence.fr')
        assert send_alert_email('Test', 'Message') is True
        assert smtp.instances[-1].calls[2][1]['To'] == 'it@laprovidence.fr'


# --- Création d'un utilisateur ---------------------------------------------

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


class _Info:
    other = {'configurationNamingContext': ['CN=Configuration,DC=laprovidence,DC=local']}


class _Server:
    info = _Info()


class FakeConn:
    def __init__(self):
        self.server = _Server()
        self.entries = []
        self.result = {'result': 0}
        self.added, self.modified = [], []
        self.taken = {'deja.pris@laprovidence.fr': 'CN=Deja Pris,OU=Users,DC=laprovidence,DC=local'}

    def search(self, base, flt, scope=None, attributes=None, **k):
        self.entries = []
        if base.startswith('CN=Partitions'):
            self.entries = [_E(base, uPNSuffixes=['laprovidence.fr'])]
        elif 'organizationalUnit' in flt:
            self.entries = [_E('OU=Users,DC=laprovidence,DC=local', name='Users')]
        elif 'objectClass=group' in flt and 'LIC_M365' in flt:
            self.entries = [_E('CN=LIC_M365,OU=Groupes,DC=laprovidence,DC=local', cn='LIC_M365')]
        elif '(mail=' in flt:
            addr = re.search(r'\(mail=([^)]+)\)', flt).group(1)
            if addr in self.taken:
                self.entries = [_E(self.taken[addr], cn='x')]

    def add(self, dn, attributes=None, **k):
        self.added.append((dn, attributes))
        self.result = {'result': 0}
        return True

    def modify(self, dn, changes):
        self.modified.append((dn, changes))
        self.result = {'result': 0}
        return True

    def delete(self, dn):
        return True

    def unbind(self):
        pass


@pytest.fixture
def env(smtp, monkeypatch):
    import core.settings_manager as sm
    import routes.users.create as uc
    from app import app
    sm.set_setting('onboarding', {'email_domain': 'laprovidence.fr', 'pattern': 'prenom.nom',
                                  'set_upn': True, 'license_groups': ['LIC_M365']})
    conn = FakeConn()
    monkeypatch.setattr(uc, 'get_ad_connection', lambda *a, **k: (conn, None))
    audit = []
    monkeypatch.setattr(uc, 'log_action', lambda *a, **k: audit.append(a))
    app.config['TESTING'] = True
    client = app.test_client()
    from core.session_crypto import encrypt_password
    with client.session_transaction() as s:
        s.update(ad_server='dc', ad_username='LAPROVIDENCE\\admin', ad_password=encrypt_password('x'),
                 ad_base_dn='DC=laprovidence,DC=local', ad_use_ssl=True, user_role='admin',
                 user_groups=['Domain Admins'])
    html = client.get('/users/create').get_data(as_text=True)
    tok = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
    return client, conn, tok, audit, html


FORM = {'username': 'jdupont', 'first_name': 'Jean', 'last_name': 'Dupont', 'password': 'Provisoire-2026!',
        'must_change_password': 'on', 'email': 'jean.dupont@laprovidence.fr', 'set_upn': 'on',
        'personal_email': 'jean.dupont@gmail.com', 'send_welcome': 'on',
        'license_group': 'CN=LIC_M365,OU=Groupes,DC=laprovidence,DC=local', 'target_ou': ''}


class TestCreate:
    def test_formulaire(self, env):
        html = env[4]
        assert 'name="personal_email"' in html and 'name="send_welcome"' in html
        assert '@laprovidence.fr' in html and 'LIC_M365' in html
        assert 'Math.random()' not in html and 'getRandomValues' in html

    def test_creation_complete(self, env):
        client, conn, tok, audit, _ = env
        r = client.post('/users/create', data=dict(FORM, csrf_token=tok))
        assert r.status_code == 302
        dn, attrs = conn.added[0]
        assert attrs['mail'] == 'jean.dupont@laprovidence.fr'
        assert attrs['proxyAddresses'] == ['SMTP:jean.dupont@laprovidence.fr']
        assert attrs['userPrincipalName'] == 'jean.dupont@laprovidence.fr'
        assert attrs['otherMailbox'] == ['jean.dupont@gmail.com']
        # Groupe de licence
        assert ('CN=LIC_M365,OU=Groupes,DC=laprovidence,DC=local',
                {'member': [(conn.modified[-1][1]['member'][0][0], [dn])]}) == conn.modified[-1]
        # Mail de bienvenue sur l'adresse personnelle
        msg = [c for c in env_smtp_calls() if isinstance(c, tuple) and c[0] == 'send'][-1][1]
        assert msg['To'] == 'jean.dupont@gmail.com'
        text = msg.get_body(('plain',)).get_content()
        assert 'Provisoire-2026!' in text and 'jean.dupont@laprovidence.fr' in text
        # Le journal d'audit ne contient pas le mot de passe
        assert 'Provisoire-2026!' not in json.dumps([list(map(str, a)) for a in audit])

    def test_domaine_non_declare(self, env):
        client, conn, tok, _, _ = env
        r = client.post('/users/create', data=dict(FORM, csrf_token=tok, email='jean@autre.fr'))
        assert r.status_code == 200 and not conn.added
        html = r.get_data(as_text=True)
        assert 'suffixe UPN' in html
        assert 'value="jdupont"' in html                 # saisie conservée

    def test_adresse_deja_prise(self, env):
        client, conn, tok, _, _ = env
        r = client.post('/users/create', data=dict(FORM, csrf_token=tok, email='deja.pris@laprovidence.fr'))
        assert not conn.added and 'déjà utilisée' in r.get_data(as_text=True)

    def test_bienvenue_sans_adresse_perso(self, env):
        client, conn, tok, _, _ = env
        client.post('/users/create', data=dict(FORM, csrf_token=tok, personal_email=''))
        assert not conn.added

    def test_groupe_de_licence_force(self, env):
        client, conn, tok, _, _ = env
        client.post('/users/create', data=dict(FORM, csrf_token=tok,
                                               license_group='CN=Domain Admins,CN=Users,DC=laprovidence,DC=local'))
        assert not conn.added

    def test_sans_upn(self, env):
        client, conn, tok, _, _ = env
        form = dict(FORM, csrf_token=tok)
        form.pop('set_upn')
        client.post('/users/create', data=form)
        assert conn.added[0][1]['userPrincipalName'] == 'jdupont@laprovidence.local'

    def test_suggestion(self, env):
        client, conn, _, _, _ = env
        conn.taken['jean.dupont@laprovidence.fr'] = 'CN=Autre,DC=laprovidence,DC=local'
        d = client.get('/users/api/address-suggestion?first=Jean&last=Dupont&domain=laprovidence.fr').get_json()
        assert d['address'] == 'jean.dupont2@laprovidence.fr'
        d = client.get('/users/api/address-suggestion?address=jean.dupont@laprovidence.fr').get_json()
        assert d['owner'] == 'CN=Autre,DC=laprovidence,DC=local'


def env_smtp_calls():
    return [c for s in FakeSMTP.instances for c in s.calls]


class TestSettings:
    def test_enregistrement_et_exemple(self, env):
        client, _, tok, _, _ = env
        r = client.post('/users/settings/messagerie', data={
            'csrf_token': tok, 'email_domain': 'laprovidence.fr', 'pattern': 'p.nom', 'set_upn': 'on',
            'license_groups': 'LIC_M365\nLIC_E3', 'welcome_subject': 'Bienvenue {prenom}',
            'welcome_body': 'Bonjour {prenom}, votre mot de passe : {mot_de_passe}'})
        assert r.status_code == 302
        s = ob.get_onboarding_settings()
        assert s['pattern'] == 'p.nom' and s['license_groups'] == ['LIC_M365', 'LIC_E3']
        html = client.get('/users/settings/messagerie').get_data(as_text=True)
        assert 'LIC_E3' in html and 'Introuvables' in html     # groupe absent de l'AD signalé
        client.post('/users/settings/messagerie', data={'csrf_token': tok, 'action': 'test',
                                                         'test_to': 'admin@laprovidence.fr'})
        msg = [c for c in env_smtp_calls() if isinstance(c, tuple) and c[0] == 'send'][-1][1]
        assert msg['Subject'].startswith('[Exemple] Bienvenue Jean')

    def test_modele_invalide(self, env):
        client, _, tok, _, _ = env
        html = client.post('/users/settings/messagerie', data={
            'csrf_token': tok, 'pattern': 'prenom.nom', 'welcome_subject': 'x',
            'welcome_body': 'Bonjour {prenom.__class__}'}).get_data(as_text=True)
        assert 'Champ inconnu' in html


def test_admin_smtp_conserve_le_mot_de_passe(smtp, monkeypatch):
    import core.settings_manager as sm
    from app import app
    from core.session_crypto import encrypt_password
    app.config['TESTING'] = True
    client = app.test_client()
    with client.session_transaction() as s:
        s.update(ad_server='dc', ad_username='X\\admin', ad_password=encrypt_password('x'),
                 ad_base_dn='DC=x,DC=local', user_role='admin', user_groups=['Domain Admins'])
    tok = re.search(rb'name="csrf-token" content="([^"]+)"', client.get('/dashboard').data).group(1).decode()
    client.post('/admin/save/smtp', data={'csrf_token': tok, 'smtp_enabled': 'on', 'smtp_server': 'smtp.x.fr',
                                          'smtp_port': '587', 'smtp_password': '', 'smtp_from_email': 'a@x.fr',
                                          'smtp_alert_recipient': 'it@x.fr'})
    smtp_settings = sm.load_settings()['smtp']
    assert smtp_settings['password'] == 'smtp-secret' and smtp_settings['alert_recipient'] == 'it@x.fr'


# --- Utilisateur existant ----------------------------------------------------

USER_DN = 'CN=Jean Dupont,OU=Users,DC=laprovidence,DC=local'


def test_merge_proxy_addresses():
    from routes.users.update import merge_proxy_addresses
    current = ['SMTP:jean.dupont@laprovidence.fr', 'smtp:jd@laprovidence.fr', 'X500:/o=Org/cn=jd']
    assert merge_proxy_addresses(current, 'jean.dupont@laprovidence.com') == [
        'SMTP:jean.dupont@laprovidence.com', 'smtp:jean.dupont@laprovidence.fr',
        'smtp:jd@laprovidence.fr', 'X500:/o=Org/cn=jd']
    assert merge_proxy_addresses(current, 'jean.dupont@laprovidence.com', keep_old_as_alias=False) == [
        'SMTP:jean.dupont@laprovidence.com', 'smtp:jd@laprovidence.fr', 'X500:/o=Org/cn=jd']
    # Un alias promu adresse principale n'est pas dupliqué
    assert merge_proxy_addresses(current, 'jd@laprovidence.fr') == [
        'SMTP:jd@laprovidence.fr', 'smtp:jean.dupont@laprovidence.fr', 'X500:/o=Org/cn=jd']


class UserConn(FakeConn):
    def __init__(self, personal='jean.dupont@gmail.com'):
        super().__init__()
        self.personal = personal

    def search(self, base, flt, scope=None, attributes=None, **k):
        if base == USER_DN and str(scope).upper() == 'BASE':
            attrs = dict(cn='Jean Dupont', displayName='Jean Dupont', sAMAccountName='jdupont',
                         givenName='Jean', sn='Dupont', mail='jean.dupont@laprovidence.fr',
                         userPrincipalName='jean.dupont@laprovidence.fr',
                         proxyAddresses=['SMTP:jean.dupont@laprovidence.fr'], memberOf=[],
                         department='', title='', telephoneNumber='', description='')
            if self.personal:
                attrs['otherMailbox'] = [self.personal]
            self.entries = [_E(USER_DN, **attrs)]
            return
        super().search(base, flt, scope, attributes, **k)


@pytest.fixture
def user_env(env, monkeypatch):
    import routes.users.password as up
    import routes.users.update as uu
    client, _, tok, audit, _ = env
    conn = UserConn()
    for mod in (uu, up):
        monkeypatch.setattr(mod, 'get_ad_connection', lambda *a, **k: (conn, None))
        monkeypatch.setattr(mod, 'log_action', lambda *a, **k: audit.append(a))
    return client, conn, tok, audit


class TestExistingUser:
    def test_fiche(self, user_env):
        client = user_env[0]
        html = client.get(f'/users/{USER_DN}/edit').get_data(as_text=True)
        assert 'name="pro_email"' in html and 'jean.dupont@gmail.com' in html
        assert 'name="mail"' not in html            # plus de modification de mail seul
        assert '/users/CN=Jean%20Dupont,OU=Users,DC=laprovidence,DC=local/send-credentials' in html

    def test_changement_adresse(self, user_env):
        client, conn, tok, _ = user_env
        client.post(f'/users/{USER_DN}/edit', data={
            'csrf_token': tok, 'action': 'update_mail', 'pro_email': 'J.Dupont@LAPROVIDENCE.fr',
            'personal_email': 'jd.perso@gmail.com', 'set_upn': 'on', 'keep_alias': 'on'})
        dn, changes = [m for m in conn.modified if m[0] == USER_DN][-1]
        assert changes['mail'][0][1] == ['j.dupont@laprovidence.fr']
        assert changes['proxyAddresses'][0][1] == ['SMTP:j.dupont@laprovidence.fr',
                                                   'smtp:jean.dupont@laprovidence.fr']
        assert changes['userPrincipalName'][0][1] == ['j.dupont@laprovidence.fr']
        assert changes['otherMailbox'][0][1] == ['jd.perso@gmail.com']

    def test_adresse_prise_par_un_autre(self, user_env):
        client, conn, tok, _ = user_env
        client.post(f'/users/{USER_DN}/edit', data={'csrf_token': tok, 'action': 'update_mail',
                                                     'pro_email': 'deja.pris@laprovidence.fr'})
        assert not [m for m in conn.modified if m[0] == USER_DN]

    def test_l_ancien_champ_mail_est_ignore(self, user_env):
        client, conn, tok, _ = user_env
        client.post(f'/users/{USER_DN}/edit', data={'csrf_token': tok, 'mail': 'x@y.fr', 'title': 'Comptable'})
        changed = {k for dn, ch in conn.modified if dn == USER_DN for k in ch}
        assert 'mail' not in changed and 'title' in changed

    def test_nouveau_mot_de_passe_par_mail(self, user_env):
        client, conn, tok, audit = user_env
        client.post(f'/users/{USER_DN}/send-credentials', data={'csrf_token': tok})
        pwd_change = [ch for dn, ch in conn.modified if dn == USER_DN and 'unicodePwd' in ch][0]
        password = pwd_change['unicodePwd'][0][1][0].decode('utf-16-le').strip('"')
        assert len(password) >= 12
        assert any('pwdLastSet' in ch for dn, ch in conn.modified if dn == USER_DN)
        msg = [c for c in env_smtp_calls() if isinstance(c, tuple) and c[0] == 'send'][-1][1]
        assert msg['To'] == 'jean.dupont@gmail.com' and password in msg.get_body(('plain',)).get_content()
        assert password not in json.dumps([list(map(str, a)) for a in audit])

    def test_sans_smtp_mot_de_passe_inchange(self, user_env):
        import core.settings_manager as sm
        client, conn, tok, _ = user_env
        sm.set_setting('smtp', dict(SMTP, enabled=False))
        client.post(f'/users/{USER_DN}/send-credentials', data={'csrf_token': tok})
        assert not [ch for dn, ch in conn.modified if 'unicodePwd' in ch]

    def test_sans_adresse_personnelle(self, user_env):
        client, conn, tok, _ = user_env
        conn.personal = ''
        client.post(f'/users/{USER_DN}/send-credentials', data={'csrf_token': tok})
        assert not [ch for dn, ch in conn.modified if 'unicodePwd' in ch]

    def test_connexion_non_chiffree(self, user_env):
        client, conn, tok, _ = user_env
        with client.session_transaction() as s:
            s['ad_use_ssl'] = False
        client.post(f'/users/{USER_DN}/send-credentials', data={'csrf_token': tok})
        assert not [ch for dn, ch in conn.modified if 'unicodePwd' in ch]
