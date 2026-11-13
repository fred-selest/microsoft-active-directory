# -*- coding: utf-8 -*-
"""
Confort d'utilisation (v1.60) : recherche rapide, fiche de groupe
(identifiant des membres, imbrication), modèles proposés à la création
d'un compte, éléments communs de mise en page.
"""
import os
import re
from pathlib import Path

import pytest

os.environ.setdefault('SECRET_KEY', 'test-ergonomie')

ROOT = Path(__file__).resolve().parent.parent
BASE = 'DC=laprovidence,DC=local'


class _A:
    def __init__(self, v):
        self.values = v if isinstance(v, list) else [v]
        self.value = v

    def __bool__(self):
        return bool(self.values)

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
    """Répond selon la base de recherche : une fiche (BASE) ou la liste donnée (SUBTREE)."""

    def __init__(self, by_dn=None, found=None, boom=False):
        self.by_dn, self.found, self.boom = by_dn or {}, found or [], boom
        self.entries, self.result, self.filters = [], {'result': 0}, []

    def search(self, base, flt, scope=None, attributes=None, **k):
        if self.boom:
            raise RuntimeError('annuaire injoignable')
        self.filters.append(flt)
        self.entries = [self.by_dn[base]] if base in self.by_dn else (self.found if base == BASE else [])
        return bool(self.entries)

    def unbind(self):
        pass


@pytest.fixture
def client():
    from app import app
    from core.session_crypto import encrypt_password
    app.config['TESTING'] = True
    c = app.test_client()
    with c.session_transaction() as s:
        s.update(ad_server='dc', ad_username='LAPROVIDENCE\\admin', ad_password=encrypt_password('x'),
                 ad_base_dn=BASE, user_role='admin', user_groups=['Domain Admins'])
    return c


class TestRechercheRapide:
    FOUND = [
        _E(f'CN=PC-MARTIN,OU=Postes,{BASE}', objectClass=['top', 'person', 'user', 'computer'], cn='PC-MARTIN',
           sAMAccountName='PC-MARTIN$'),
        _E(f'CN=Zoé Martinez,OU=Profs,{BASE}', objectClass=['top', 'person', 'user'], cn='Zoé Martinez',
           sAMAccountName='zmartinez', displayName='Zoé Martinez', mail='zoe@laprovidence.fr'),
        _E(f'CN=Alice Martin,OU=Profs,{BASE}', objectClass=['top', 'person', 'user'], cn='Alice Martin',
           sAMAccountName='amartin', displayName='Alice Martin'),
        _E(f'CN=GG_Martinique,OU=Groupes,{BASE}', objectClass=['top', 'group'], cn='GG_Martinique'),
        _E(f'OU=Martigues,{BASE}', objectClass=['top', 'organizationalUnit'], ou='Martigues'),
    ]

    def test_resultats_classes_avec_leur_lien(self, client, monkeypatch):
        import routes.api as api
        conn = Conn(found=self.FOUND)
        monkeypatch.setattr(api, 'get_ad_connection', lambda *a, **k: (conn, None))
        rows = client.get('/api/quick-search?q=mart').get_json()
        assert [r['kind'] for r in rows] == ['user', 'user', 'group', 'computer', 'ou']
        assert rows[0]['label'] == 'Alice Martin' and rows[0]['url'].endswith('/overview')
        assert rows[1]['detail'] == 'zmartinez — zoe@laprovidence.fr'
        assert '/groups/' in rows[2]['url'] and 'search=PC-MARTIN' in rows[3]['url'] and 'ou=' in rows[4]['url']

    def test_saisie_echappee_et_requete_courte(self, client, monkeypatch):
        import routes.api as api
        conn = Conn()
        monkeypatch.setattr(api, 'get_ad_connection', lambda *a, **k: (conn, None))
        assert client.get('/api/quick-search?q=a').get_json() == [] and not conn.filters
        client.get('/api/quick-search?q=' + 'a)(objectClass=*')
        assert '(objectClass=*))' not in conn.filters[0].split('cn=*')[1].split('*)')[0]
        assert '\\28' in conn.filters[0] and '\\2a' in conn.filters[0]

    def test_annuaire_injoignable_ne_casse_rien(self, client, monkeypatch):
        import routes.api as api
        monkeypatch.setattr(api, 'get_ad_connection', lambda *a, **k: (Conn(boom=True), None))
        r = client.get('/api/quick-search?q=martin')
        assert r.status_code == 200 and r.get_json() == []

    def test_barre_presente_sur_les_pages(self, client):
        html = client.get('/tools/favorites').get_data(as_text=True)
        assert 'id="quick-search"' in html and '/api/quick-search' in html and 'js/ux.js' in html


class TestFicheGroupe:
    G = f'CN=GG_Profs,OU=Groupes,{BASE}'
    U = f'CN=Alice Martin,OU=Profs,{BASE}'
    SUB = f'CN=GG_Maths,OU=Groupes,{BASE}'
    PC = f'CN=PC-01,OU=Postes,{BASE}'

    def _conn(self):
        return Conn(by_dn={
            self.G: _E(self.G, cn='GG_Profs', description='Enseignants', member=[self.U, self.SUB, self.PC],
                       memberOf=[f'CN=DL_Partage_RW,OU=Groupes,{BASE}']),
            self.U: _E(self.U, cn='Alice Martin', sAMAccountName='amartin', objectClass=['top', 'person', 'user']),
            self.SUB: _E(self.SUB, cn='GG_Maths', sAMAccountName='GG_Maths', objectClass=['top', 'group']),
            self.PC: _E(self.PC, cn='PC-01', sAMAccountName='PC-01$', objectClass=['top', 'user', 'computer']),
        })

    def test_membres_identifiant_et_imbrication(self, client, monkeypatch):
        import routes.groups as rg
        monkeypatch.setattr(rg, 'get_ad_connection', lambda *a, **k: (self._conn(), None))
        html = client.get(f'/groups/{self.G}').get_data(as_text=True)
        assert 'amartin' in html and 'Ordinateur' in html            # identifiant affiché, poste reconnu
        assert 'dont <strong>1</strong> groupe(s) imbriqué(s)' in html
        assert 'DL_Partage_RW' in html and 'Membre de' in html and '☆ Favori' in html
        assert html.index('GG_Maths') < html.index('Alice Martin')    # les groupes imbriqués d'abord

    def test_ancien_lien_imbrication(self, client):
        r = client.get(f'/groups/{self.G}/nested')
        assert r.status_code == 302 and r.headers['Location'].endswith('#imbrication')
        with client.session_transaction() as s:
            assert not s.get('_flashes')                              # plus de message « version complète »


class TestModelesALaCreation:
    def test_modele_propose(self, client, monkeypatch, tmp_path):
        import core.user_templates as ut
        import routes.users.create as rc
        monkeypatch.setattr(ut, 'TEMPLATES_FILE', tmp_path / 't.json')
        ut.create_template('Enseignant', '', {'department': 'Pédagogie', 'title': 'Professeur', 'description': ''})
        monkeypatch.setattr(rc, 'get_ad_connection', lambda *a, **k: (Conn(), None))
        html = client.get('/users/create').get_data(as_text=True)
        assert 'id="user_template"' in html and 'data-department="Pédagogie"' in html and 'data-title="Professeur"' in html

    def test_sans_modele_une_astuce(self, client, monkeypatch, tmp_path):
        import core.user_templates as ut
        import routes.users.create as rc
        monkeypatch.setattr(ut, 'TEMPLATES_FILE', tmp_path / 'vide.json')
        monkeypatch.setattr(rc, 'get_ad_connection', lambda *a, **k: (Conn(), None))
        html = client.get('/users/create').get_data(as_text=True)
        assert 'id="user_template"' not in html and '/tools/templates' in html


class TestMiseEnPage:
    def test_alertes_en_paragraphe(self):
        css = (ROOT / 'static' / 'css' / 'styles.css').read_text(encoding='utf-8')
        last = css.rindex('\n.alert {')
        assert 'display: block' in css[last:last + 200]              # plus de découpage du texte en colonnes
        assert '.alert-error' in css                                  # classe utilisée par les messages d'erreur

    def test_tableaux_etiquetes_sur_mobile(self):
        js = (ROOT / 'static' / 'js' / 'ux.js').read_text(encoding='utf-8')
        assert "setAttribute('data-label'" in js and 'MutationObserver' in js
        assert 'sidebarSections' in js and 'page-progress' in js

    def test_plus_de_libelles_sans_accents(self):
        for name, banned in (('bitlocker.html', ['Cles de recuperation', 'trouvee']),
                             ('user_templates.html', ['Modeles', 'Creer un modele']),
                             ('ou_form.html', ['Creer', 'unite organisationnelle']),
                             ('group_form.html', ['Creer', 'Etendue']), ('audit.html', ['>Succes<', '>Echec<']),
                             ('reset_password.html', ['Reinitialiser'])):
            html = (ROOT / 'templates' / name).read_text(encoding='utf-8')
            visible = re.sub(r'<script.*?</script>|<style.*?</style>|\{[{%#].*?[}%#]\}', '', html, flags=re.S)
            for word in banned:
                assert word not in visible, (name, word)

    def test_erreur_inattendue_sans_page_500(self, client, monkeypatch):
        import routes.gpo as rg
        from core import gpo as gp

        def boom(*a, **k):
            raise RuntimeError('réponse inattendue')
        monkeypatch.setattr(rg, 'get_ad_connection', lambda *a, **k: (Conn(), None))
        monkeypatch.setattr(rg, '_ous', lambda conn: [])
        monkeypatch.setattr(gp, 'applied_gpos', boom)
        r = client.get(f'/gpo/applied?dn=CN=X,{BASE}')
        assert r.status_code == 200 and 'Lecture des stratégies impossible' in r.get_data(as_text=True)
