# -*- coding: utf-8 -*-
"""
Pagination des listes (ordinateurs, utilisateurs, groupes).

- Ordinateurs : la route paginait (25 par page) mais le template n'affichait
  ni le total ni les liens de page : au-dela des 25 premiers, les ordinateurs
  etaient inaccessibles, et le compteur affichait « 25 ordinateur(s) ».
- Utilisateurs : les liens de page ne conservaient que la recherche (filtre
  OU/statut perdu des la page 2). Groupes : recherche non encodee dans l'URL.
"""
import os
import re
import urllib.parse

import pytest

os.environ.setdefault('SECRET_KEY', 'test-pagination')


class _A:
    def __init__(self, v):
        self.value = v


class _E:
    def __init__(self, i):
        self.entry_dn = f'CN=PC{i:03d},OU=Paris,DC=corp,DC=local'
        self.cn = _A(f'PC{i:03d}')
        self.description = _A('R&D #1')
        self.operatingSystem = _A('Windows 11' if i % 2 else 'Windows 10')
        self.operatingSystemVersion = _A('')
        self.dNSHostName = _A('')
        self.userAccountControl = _A(4096)


class _Conn:
    entries = []

    def search(self, *a, **k):
        self.entries = []

    def unbind(self):
        pass


@pytest.fixture
def client(monkeypatch):
    import routes.computers as rc
    from app import app
    from core.session_crypto import encrypt_password
    monkeypatch.setattr(rc, 'get_ad_connection', lambda *a, **k: (_Conn(), None))
    monkeypatch.setattr(rc, 'paged_search', lambda *a, **k: [_E(i) for i in range(60)])
    app.config['TESTING'] = True
    c = app.test_client()
    with c.session_transaction() as s:
        s.update(ad_server='dc', ad_username='CORP\\admin', ad_password=encrypt_password('x'),
                 ad_base_dn='DC=corp,DC=local', user_role='admin', user_groups=['Domain Admins'])
    return c


def _liens(html):
    return [urllib.parse.unquote_plus(h.replace('&amp;', '&'))
            for h in re.findall(r'<a href="([^"]*(?:\?|&amp;|&)page=\d+[^"]*)"', html)]


def test_ordinateurs_total_et_liens_de_page(client):
    h = client.get('/computers/').get_data(as_text=True)
    assert '60 ordinateur(s)' in h and 'page 1/3' in h
    assert h.count('class="computer-checkbox"') == 25
    assert '/computers/?page=3' in _liens(h)


def test_ordinateurs_derniere_page_accessible(client):
    h = client.get('/computers/?page=3').get_data(as_text=True)
    assert h.count('class="computer-checkbox"') == 10


def test_filtre_conserve_entre_les_pages(client):
    h = client.get('/computers/?os=Windows+11').get_data(as_text=True)
    assert any('os=Windows 11' in l and 'page=2' in l for l in _liens(h))


def test_recherche_encodee_dans_les_liens(client):
    h = client.get('/computers/?search=R%26D+%231').get_data(as_text=True)
    bruts = re.findall(r'<a href="([^"]*(?:\?|&amp;|&)page=\d+[^"]*)"', h)
    assert bruts and all('R%26D' in b and '%231' in b for b in bruts)


@pytest.mark.parametrize('page,attendu', [('0', 'page 1/3'), ('-4', 'page 1/3'), ('99', 'page 3/3')])
def test_numero_de_page_borne(client, page, attendu):
    assert attendu in client.get('/computers/?page=' + page).get_data(as_text=True)


def test_listes_utilisent_la_pagination_commune():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / 'templates'
    for t in ('users.html', 'groups.html', 'computers.html'):
        assert "{% include 'partials/_pagination.html' %}" in (root / t).read_text(encoding='utf-8'), t
