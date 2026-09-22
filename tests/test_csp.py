# -*- coding: utf-8 -*-
"""
Content Security Policy stricte (constat M9 de AUDIT_2026-07-20.md).

La politique n'autorise que les scripts servis par l'application ou portant
le nonce de la requete : tout script injecte (XSS) est bloque. En presence
d'un nonce, 'unsafe-inline' est ignore par le navigateur — les gestionnaires
on*="..." ne s'executent plus, d'ou la delegation de static/js/actions.js.
"""
import os
import re
from pathlib import Path

import pytest

os.environ.setdefault('SECRET_KEY', 'test-csp')

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def client():
    from app import app
    app.config['TESTING'] = True
    return app.test_client()


def _script_src(csp):
    return next(d for d in csp.split('; ') if d.startswith('script-src'))


def test_strict_par_defaut(client, monkeypatch):
    monkeypatch.delenv('CSP_MODE', raising=False)
    r = client.get('/connect')
    csp = r.headers['Content-Security-Policy']
    src = _script_src(csp)
    assert "'unsafe-inline'" not in src
    assert re.search(r"'nonce-[A-Za-z0-9_-]{20,}'", src)
    assert 'https:' not in csp and 'cdn.' not in csp
    assert "object-src 'none'" in csp and "base-uri 'self'" in csp


def test_nonce_de_len_tete_porte_par_les_scripts(client, monkeypatch):
    monkeypatch.setenv('CSP_MODE', 'strict')
    r = client.get('/connect')
    nonce = re.search(r"'nonce-([^']+)'", r.headers['Content-Security-Policy']).group(1)
    html = r.get_data(as_text=True)
    scripts = re.findall(r'<script\b[^>]*>', html)
    assert scripts, "la page doit contenir des scripts"
    for tag in scripts:
        assert f'nonce="{nonce}"' in tag, tag


def test_nonce_change_a_chaque_requete(client, monkeypatch):
    monkeypatch.setenv('CSP_MODE', 'strict')
    n1 = client.get('/connect').headers['Content-Security-Policy']
    n2 = client.get('/connect').headers['Content-Security-Policy']
    assert n1 != n2


def test_mode_report_only(client, monkeypatch):
    monkeypatch.setenv('CSP_MODE', 'report-only')
    r = client.get('/connect')
    assert "'unsafe-inline'" in _script_src(r.headers['Content-Security-Policy'])
    ro = r.headers['Content-Security-Policy-Report-Only']
    assert "'nonce-" in _script_src(ro) and 'report-uri /csp-report' in ro


def test_mode_legacy_et_valeur_invalide(client, monkeypatch):
    monkeypatch.setenv('CSP_MODE', 'legacy')
    r = client.get('/connect')
    assert "'unsafe-inline'" in _script_src(r.headers['Content-Security-Policy'])
    assert 'Content-Security-Policy-Report-Only' not in r.headers
    monkeypatch.setenv('CSP_MODE', 'n-importe-quoi')
    r = client.get('/connect')
    assert "'unsafe-inline'" not in _script_src(r.headers['Content-Security-Policy'])


def test_csp_report_sans_csrf(client):
    r = client.post('/csp-report', data=b'{"csp-report": {"violated-directive": "script-src"}}',
                    content_type='application/csp-report')
    assert r.status_code == 204
    r = client.post('/csp-report', data=b'pas du json', content_type='application/csp-report')
    assert r.status_code == 204


def test_aucune_ressource_externe_dans_les_templates():
    """Plus de CDN : le DC est souvent sans acces Internet, et la CSP les bloque."""
    bad = []
    for p in (ROOT / 'templates').rglob('*.html'):
        for m in re.finditer(r'<(script|link)\b[^>]*(src|href)="https?://', p.read_text(encoding='utf-8')):
            bad.append(f"{p.relative_to(ROOT)}: {m.group(0)}")
    assert bad == []


def test_toutes_les_balises_script_ont_le_nonce():
    bad = []
    for p in (ROOT / 'templates').rglob('*.html'):
        for tag in re.findall(r'<script\b[^>]*>', p.read_text(encoding='utf-8')):
            if 'nonce="{{ csp_nonce() }}"' not in tag:
                bad.append(f"{p.relative_to(ROOT)}: {tag}")
    assert bad == []


def test_extra_js_et_extra_css_jamais_imbriques():
    """
    {% block extra_js %} imbrique dans {% block content %} etait rendu deux
    fois (contenu + emplacement de base.html) : scripts executes en double,
    et « Identifier already declared » sur group_details (const redeclare).
    Meme chose pour extra_css : feuille dupliquee dans le <body>, qui
    reprenait la priorite sur les styles de base.html et de la barre
    superieure.
    """
    bad = []
    for p in (ROOT / 'templates').rglob('*.html'):
        stack = []
        for m in re.finditer(r"{%-?\s*(?:block\s+(\w+)|endblock)\b", p.read_text(encoding='utf-8')):
            if m.group(1):
                if m.group(1) in ('extra_js', 'extra_css') and stack:
                    bad.append(f"{p.relative_to(ROOT)}: dans {stack}")
                stack.append(m.group(1))
            elif stack:
                stack.pop()
    assert bad == []


def test_aucun_gestionnaire_inline():
    """Les attributs on*="…" sont bloques par la CSP stricte : data-on* a la place."""
    # Attribut HTML uniquement (espace avant, guillemet apres) : une
    # affectation JS « el.onclick = function… » reste autorisee par la CSP.
    pat = re.compile(r'\son(click|change|submit|input|keyup|keydown|load|error|'
                     r'focus|blur|mouseover|mouseout)\s*=\s*["\']', re.I)
    bad = []
    files = list((ROOT / 'templates').rglob('*.html')) + list((ROOT / 'static' / 'js').glob('*.js'))
    for p in files:
        if p.name == 'actions.js':
            continue
        for i, line in enumerate(p.read_text(encoding='utf-8').splitlines(), 1):
            if pat.search(line):
                bad.append(f"{p.relative_to(ROOT)}:{i}: {line.strip()[:100]}")
    assert bad == []


def test_notes_de_version_echappees(client, monkeypatch):
    """
    Les notes GitHub (Markdown brut) etaient rendues avec |safe : la mention
    litterale « `<style>` » des notes v1.50.3 ouvrait une vraie balise et
    transformait toute la suite de /update en CSS (scripts inoperants).
    """
    import routes.admin_tools as at
    monkeypatch.setattr(at, '_fetch_github_releases', lambda *a, **k: [{
        'version': '9.9.9', 'tag': 'v9.9.9', 'date': '01/01/2026',
        'notes': 'dans un bloc `<style>` puis <script>alert(1)</script>'}])
    from core.session_crypto import encrypt_password
    with client.session_transaction() as sess:
        sess.update(ad_server='dc', ad_username='u', ad_password=encrypt_password('p'),
                    user_role='admin', user_groups=['Domain Admins'])
    r = client.get('/update')
    html = r.get_data(as_text=True)
    assert r.status_code == 200
    assert '&lt;style&gt;' in html and '<script>alert(1)' not in html
