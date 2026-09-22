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


def test_mode_strict(client, monkeypatch):
    monkeypatch.setenv('CSP_MODE', 'strict')
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
    assert 'Content-Security-Policy-Report-Only' in r.headers


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
