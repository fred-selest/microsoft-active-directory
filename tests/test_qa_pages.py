# -*- coding: utf-8 -*-
"""
Tests de non-régression du passage QA des pages (crashes 500 + interactivité).
Ne dépendent d'aucune connexion AD.
"""
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# --- Crash #3 : /tools/password-audit/report importait la mauvaise fonction ---

def test_generate_auditor_issues_importable():
    """L'import cassé faisait planter la page rapport en 500."""
    from password_audit.report import generate_auditor_issues
    assert callable(generate_auditor_issues)


def test_report_route_importe_depuis_report():
    src = (PROJECT_ROOT / 'routes' / 'tools' / 'password.py').read_text(encoding='utf-8')
    # ne doit plus importer generate_auditor_issues depuis runner
    assert 'from password_audit.runner import run_password_audit, generate_auditor_issues' not in src
    assert 'from password_audit.report import generate_auditor_issues' in src


# --- Crashes #1,#2,#4 : templates rendus sans leur contexte requis ------------

def test_routes_passent_le_contexte_requis():
    src = (PROJECT_ROOT / 'routes' / 'tools' / 'misc.py').read_text(encoding='utf-8')
    # user_templates -> templates=, favorites -> counts=, api-docs -> permissions
    assert "user_templates.html', templates=" in src
    assert 'counts=' in src
    assert "'permissions': get_available_permissions()" in src


# --- Interactivité : les fetch JS de la page historique doivent viser /tools ---

def test_history_fetch_urls_prefixees_tools():
    """Les appels API de password_audit_history.html visaient /api/... au lieu de
    /tools/api/... (blueprint monté sur /tools) → 404 → contenu dynamique cassé."""
    html = (PROJECT_ROOT / 'templates' / 'password_audit_history.html').read_text(encoding='utf-8')
    # aucun fetch vers /api/password-audit ou /password-audit sans prefixe /tools
    bad = re.findall(r"fetch\([`'](/(?:api/password-audit|password-audit/(?:history/|send-email)))", html)
    assert not bad, f"URLs sans prefixe /tools: {bad}"
    # et les bonnes formes sont bien presentes
    assert '/tools/api/password-audit/alerts-summary' in html
    assert '/tools/api/password-audit/history' in html
