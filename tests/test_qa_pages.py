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


# --- Menu : un endpoint inconnu ne doit pas faire tomber toutes les pages ---

def test_menu_endpoint_inconnu_ignore(monkeypatch):
    """
    L'entree « Recherche » (endpoint global_search, inexistant) activee depuis
    /admin faisait lever url_for() dans la barre laterale : 500 sur toutes les
    pages, page d'erreur comprise.
    """
    import core.settings_manager as sm
    from app import app
    orig = sm.get_menu_items
    monkeypatch.setattr(sm, 'get_menu_items', lambda: orig() + [
        {'id': 'search', 'label': 'Recherche', 'endpoint': 'global_search',
         'icon': 'x', 'enabled': True, 'order': 6}])
    r = app.test_client().get('/connect')
    assert r.status_code == 200
    assert b'Recherche' not in r.data


def test_tous_les_url_for_litteraux_resolvent():
    """Chaque url_for('...') litteral des routes doit viser un endpoint existant."""
    import re
    from pathlib import Path
    from app import app
    root = Path(__file__).resolve().parent.parent
    bad = []
    for f in list((root / 'routes').rglob('*.py')) + list((root / 'core').rglob('*.py')):
        src = f.read_text(encoding='utf-8', errors='ignore')
        for m in re.finditer(r"url_for\(\s*['\"]([\w.]+)['\"]", src):
            if m.group(1) != 'static' and m.group(1) not in app.view_functions:
                bad.append(f"{f.relative_to(root)}: {m.group(1)}")
    assert bad == []


def test_aucun_template_orphelin():
    """
    Chaque template doit etre rendu (render_template) ou inclus/etendu par un
    autre template. 24 templates morts ont ete supprimes en v1.50.4 : ils
    contenaient des url_for() vers des routes inexistantes, invisibles tant
    que personne ne les rendait.
    """
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    tpl_dir = root / 'templates'
    sources = [p.read_text(encoding='utf-8', errors='ignore')
               for p in list((root / 'routes').rglob('*.py'))
               + list((root / 'core').rglob('*.py'))
               + list((root / 'password_audit').rglob('*.py'))
               + [root / 'app.py']]
    templates = {p.relative_to(tpl_dir).as_posix(): p for p in tpl_dir.rglob('*.html')}
    tpl_sources = {name: p.read_text(encoding='utf-8', errors='ignore')
                   for name, p in templates.items()}
    orphelins = []
    for name in templates:
        pat = re.compile(r"['\"]" + re.escape(name) + r"['\"]")
        if any(pat.search(s) for s in sources):
            continue
        if any(pat.search(s) for other, s in tpl_sources.items() if other != name):
            continue
        orphelins.append(name)
    assert orphelins == []


def test_notes_de_version_sans_balise_html():
    """
    auto-tag.yml publie la section du CHANGELOG de la version courante comme
    notes de release GitHub. Les serveurs encore en version < 1.51.0 affichent
    ces notes SANS echappement sur /update : un texte comme « <style> » y
    ouvrait une vraie balise, rendait toute la suite de la page inerte, et
    le bouton de mise a jour inutilisable — alors que c'est justement le
    moyen de recevoir le correctif. Aucune balise dans les notes publiees.
    """
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    version = (root / 'VERSION').read_text(encoding='utf-8').strip()
    changelog = (root / 'CHANGELOG.md').read_text(encoding='utf-8')
    m = re.search(r'^## \[' + re.escape(version) + r'\].*?(?=^## \[|\Z)', changelog, re.S | re.M)
    assert m, f"Section [{version}] absente du CHANGELOG"
    balises = re.findall(r'<[A-Za-z!/][^>\n]*>?', m.group(0))
    assert balises == [], (
        f"Balises HTML dans les notes de la v{version} : {balises}. "
        "Les decrire sans chevrons (ex. « balise style »).")
