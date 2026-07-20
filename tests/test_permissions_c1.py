# -*- coding: utf-8 -*-
"""
Tests de non-regression du controle d'acces granulaire.

Reference : AUDIT_2026-07-20.md, constat C1.

La faille corrigee : has_permission() accordait l'acces des qu'il existait une
*intersection* entre les permissions detenues et les permissions requises. Comme
l'alias legacy 'admin' etait traduit en la totalite des permissions, detenir une
seule permission (par ex. 'users:read') suffisait a passer require_permission('admin')
et donc a atteindre l'execution de scripts PowerShell sur le controleur de domaine.

Ces tests echouent si ce comportement reapparait.
"""
import json
import re
from pathlib import Path

import pytest

import core.granular_permissions as gp


PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def support_user(tmp_path, monkeypatch):
    """
    Reproduit la configuration reellement trouvee en production : un groupe
    'equipe support' disposant de permissions de gestion d'utilisateurs, mais
    d'aucune permission d'administration.
    """
    perms_file = tmp_path / 'permissions.json'
    perms_file.write_text(json.dumps({
        'version': '1.0',
        'groups': {
            'Equipe-Support': {
                'description': 'equipe support',
                'subject_type': 'group',
                'enabled': True,
                'permissions': [
                    'users:create', 'users:read', 'users:update', 'users:delete',
                    'groups:read', 'groups:update',
                    'computers:read', 'computers:update',
                    'ous:read', 'ous:update',
                ],
            }
        },
    }), encoding='utf-8')
    monkeypatch.setattr(gp, 'PERMISSIONS_FILE', perms_file)
    return ['Equipe-Support']


@pytest.fixture(autouse=True)
def no_admin_session(monkeypatch):
    """
    Neutralise le filet de securite 'administrateur du domaine' pour que les
    tests mesurent bien les permissions granulaires et non ce fallback.
    """
    monkeypatch.setattr(gp, 'session', {}, raising=False)

    import sys
    import types
    fake_flask = types.ModuleType('flask')
    fake_flask.session = {}
    real_flask = sys.modules.get('flask')
    sys.modules['flask'] = fake_flask
    yield
    if real_flask is not None:
        sys.modules['flask'] = real_flask


# ---------------------------------------------------------------------------
# Le coeur de C1
# ---------------------------------------------------------------------------

def test_permission_detenue_est_accordee(support_user):
    assert gp.has_permission(support_user, 'users:read') is True
    assert gp.has_permission(support_user, 'users:delete') is True


def test_permission_non_detenue_est_refusee(support_user):
    """Le cas exact de la faille : une permission absente doit etre refusee."""
    assert gp.has_permission(support_user, 'system:execute_script') is False
    assert gp.has_permission(support_user, 'admin:settings') is False
    assert gp.has_permission(support_user, 'admin:permissions') is False
    assert gp.has_permission(support_user, 'tools:laps') is False
    assert gp.has_permission(support_user, 'tools:bitlocker') is False


def test_exploit_c1_alias_admin_ne_doit_plus_rien_accorder(support_user):
    """
    Reproduction directe de la faille C1.

    Sur le code vulnerable, cet appel renvoyait True : l'alias 'admin' etait
    traduit en la totalite des permissions, et l'intersection avec les 10
    permissions du groupe support etait non vide. Le groupe 'equipe support'
    obtenait ainsi l'acces aux 64 routes d'administration, dont l'execution
    de PowerShell sur le controleur de domaine.

    Ce test est la sentinelle de la correction : s'il repasse a True, la
    faille est revenue.
    """
    assert gp.has_permission(support_user, 'admin') is False
    assert gp.has_permission(support_user, 'write') is False
    assert gp.has_permission(support_user, 'delete') is False


def test_utilisateur_sans_groupe_est_refuse():
    assert gp.has_permission([], 'users:read') is False
    assert gp.has_permission(None, 'users:read') is False


def test_permission_inconnue_est_refusee(support_user):
    """
    Une permission inexistante (faute de frappe dans un garde de route) doit
    produire un refus, jamais une autorisation silencieuse.
    """
    assert gp.has_permission(support_user, 'users:raed') is False
    assert gp.has_permission(support_user, 'admin') is False
    assert gp.has_permission(support_user, 'write') is False
    assert gp.has_permission(support_user, '') is False


def test_entree_desactivee_n_accorde_rien(tmp_path, monkeypatch):
    perms_file = tmp_path / 'permissions.json'
    perms_file.write_text(json.dumps({
        'groups': {
            'Support': {
                'subject_type': 'group',
                'enabled': False,
                'permissions': ['users:read'],
            }
        }
    }), encoding='utf-8')
    monkeypatch.setattr(gp, 'PERMISSIONS_FILE', perms_file)
    assert gp.has_permission(['Support'], 'users:read') is False


def test_role_predefini_lecture_seule(tmp_path, monkeypatch):
    monkeypatch.setattr(gp, 'PERMISSIONS_FILE', tmp_path / 'absent.json')
    lecteurs = ['Utilisateurs du domaine']
    assert gp.has_permission(lecteurs, 'users:read') is True
    assert gp.has_permission(lecteurs, 'users:delete') is False
    assert gp.has_permission(lecteurs, 'system:execute_script') is False


def test_administrateurs_du_domaine_ont_tout(tmp_path, monkeypatch):
    monkeypatch.setattr(gp, 'PERMISSIONS_FILE', tmp_path / 'absent.json')
    admins = ['Administrateurs du domaine']
    for permission in gp.ALL_PERMISSIONS:
        assert gp.has_permission(admins, permission) is True, permission


# ---------------------------------------------------------------------------
# Garde-fous structurels : empechent la reintroduction du motif fautif
# ---------------------------------------------------------------------------

def test_aucun_alias_legacy_dans_les_gardes():
    """
    Les gardes de routes doivent utiliser des permissions granulaires. Les
    alias larges ('admin', 'write', 'delete') sont ceux qui rendaient C1
    exploitable.
    """
    interdits = {'admin', 'write', 'delete', 'read'}
    fautifs = []

    for path in (PROJECT_ROOT / 'routes').rglob('*.py'):
        for num, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            for match in re.finditer(r"require_permission\('([^']+)'\)", line):
                if match.group(1) in interdits:
                    rel = path.relative_to(PROJECT_ROOT)
                    fautifs.append(f"{rel}:{num} -> '{match.group(1)}'")

    assert not fautifs, (
        "Alias de permission a large perimetre detecte(s) :\n  "
        + "\n  ".join(fautifs)
    )


def test_toutes_les_permissions_des_gardes_existent():
    """
    Un garde referencant une permission absente de ALL_PERMISSIONS refuserait
    tout le monde en silence. Ce test rend l'erreur visible au build.
    """
    inconnues = []

    for path in (PROJECT_ROOT / 'routes').rglob('*.py'):
        for num, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            for match in re.finditer(r"require_permission\('([^']+)'\)", line):
                if match.group(1) not in gp.ALL_PERMISSIONS:
                    rel = path.relative_to(PROJECT_ROOT)
                    inconnues.append(f"{rel}:{num} -> '{match.group(1)}'")

    assert not inconnues, (
        "Permission inconnue dans un garde de route :\n  " + "\n  ".join(inconnues)
    )


def test_mapping_legacy_non_reintroduit():
    assert not hasattr(gp, 'LEGACY_PERMISSION_MAPPING'), (
        "LEGACY_PERMISSION_MAPPING traduisait des alias larges en listes de "
        "permissions et rendait le controle par intersection exploitable (C1)."
    )


def test_execution_powershell_exige_sa_propre_permission():
    """
    L'execution de scripts sur le DC est l'action la plus sensible de
    l'application : elle doit avoir une permission dediee, non impliquee par
    une quelconque permission de gestion courante.
    """
    assert 'system:execute_script' in gp.ALL_PERMISSIONS
    assert 'system:execute_script' in gp.SENSITIVE_PERMISSIONS

    routes_api = (PROJECT_ROOT / 'routes' / 'api.py').read_text(encoding='utf-8')
    execute_route = routes_api.split("@api_bp.route('/scripts/<script_name>/execute'")[1][:400]
    assert "require_permission('system:execute_script')" in execute_route
