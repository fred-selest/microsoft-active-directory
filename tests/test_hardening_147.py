# -*- coding: utf-8 -*-
"""
Tests des durcissements de la v1.47.0 (issus de AUDIT_2026-07-20.md).
Ne dépendent d'aucun contexte Flask ni d'aucune connexion AD.
"""
import os
from pathlib import Path

from core import security
from core.path_security import is_safe_path


# --- É4 : comparaison CSRF à temps constant --------------------------------

def test_csrf_compare_est_constante(monkeypatch):
    monkeypatch.setattr(security, 'session', {'csrf_token': 'abc123'}, raising=False)
    assert security.validate_csrf_token('abc123') is True
    assert security.validate_csrf_token('mauvais') is False
    assert security.validate_csrf_token('') in (False, '')  # falsy
    assert security.validate_csrf_token(None) in (False, None)


def test_csrf_refuse_si_pas_de_token_en_session(monkeypatch):
    monkeypatch.setattr(security, 'session', {}, raising=False)
    assert security.validate_csrf_token('quelconque') is False


# --- M8 : get_rate_limit_status honore ses paramètres ----------------------

def test_rate_limit_status_utilise_les_parametres():
    st = security.get_rate_limit_status('10.0.0.1', max_attempts=20, window_seconds=60)
    assert st['max_attempts'] == 20
    assert st['limited'] is False


# --- M3 : path traversal par comparaison hiérarchique ----------------------

def test_is_safe_path_rejette_le_frere_de_repertoire(tmp_path):
    base = tmp_path / 'app'
    base.mkdir()
    sibling = tmp_path / 'app-evil'
    sibling.mkdir()
    assert is_safe_path(base, sibling / 'x') is False


def test_is_safe_path_accepte_un_sous_chemin(tmp_path):
    base = tmp_path / 'app'
    (base / 'sub').mkdir(parents=True)
    assert is_safe_path(base, base / 'sub' / 'f.txt') is True


def test_is_safe_path_rejette_traversal(tmp_path):
    base = tmp_path / 'app'
    base.mkdir()
    assert is_safe_path(base, base / '..' / 'etc' / 'passwd') is False


# --- M4 : neutralisation du CSS personnalisé (anti-XSS) --------------------

def test_sanitize_css_neutralise_la_sortie_de_balise():
    out = security.sanitize_css('</style><script>alert(1)</script>body{color:red}')
    assert '<' not in out and '>' not in out
    assert 'script' in out          # le texte reste, inerte
    assert 'body{color:red}' in out  # le CSS legitime est preserve


def test_sanitize_css_retire_vecteurs_herites():
    assert 'javascript:' not in security.sanitize_css('a{x:JavaScript:alert(1)}').lower()
    assert 'expression(' not in security.sanitize_css('a{width:expression(alert(1))}').lower()


def test_sanitize_css_vide():
    assert security.sanitize_css('') == ''
    assert security.sanitize_css(None) == ''


# --- C3 : la validation TLS est opt-in et non-breaking ---------------------

def test_tls_defaut_non_bloquant(monkeypatch):
    """Sans AD_TLS_VERIFY, le comportement historique (CERT_NONE) est conservé
    pour ne pas casser les DC à certificat auto-signé."""
    import ssl
    import importlib
    monkeypatch.delenv('AD_TLS_VERIFY', raising=False)
    import routes.core as core
    importlib.reload(core)
    assert core._tls_config.validate == ssl.CERT_NONE


def test_tls_opt_in_active_la_verification(monkeypatch):
    import ssl
    import importlib
    monkeypatch.setenv('AD_TLS_VERIFY', 'true')
    import routes.core as core
    importlib.reload(core)
    assert core._tls_config.validate == ssl.CERT_REQUIRED
    # nettoyage : recharger en mode défaut pour ne pas polluer les autres tests
    monkeypatch.delenv('AD_TLS_VERIFY', raising=False)
    importlib.reload(core)
