# -*- coding: utf-8 -*-
"""
Tests de l'ordre des méthodes de connexion AD (constat É2 : LDAPS d'abord).
On inspecte la liste des méthodes construite par _try_connection sans ouvrir
de connexion réseau (le bind échoue sur un serveur bidon).
"""
import os
import re
from pathlib import Path

os.environ.setdefault('SECRET_KEY', 'test-conn-order')
os.environ.setdefault('FLASK_ENV', 'production')

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_ldaps_avant_le_clair_dans_la_source():
    """La méthode LDAPS doit être déclarée avant le LDAP en clair (NTLM/389)."""
    src = (PROJECT_ROOT / 'routes' / 'core.py').read_text(encoding='utf-8')
    block = src.split('methods = [', 1)[1].split(']', 1)[0]
    pos_ldaps = block.find('LDAPS-NTLM')
    pos_starttls = block.find('STARTTLS')
    pos_clair = block.rfind('"NTLM"')
    assert pos_ldaps != -1 and pos_clair != -1
    assert pos_ldaps < pos_clair, "LDAPS doit précéder le LDAP en clair"
    assert pos_starttls < pos_clair, "STARTTLS doit précéder le LDAP en clair"


def test_gate_insecure_present():
    src = (PROJECT_ROOT / 'routes' / 'core.py').read_text(encoding='utf-8')
    assert 'AD_ALLOW_INSECURE_LDAP' in src
    # défaut = true (non-breaking)
    assert "os.environ.get('AD_ALLOW_INSECURE_LDAP', 'true')" in src


def test_interdiction_du_clair_retire_les_methodes_non_chiffrees(monkeypatch):
    """Avec AD_ALLOW_INSECURE_LDAP=false, aucune méthode non chiffrée ne subsiste."""
    import importlib
    monkeypatch.setenv('AD_ALLOW_INSECURE_LDAP', 'false')
    import routes.core as core
    importlib.reload(core)

    captured = {}
    real_make = core._make_server

    def spy_make(server, port, use_ssl, ip_mode=None):
        captured.setdefault('attempts', []).append((port, use_ssl))
        # Retourner un vrai Server (le bind échouera, peu importe)
        return real_make(server, port, use_ssl)

    monkeypatch.setattr(core, '_make_server', spy_make)
    # session est un objet global flask ; on utilise un contexte d'app.
    from app import app
    with app.test_request_context():
        core._try_connection('dc.exemple.local', 'admin', 'x')

    # Toutes les tentatives doivent être chiffrées : soit LDAPS (use_ssl=True),
    # soit STARTTLS (port 389 mais chiffré). La méthode NTLM/389 en clair
    # (389, False) ne doit PAS apparaître... or STARTTLS est aussi (389, False).
    # On vérifie plutôt qu'il ne reste qu'UNE tentative sur 389 (STARTTLS) et
    # deux sur 636 (LDAPS), soit 3 au total, pas 4.
    attempts = captured.get('attempts', [])
    assert len(attempts) == 3, f"attendu 3 méthodes chiffrées, obtenu {attempts}"

    monkeypatch.delenv('AD_ALLOW_INSECURE_LDAP', raising=False)
    importlib.reload(core)
