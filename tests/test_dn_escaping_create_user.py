# -*- coding: utf-8 -*-
"""
Non-regression : le CN doit etre echappe (RFC 4514) avant d'etre interpole
dans le DN de creation d'un compte.

Constat M2 de AUDIT_2026-07-20.md : un nom legitime contenant une virgule
(« O'Brien, John ») produisait un DN malforme — compte cree au mauvais
endroit, ou creation en echec.
"""
import os
import re
from pathlib import Path

import pytest

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-unit-tests')

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestSanitizeDnComponent:
    def test_comma_is_escaped_not_dropped(self):
        from core.security import sanitize_dn_component
        assert sanitize_dn_component("O'Brien, John") == "O'Brien\\, John"

    def test_plus_and_equals_escaped(self):
        from core.security import sanitize_dn_component
        assert sanitize_dn_component('a+b=c') == 'a\\+b\\=c'

    def test_plain_name_untouched(self):
        from core.security import sanitize_dn_component
        assert sanitize_dn_component('Jean Dupont') == 'Jean Dupont'


class TestCreateUserWiring:
    """
    La fonction doit etre reellement CABLEE dans la construction du DN : elle
    est restee du code mort (aucun appelant) jusqu'a la v1.50.2, ce qui
    rendait sa correction sans effet reel.
    """

    def test_create_user_escapes_cn_in_dn(self):
        src = (PROJECT_ROOT / 'routes' / 'users' / 'create.py').read_text(encoding='utf-8')
        assert 'sanitize_dn_component' in src, \
            "create.py doit importer/utiliser sanitize_dn_component"
        assert re.search(r'user_dn\s*=\s*f"CN=\{sanitize_dn_component\(cn\)\}', src), \
            "Le CN doit etre echappe dans la construction du DN"

    def test_cn_attribute_keeps_literal_value(self):
        """
        L'attribut cn/displayName doit garder la valeur LITTERALE : seul le
        DN est echappe. Sinon le compte s'afficherait avec des backslashes.
        """
        src = (PROJECT_ROOT / 'routes' / 'users' / 'create.py').read_text(encoding='utf-8')
        assert re.search(r"'cn':\s*cn,", src)
        assert re.search(r"'displayName':\s*cn,", src)


class TestUserTemplatesAtomicWrite:
    """save_templates doit ecrire atomiquement (tmp + os.replace)."""

    def test_save_is_atomic(self, tmp_path, monkeypatch):
        import core.user_templates as ut
        monkeypatch.setattr(ut, 'TEMPLATES_FILE', tmp_path / 'user_templates.json')

        ut.save_templates({'a': {'name': 'A'}})
        assert ut.load_templates() == {'a': {'name': 'A'}}
        # aucun fichier temporaire ne doit subsister
        assert list(tmp_path.glob('*.tmp')) == []

    def test_corrupt_file_does_not_crash(self, tmp_path, monkeypatch):
        import core.user_templates as ut
        target = tmp_path / 'user_templates.json'
        monkeypatch.setattr(ut, 'TEMPLATES_FILE', target)
        target.write_text('{ ceci nest pas du json', encoding='utf-8')
        assert ut.load_templates() == {}
