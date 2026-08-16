# -*- coding: utf-8 -*-
"""
Tests pour le cablage ProxyFix (constat M6, AUDIT_2026-07-20.md) :
TRUSTED_PROXY_HOPS doit rester a 0 par defaut (aucune confiance implicite
dans X-Forwarded-For), et etre honore quand configure explicitement.
"""
import importlib
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _reload_config(monkeypatch, **env):
    for key in ('TRUSTED_PROXIES', 'TRUSTED_PROXY_HOPS'):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv('SECRET_KEY', 'test-secret-key-for-unit-tests')
    import config
    return importlib.reload(config)


class TestTrustedProxyHopsDefault:
    def test_no_env_means_zero_hops(self, monkeypatch):
        """Sans configuration, aucun proxy n'est de confiance (defaut sur)."""
        config = _reload_config(monkeypatch)
        assert config.Config.TRUSTED_PROXY_HOPS == 0
        assert config.Config.TRUSTED_PROXIES == []

    def test_trusted_proxies_list_does_not_set_hop_count(self, monkeypatch):
        """
        TRUSTED_PROXIES est purement documentaire et ne doit PAS piloter le
        nombre de sauts : un meme proxy peut y figurer sous plusieurs
        adresses (IPv4/IPv6/CIDR), et en deduire les sauts ferait confiance a
        des X-Forwarded-For inexistants — usurpation d'IP possible.
        """
        config = _reload_config(monkeypatch, TRUSTED_PROXIES='127.0.0.1,::1,10.0.0.0/8')
        assert config.Config.TRUSTED_PROXIES == ['127.0.0.1', '::1', '10.0.0.0/8']
        assert config.Config.TRUSTED_PROXY_HOPS == 0

    def test_explicit_hops_is_the_only_switch(self, monkeypatch):
        """TRUSTED_PROXY_HOPS seul active ProxyFix."""
        config = _reload_config(monkeypatch, TRUSTED_PROXY_HOPS='1')
        assert config.Config.TRUSTED_PROXY_HOPS == 1

    def test_hops_wins_over_proxies_list_length(self, monkeypatch):
        """Les deux variables renseignees : seul TRUSTED_PROXY_HOPS compte."""
        config = _reload_config(monkeypatch,
                                TRUSTED_PROXIES='127.0.0.1,::1,10.0.0.0/8',
                                TRUSTED_PROXY_HOPS='1')
        assert config.Config.TRUSTED_PROXY_HOPS == 1

    def test_invalid_hops_falls_back_to_zero(self, monkeypatch):
        """Une valeur non numerique ne doit pas empecher l'app de demarrer."""
        config = _reload_config(monkeypatch, TRUSTED_PROXY_HOPS='oui')
        assert config.Config.TRUSTED_PROXY_HOPS == 0

    def test_negative_hops_clamped_to_zero(self, monkeypatch):
        config = _reload_config(monkeypatch, TRUSTED_PROXY_HOPS='-3')
        assert config.Config.TRUSTED_PROXY_HOPS == 0


_CHECK_SCRIPT = textwrap.dedent("""
    from app import app
    from werkzeug.middleware.proxy_fix import ProxyFix
    print(isinstance(app.wsgi_app, ProxyFix))
""")


def _wsgi_app_is_proxyfix(env_overrides):
    """
    Verifie le cablage reel dans un sous-processus frais (import de app.py
    a l'etat neuf) plutot qu'un reload en-process, pour ne pas faire fuiter
    les effets de bord du module app (watchdog, cache updates...) sur le
    reste de la suite.
    """
    import os
    env = dict(os.environ)
    env.pop('TRUSTED_PROXIES', None)
    env.pop('TRUSTED_PROXY_HOPS', None)
    env['SECRET_KEY'] = 'test-secret-key-for-unit-tests'
    env.update(env_overrides)

    result = subprocess.run(
        [sys.executable, '-c', _CHECK_SCRIPT],
        cwd=str(REPO_ROOT),
        env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip() == 'True'


class TestProxyFixWiring:
    def test_disabled_by_default(self):
        """app.wsgi_app n'est pas enveloppe par ProxyFix sans configuration."""
        assert _wsgi_app_is_proxyfix({}) is False

    def test_enabled_when_hops_configured(self):
        """app.wsgi_app est enveloppe par ProxyFix quand des sauts sont configures."""
        assert _wsgi_app_is_proxyfix({'TRUSTED_PROXY_HOPS': '1'}) is True

    def test_trusted_proxies_alone_does_not_enable(self):
        """
        TRUSTED_PROXIES seul ne doit PAS activer ProxyFix : sans nombre de
        sauts declare explicitement, on ne fait confiance a aucun
        X-Forwarded-For (cf. TestTrustedProxyHopsDefault).
        """
        assert _wsgi_app_is_proxyfix({'TRUSTED_PROXIES': '127.0.0.1,10.0.0.5'}) is False
