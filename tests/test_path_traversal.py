# -*- coding: utf-8 -*-
"""
Traversee de repertoire par les identifiants d'audit et de rapport.

core/audit_history.py construisait HISTORY_DIR / f'{audit_id}.json' avec un
identifiant venu de l'URL (suppression) ou des parametres de requete
(comparaison) : « ../../core/data/settings » lisait ou supprimait n'importe
quel .json de l'application (sous Windows, « ..\\..\\… » passait aussi dans
le segment d'URL). Meme construction pour les rapports d'analyse de logs.
"""
import json
import os

import pytest

os.environ.setdefault('SECRET_KEY', 'test-path-traversal')


@pytest.fixture
def history(tmp_path, monkeypatch):
    import core.audit_history as ah
    hist = tmp_path / 'data' / 'audit_history'
    hist.mkdir(parents=True)
    monkeypatch.setattr(ah, 'HISTORY_DIR', hist)
    victime = tmp_path / 'data' / 'settings.json'
    victime.write_text(json.dumps({'secret': 'ne-doit-pas-fuiter'}), encoding='utf-8')
    (hist / '20260101_120000.json').write_text(json.dumps({'id': '20260101_120000'}), encoding='utf-8')
    return ah, hist, victime


@pytest.mark.parametrize('audit_id', ['../settings', '..\\settings', '../../data/settings',
                                      '20260101_120000/../../settings', 'x' * 400, '', None])
def test_identifiant_invalide_refuse(history, audit_id):
    ah, hist, victime = history
    assert ah.get_audit_by_id(audit_id) is None
    assert ah.delete_audit(audit_id) is False
    assert victime.exists(), "le fichier hors de l'historique ne doit pas etre supprime"


def test_identifiant_valide_fonctionne(history):
    ah, hist, victime = history
    assert ah.get_audit_by_id('20260101_120000') == {'id': '20260101_120000'}
    assert ah.delete_audit('20260101_120000') is True
    assert not (hist / '20260101_120000.json').exists()


@pytest.fixture
def client():
    from app import app
    from core.session_crypto import encrypt_password
    app.config['TESTING'] = True
    c = app.test_client()
    with c.session_transaction() as s:
        s.update(ad_server='dc', ad_username='CORP\\admin', ad_password=encrypt_password('x'),
                 ad_base_dn='DC=corp,DC=local', user_role='admin', user_groups=['Domain Admins'],
                 csrf_token='t' * 64)
    return c


@pytest.mark.parametrize('report_id', ['..%5C..%5Cx', 'x' * 400, '20260101'])
def test_rapport_analyse_identifiant_invalide(client, report_id):
    r = client.get('/api/log-analysis/report/' + report_id)
    assert r.status_code == 400


def test_suppression_audit_identifiant_long_sans_500(client):
    r = client.post('/tools/password-audit/history/' + 'x' * 400 + '/delete',
                    data={'csrf_token': 't' * 64})
    assert r.status_code == 302


# --- Pages de diagnostic et journal d'erreurs : authentification -----------

@pytest.mark.parametrize('url', ['/errors', '/api/diagnostic', '/diagnostic', '/api/errors'])
def test_pages_de_diagnostic_protegees(url):
    """
    /errors et /api/diagnostic repondaient 200 sans aucune session :
    n'importe qui sur le reseau lisait le journal d'erreurs (utilisateurs,
    DN) et la configuration du serveur (chemins, versions, TLS).
    """
    from app import app
    app.config['TESTING'] = True
    r = app.test_client().get(url)
    assert r.status_code in (302, 401), (url, r.status_code)


def test_erreurs_limitees_a_la_fenetre(client, tmp_path, monkeypatch):
    from datetime import datetime, timedelta
    logs = tmp_path / 'logs'
    logs.mkdir()
    vieux = (datetime.now() - timedelta(days=160)).strftime('%Y-%m-%d %H:%M:%S')
    recent = (datetime.now() - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S')
    (logs / 'server.log').write_text(
        f'{vieux},1 ERROR ad_connection: ancienne\n'
        f'{recent},1 INFO app: rien\n'
        f'{recent},2 ERROR app: recente\n', encoding='utf-8')
    monkeypatch.chdir(tmp_path)
    data = client.get('/api/errors').get_json()
    assert data['count'] == 1 and 'recente' in data['errors'][0]
    assert data['older_count'] == 1 and data['last_older'] == vieux
