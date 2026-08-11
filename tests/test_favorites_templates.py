# -*- coding: utf-8 -*-
"""
Tests pour les favoris et les modeles utilisateur (routes/tools/misc.py),
implementes dans cette iteration (TODO non fonctionnels auparavant).
"""
import os
import pytest
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-unit-tests')


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Client de test Flask, avec une session connectee (permission
    admin:user_templates mockee, cf. test_scripts_manager.py) et un fichier
    de modeles isole dans un repertoire temporaire (pour ne pas polluer
    data/user_templates.json)."""
    import core.user_templates as user_templates_module
    monkeypatch.setattr(user_templates_module, 'TEMPLATES_FILE', tmp_path / 'user_templates.json')

    from app import app
    app.config['TESTING'] = True

    patcher = patch('routes.core.has_granular_permission', return_value=True)
    patcher.start()

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['ad_server'] = 'test-server'
            sess['ad_base_dn'] = 'DC=test,DC=local'
            sess['ad_username'] = 'admin'
            sess['ad_password'] = 'dummy-password-marker'
            sess['user_groups'] = ['test-group']
            sess['connected'] = True
            sess['csrf_token'] = 'test-csrf-token'
        try:
            yield client
        finally:
            patcher.stop()


class TestFavorites:
    """Tests pour /tools/favorites et /tools/favorites/toggle."""

    def test_favorites_empty_by_default(self, client):
        response = client.get('/tools/favorites')
        assert response.status_code == 200
        assert 'Aucun favori' in response.get_data(as_text=True)

    def test_toggle_favorite_adds(self, client):
        response = client.post('/tools/favorites/toggle', data={
            'csrf_token': 'test-csrf-token',
            'type': 'user',
            'dn': 'CN=Jean Dupont,OU=Users,DC=test,DC=local',
            'name': 'Jean Dupont',
        })
        assert response.status_code == 302

        page = client.get('/tools/favorites').get_data(as_text=True)
        assert 'Jean Dupont' in page

    def test_toggle_favorite_is_idempotent(self, client):
        """Ajouter deux fois le meme DN ne cree pas de doublon."""
        data = {
            'csrf_token': 'test-csrf-token',
            'type': 'group',
            'dn': 'CN=Support,DC=test,DC=local',
            'name': 'Support',
        }
        client.post('/tools/favorites/toggle', data=data)
        client.post('/tools/favorites/toggle', data=data)

        with client.session_transaction() as sess:
            assert len(sess.get('favorites', [])) == 1

    def test_toggle_favorite_removes(self, client):
        add = {
            'csrf_token': 'test-csrf-token',
            'type': 'computer',
            'dn': 'CN=PC01,DC=test,DC=local',
            'name': 'PC01',
        }
        client.post('/tools/favorites/toggle', data=add)

        remove = {'csrf_token': 'test-csrf-token', 'action': 'remove', 'dn': add['dn']}
        client.post('/tools/favorites/toggle', data=remove)

        page = client.get('/tools/favorites').get_data(as_text=True)
        assert 'PC01' not in page
        assert 'Aucun favori' in page

    def test_toggle_favorite_missing_dn_rejected(self, client):
        response = client.post('/tools/favorites/toggle', data={
            'csrf_token': 'test-csrf-token', 'type': 'user', 'dn': '', 'name': 'X',
        })
        assert response.status_code == 302
        with client.session_transaction() as sess:
            assert sess.get('favorites', []) == []


class TestUserTemplates:
    """Tests pour /tools/templates (CRUD)."""

    def test_templates_empty_by_default(self, client):
        response = client.get('/tools/templates')
        assert response.status_code == 200
        assert 'Aucun modele' in response.get_data(as_text=True)

    def test_create_template_persists(self, client):
        response = client.post('/tools/templates/create', data={
            'csrf_token': 'test-csrf-token',
            'name': 'Employe standard',
            'description': 'Modele par defaut',
            'department': 'Informatique',
            'title': 'Developpeur',
            'user_description': 'Compte standard',
        })
        assert response.status_code == 302

        page = client.get('/tools/templates').get_data(as_text=True)
        assert 'Employe standard' in page
        assert 'Informatique' in page

    def test_create_template_requires_name(self, client):
        response = client.post('/tools/templates/create', data={
            'csrf_token': 'test-csrf-token', 'name': '', 'department': 'IT',
        })
        assert response.status_code == 200
        page = client.get('/tools/templates').get_data(as_text=True)
        assert 'Aucun modele' in page

    def test_edit_template_updates_fields(self, client):
        client.post('/tools/templates/create', data={
            'csrf_token': 'test-csrf-token', 'name': 'Original', 'department': 'IT',
        })
        import core.user_templates as user_templates_module
        template_id = next(iter(user_templates_module.load_templates()))

        response = client.post(f'/tools/templates/{template_id}/edit', data={
            'csrf_token': 'test-csrf-token', 'name': 'Modifie', 'department': 'RH',
        })
        assert response.status_code == 302

        page = client.get('/tools/templates').get_data(as_text=True)
        assert 'Modifie' in page
        assert 'Original' not in page

    def test_edit_nonexistent_template_redirects(self, client):
        response = client.get('/tools/templates/does-not-exist/edit')
        assert response.status_code == 302

    def test_delete_template_removes_it(self, client):
        client.post('/tools/templates/create', data={
            'csrf_token': 'test-csrf-token', 'name': 'A supprimer', 'department': 'IT',
        })
        import core.user_templates as user_templates_module
        template_id = next(iter(user_templates_module.load_templates()))

        response = client.post(f'/tools/templates/{template_id}/delete', data={
            'csrf_token': 'test-csrf-token',
        })
        assert response.status_code == 302

        page = client.get('/tools/templates').get_data(as_text=True)
        assert 'A supprimer' not in page
        assert 'Aucun modele' in page
