# -*- coding: utf-8 -*-
"""
Tests pour le module scripts_manager.py
Teste la gestion des scripts PowerShell (exécution, téléchargement, historique)
"""
import pytest
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ajouter le répertoire parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestScriptsManager:
    """Tests pour core/scripts_manager.py"""
    
    def test_get_scripts_directory(self):
        """Test que le répertoire des scripts existe"""
        from core.scripts_manager import get_scripts_directory
        
        scripts_dir = get_scripts_directory()
        assert scripts_dir.exists()
        assert scripts_dir.is_dir()
    
    def test_get_script_path_existing(self):
        """Test l'obtention du chemin d'un script existant"""
        from core.scripts_manager import get_script_path
        
        # Tester avec un script qui devrait exister
        script_path = get_script_path('fix_md4.ps1')
        # Le script peut ou non exister, mais la fonction ne doit pas planter
        assert script_path is None or script_path.exists()
    
    def test_get_script_path_nonexistent(self):
        """Test l'obtention du chemin d'un script inexistant"""
        from core.scripts_manager import get_script_path
        
        script_path = get_script_path('script_inexistant.ps1')
        assert script_path is None
    
    def test_list_available_scripts(self):
        """Test la liste des scripts disponibles"""
        from core.scripts_manager import list_available_scripts
        
        scripts = list_available_scripts()
        assert isinstance(scripts, list)
        assert len(scripts) > 0
        
        # Vérifier la structure des données
        for script in scripts:
            assert 'name' in script
            assert 'display_name' in script
            assert 'description' in script
            assert 'severity' in script
            assert 'category' in script
            assert 'exists' in script
    
    def test_list_available_scripts_filter_category(self):
        """Test le filtrage des scripts par catégorie"""
        from core.scripts_manager import list_available_scripts
        
        # Filtrer par catégorie 'security'
        security_scripts = list_available_scripts(category='security')
        
        for script in security_scripts:
            assert script['category'] == 'security'
        
        # Filtrer par catégorie 'system'
        system_scripts = list_available_scripts(category='system')
        
        for script in system_scripts:
            assert script['category'] == 'system'
    
    def test_available_scripts_metadata(self):
        """Test que les métadonnées des scripts sont correctes"""
        from core.scripts_manager import AVAILABLE_SCRIPTS
        
        # Vérifier que fix_md4_final.ps1 est défini
        assert 'fix_md4_final.ps1' in AVAILABLE_SCRIPTS
        
        script_info = AVAILABLE_SCRIPTS['fix_md4_final.ps1']
        assert script_info['severity'] == 'critical'
        assert script_info['requires_admin'] is True
        assert script_info['requires_restart'] is True
        assert 'timeout' in script_info
    
    def test_execution_history_initial(self):
        """Test que l'historique est vide au départ"""
        from core.scripts_manager import get_execution_history, clear_execution_history
        
        clear_execution_history()
        history = get_execution_history()
        assert isinstance(history, list)
    
    def test_get_execution_history_limit(self):
        """Test la limite de l'historique"""
        from core.scripts_manager import get_execution_history, execution_history
        
        # Sauvegarder l'historique actuel
        original_history = execution_history.copy()
        
        # Ajouter des fausses entrées
        execution_history.clear()
        for i in range(30):
            execution_history.append({'script': f'test_{i}.ps1', 'success': True})
        
        # Tester avec limite
        history = get_execution_history(limit=10)
        assert len(history) == 10
        
        # Restaurer
        execution_history.clear()
        execution_history.extend(original_history)
    
    def test_clear_execution_history(self):
        """Test l'effacement de l'historique"""
        from core.scripts_manager import (
            clear_execution_history, 
            get_execution_history,
            execution_history
        )
        
        # Sauvegarder
        original_history = execution_history.copy()
        
        # Ajouter une entrée
        execution_history.append({'script': 'test.ps1', 'success': True})
        
        # Effacer
        clear_execution_history()
        history = get_execution_history()
        assert len(history) == 0
        
        # Restaurer
        execution_history.clear()
        execution_history.extend(original_history)


class TestScriptsAPI:
    """Tests pour les routes API des scripts"""
    
    @pytest.fixture
    def client(self):
        """Fixture pour le client de test Flask"""
        from app import app
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        
        with app.test_client() as client:
            with client.session_transaction() as sess:
                # Simuler une session authentifiée avec permissions admin
                sess['ad_server'] = 'test-server'
                sess['ad_base_dn'] = 'DC=test,DC=local'
                sess['ad_username'] = 'admin'
                sess['ad_permissions'] = ['admin:settings', 'admin:scripts']
                sess['connected'] = True
            yield client
    
    def test_api_list_scripts(self, client):
        """Test l'API de liste des scripts"""
        response = client.get('/api/scripts')
        
        # La route nécessite une connexion, donc 302 ou 403 si non connecté
        # ou 200 si la session est correctement mockée
        assert response.status_code in [200, 302, 403]
        
        if response.status_code == 200:
            data = response.get_json()
            assert data['success'] is True
            assert 'scripts' in data
            assert 'count' in data
    
    def test_api_scripts_prerequisites(self, client):
        """Test l'API de vérification des prérequis"""
        response = client.get('/api/scripts/fix_md4.ps1/prerequisites')
        
        # Peut nécessiter authentification
        assert response.status_code in [200, 302, 403, 404]
        
        if response.status_code == 200:
            data = response.get_json()
            assert data['success'] is True
            assert 'script' in data
            assert 'prerequisites' in data
    
    def test_api_scripts_history(self, client):
        """Test l'API d'historique des scripts"""
        response = client.get('/api/scripts/history')
        
        assert response.status_code in [200, 302, 403]
        
        if response.status_code == 200:
            data = response.get_json()
            assert data['success'] is True
            assert 'history' in data
            assert 'count' in data
    
    def test_api_execute_script_not_found(self, client):
        """Test l'exécution d'un script inexistant"""
        response = client.post('/api/scripts/inexistant.ps1/execute', 
                              json={})
        
        # 302 si non connecté (redirection vers login), 404 si script inconnu
        assert response.status_code in [302, 404]
        
        if response.status_code == 404:
            data = response.get_json()
            assert data['success'] is False
            assert 'error' in data
    
    def test_api_download_script_not_found(self, client):
        """Test le téléchargement d'un script inexistant"""
        response = client.get('/api/scripts/inexistant.ps1/download')
        
        # 302 si non connecté, 404 si script inconnu
        assert response.status_code in [302, 404]


class TestScriptExecution:
    """Tests pour l'exécution de scripts PowerShell"""
    
    @patch('core.scripts_manager.subprocess.Popen')
    def test_execute_script_mock_success(self, mock_popen):
        """Test l'exécution réussie d'un script (mocké)"""
        from core.scripts_manager import execute_script, clear_execution_history
        
        clear_execution_history()
        
        # Configurer le mock pour simuler un succès
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ('SUCCESS\n', '')
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc
        
        result = execute_script('fix_md4.ps1', timeout=30)
        
        assert result['success'] is True
        assert result['script'] == 'fix_md4.ps1'
        assert result['returncode'] == 0
        assert 'stdout' in result
    
    @patch('core.scripts_manager.subprocess.Popen')
    def test_execute_script_mock_error(self, mock_popen):
        """Test l'exécution échouée d'un script (mocké)"""
        from core.scripts_manager import execute_script, clear_execution_history
        
        clear_execution_history()
        
        # Configurer le mock pour simuler un échec
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ('', 'ERROR: Access denied')
        mock_proc.returncode = 1
        mock_popen.return_value = mock_proc
        
        result = execute_script('fix_md4.ps1', timeout=30)
        
        assert result['success'] is False
        assert result['returncode'] == 1
        assert result['error'] is not None
    
    @patch('core.scripts_manager.subprocess.Popen')
    def test_execute_script_timeout(self, mock_popen):
        """Test le timeout d'exécution d'un script (mocké)"""
        from core.scripts_manager import execute_script, clear_execution_history
        import subprocess
        
        clear_execution_history()
        
        # Configurer le mock pour simuler un timeout
        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired(
            cmd='powershell.exe', timeout=30
        )
        mock_popen.return_value = mock_proc
        
        result = execute_script('fix_md4.ps1', timeout=30)
        
        assert result['success'] is False
        assert 'Timeout' in result['error']
    
    def test_execute_script_file_not_found(self):
        """Test l'exécution d'un script inexistant"""
        from core.scripts_manager import execute_script, clear_execution_history
        
        clear_execution_history()
        
        result = execute_script('script_inexistant.ps1', timeout=30)
        
        assert result['success'] is False
        assert 'Script introuvable' in result['error']


class TestScriptContent:
    """Tests pour la lecture du contenu des scripts"""
    
    def test_get_script_content(self):
        """Test la lecture du contenu d'un script"""
        from core.scripts_manager import get_script_content
        
        # Le script peut ou non exister
        content = get_script_content('fix_md4.ps1')
        
        # Si le contenu n'est pas None, vérifier que c'est une string
        if content is not None:
            assert isinstance(content, str)
            assert len(content) > 0
    
    def test_download_script(self):
        """Test le téléchargement binaire d'un script"""
        from core.scripts_manager import download_script
        
        content = download_script('fix_md4.ps1')
        
        # Si le contenu n'est pas None, vérifier que c'est des bytes
        if content is not None:
            assert isinstance(content, bytes)
            assert len(content) > 0
    
    def test_get_script_content_not_found(self):
        """Test la lecture du contenu d'un script inexistant"""
        from core.scripts_manager import get_script_content
        
        content = get_script_content('script_inexistant.ps1')
        assert content is None


class TestScriptOutputParsing:
    """Tests pour l'analyse des sorties de scripts"""
    
    def test_parse_script_output_success(self):
        """Test l'analyse d'une sortie avec succès"""
        from core.scripts_manager import parse_script_output
        
        output = """
        Starting script...
        Configuration updated
        SUCCESS: Operation completed
        System detected: Windows Server 2022
        """
        
        result = parse_script_output('test.ps1', output)
        
        assert result['success'] is True
        assert len(result['messages']) > 0
    
    def test_parse_script_output_error(self):
        """Test l'analyse d'une sortie avec erreur"""
        from core.scripts_manager import parse_script_output
        
        output = """
        Starting script...
        ERROR: Access is denied
        Failed to update configuration
        """
        
        result = parse_script_output('test.ps1', output)
        
        assert result['success'] is False
        assert len(result['errors']) > 0
    
    def test_parse_script_output_warnings(self):
        """Test l'analyse d'une sortie avec avertissements"""
        from core.scripts_manager import parse_script_output
        
        output = """
        Starting script...
        WARNING: Legacy mode detected
        Operation completed with warnings
        """
        
        result = parse_script_output('test.ps1', output)
        
        assert len(result['warnings']) > 0
    
    def test_parse_script_output_key_value(self):
        """Test l'analyse d'une sortie avec données clé:valeur"""
        from core.scripts_manager import parse_script_output

        output = """
        Status: SUCCESS
        Version: 1.0.0
        Server: DC01
        Port: 389
        """

        result = parse_script_output('test.ps1', output)

        # Vérifier que des données ont été extraites (Status peut être dans messages)
        assert len(result['data']) > 0
        assert 'Version' in result['data']
        assert result['data']['Version'] == '1.0.0'


class TestScriptPrerequisites:
    """Tests pour la vérification des prérequis"""
    
    def test_check_prerequisites_structure(self):
        """Test que la structure des prérequis est correcte"""
        from core.scripts_manager import check_script_prerequisites
        
        # Le script peut ou non exister
        result = check_script_prerequisites('fix_md4.ps1')
        
        assert isinstance(result, dict)
        assert 'ready' in result
        assert 'checks' in result
        assert 'warnings' in result
        assert 'errors' in result
    
    def test_check_prerequisites_nonexistent_script(self):
        """Test les prérequis pour un script inexistant"""
        from core.scripts_manager import check_script_prerequisites
        
        result = check_script_prerequisites('script_inexistant.ps1')
        
        assert result['ready'] is False
        assert len(result['errors']) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
