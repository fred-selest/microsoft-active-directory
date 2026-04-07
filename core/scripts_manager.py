# -*- coding: utf-8 -*-
"""
Gestion des scripts PowerShell - Exécution et téléchargement
Permet d'exécuter les scripts de correction depuis l'interface web.
"""
import subprocess
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Liste des scripts disponibles avec métadonnées
AVAILABLE_SCRIPTS = {
    'fix_md4_final.ps1': {
        'name': 'Correctif MD4/NTLM',
        'description': 'Active le support MD4 pour NTLM sur Python 3.12+',
        'severity': 'critical',
        'requires_admin': True,
        'requires_restart': True,
        'timeout': 60,
        'category': 'system'
    },
    'fix_md4.ps1': {
        'name': 'Correctif MD4 (simple)',
        'description': 'Version légère du correctif MD4',
        'severity': 'critical',
        'requires_admin': True,
        'requires_restart': True,
        'timeout': 30,
        'category': 'system'
    },
    'fix_ntlm.ps1': {
        'name': 'Configuration NTLM',
        'description': 'Configure le niveau d\'authentification NTLMv2',
        'severity': 'high',
        'requires_admin': True,
        'requires_restart': False,
        'timeout': 60,
        'category': 'security'
    },
    'fix_ldap_signing.ps1': {
        'name': 'LDAP Signing',
        'description': 'Configure la signature LDAP requise',
        'severity': 'high',
        'requires_admin': True,
        'requires_restart': False,
        'timeout': 60,
        'category': 'security'
    },
    'fix_channel_binding.ps1': {
        'name': 'Channel Binding Tokens',
        'description': 'Configure les CBT pour l\'authentification',
        'severity': 'medium',
        'requires_admin': True,
        'requires_restart': False,
        'timeout': 60,
        'category': 'security'
    },
    'fix_smbv1.ps1': {
        'name': 'Désactiver SMBv1',
        'description': 'Désactive SMBv1 (faille de sécurité critique)',
        'severity': 'critical',
        'requires_admin': True,
        'requires_restart': True,
        'timeout': 120,
        'category': 'security'
    },
    'install_ad.ps1': {
        'name': 'Installation AD',
        'description': 'Installe l\'application sur un contrôleur de domaine',
        'severity': 'info',
        'requires_admin': True,
        'requires_restart': True,
        'timeout': 300,
        'category': 'installation'
    },
    'configure_service.ps1': {
        'name': 'Configuration du service',
        'description': 'Configure le service Windows AD Web Interface',
        'severity': 'info',
        'requires_admin': True,
        'requires_restart': True,
        'timeout': 120,
        'category': 'installation'
    },
    'laps_management.ps1': {
        'name': 'Gestion LAPS',
        'description': 'Installe et configure LAPS',
        'severity': 'info',
        'requires_admin': True,
        'requires_restart': False,
        'timeout': 180,
        'category': 'features'
    }
}

# Historique des exécutions (en mémoire)
execution_history = []


def get_scripts_directory() -> Path:
    """Obtenir le répertoire des scripts."""
    return Path(__file__).parent.parent / 'scripts'


def get_script_path(script_name: str) -> Optional[Path]:
    """Obtenir le chemin complet d'un script."""
    scripts_dir = get_scripts_directory()
    script_path = scripts_dir / script_name
    
    if script_path.exists():
        return script_path
    return None


def list_available_scripts(category: Optional[str] = None) -> list:
    """
    Lister les scripts disponibles.
    
    Args:
        category: Filtrer par catégorie (system, security, installation, features)
    
    Returns:
        list: Liste des scripts avec métadonnées
    """
    scripts = []
    scripts_dir = get_scripts_directory()
    
    for script_name, metadata in AVAILABLE_SCRIPTS.items():
        script_path = scripts_dir / script_name
        exists = script_path.exists()
        
        if category and metadata.get('category') != category:
            continue
        
        scripts.append({
            'name': script_name,
            'display_name': metadata['name'],
            'description': metadata['description'],
            'severity': metadata['severity'],
            'requires_admin': metadata['requires_admin'],
            'requires_restart': metadata['requires_restart'],
            'timeout': metadata['timeout'],
            'category': metadata.get('category', 'other'),
            'exists': exists,
            'file_size': script_path.stat().st_size if exists else 0
        })
    
    return scripts


def execute_script(
    script_name: str,
    arguments: Optional[list] = None,
    timeout: Optional[int] = None,
    run_as_admin: bool = False
) -> Dict[str, Any]:
    """
    Exécuter un script PowerShell.
    
    Args:
        script_name: Nom du script (ex: fix_md4.ps1)
        arguments: Arguments à passer au script
        timeout: Timeout en secondes (défaut: depuis métadonnées)
        run_as_admin: Exécuter en administrateur
    
    Returns:
        dict: Résultat de l'exécution
    """
    result = {
        'success': False,
        'script': script_name,
        'stdout': '',
        'stderr': '',
        'returncode': -1,
        'error': None,
        'execution_time': 0,
        'timestamp': datetime.now().isoformat()
    }
    
    # Vérifier que le script existe
    script_path = get_script_path(script_name)
    if not script_path:
        result['error'] = f'Script introuvable: {script_name}'
        return result
    
    # Obtenir le timeout depuis les métadonnées si non spécifié
    if timeout is None:
        timeout = AVAILABLE_SCRIPTS.get(script_name, {}).get('timeout', 60)
    
    # Construire la commande PowerShell
    ps_args = ['-ExecutionPolicy', 'Bypass', '-File', str(script_path)]
    if arguments:
        ps_args.extend(arguments)
    
    start_time = datetime.now()
    
    try:
        logger.info(f"Exécution du script: {script_name}")
        logger.debug(f"Commande: powershell.exe {' '.join(ps_args)}")
        
        proc = subprocess.Popen(
            ['powershell.exe'] + ps_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
        )
        
        stdout, stderr = proc.communicate(timeout=timeout)
        
        result['stdout'] = stdout
        result['stderr'] = stderr
        result['returncode'] = proc.returncode
        result['success'] = proc.returncode == 0
        result['execution_time'] = (datetime.now() - start_time).total_seconds()
        
        if not result['success']:
            if stderr:
                result['error'] = stderr[:500]  # Limiter la taille
            elif stdout:
                # Parfois l'erreur est dans stdout
                if 'ERROR' in stdout.upper() or 'Exception' in stdout:
                    result['error'] = stdout[:500]
        
        logger.info(f"Script terminé: {script_name} - {'Succès' if result['success'] else 'Échec'}")
        
    except subprocess.TimeoutExpired:
        proc.kill()
        result['error'] = f'Timeout après {timeout} secondes'
        logger.error(f"Timeout script: {script_name}")
        
    except Exception as e:
        result['error'] = str(e)
        logger.error(f"Erreur exécution script: {script_name} - {e}", exc_info=True)
    
    # Ajouter à l'historique
    execution_history.append({
        'script': script_name,
        'success': result['success'],
        'timestamp': result['timestamp'],
        'execution_time': result['execution_time'],
        'error': result['error']
    })
    
    # Garder seulement les 100 dernières exécutions
    if len(execution_history) > 100:
        execution_history.pop(0)
    
    return result


def get_execution_history(limit: int = 20) -> list:
    """
    Obtenir l'historique des exécutions.
    
    Args:
        limit: Nombre maximum d'entrées à retourner
    
    Returns:
        list: Historique des exécutions
    """
    return execution_history[-limit:]


def clear_execution_history():
    """Vider l'historique des exécutions."""
    execution_history.clear()


def check_script_prerequisites(script_name: str) -> Dict[str, Any]:
    """
    Vérifier les prérequis pour l'exécution d'un script.
    
    Args:
        script_name: Nom du script
    
    Returns:
        dict: État des prérequis
    """
    result = {
        'ready': True,
        'checks': [],
        'warnings': [],
        'errors': []
    }
    
    # Vérifier que le script existe
    script_path = get_script_path(script_name)
    if not script_path:
        result['ready'] = False
        result['errors'].append(f'Script introuvable: {script_name}')
        return result
    
    # Vérifier les droits administrateur si requis
    metadata = AVAILABLE_SCRIPTS.get(script_name, {})
    if metadata.get('requires_admin'):
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                result['warnings'].append(
                    'Ce script nécessite des droits administrateur. '
                    'Exécutez-le manuellement depuis PowerShell en mode administrateur.'
                )
        except Exception:
            # Pas sur Windows ou erreur
            result['warnings'].append('Vérification des droits admin impossible')
    
    # Vérifier PowerShell
    try:
        proc = subprocess.Popen(
            ['powershell.exe', '-Command', '$PSVersionTable.PSVersion.Major'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, _ = proc.communicate(timeout=10)
        ps_version = stdout.strip()
        if ps_version.isdigit() and int(ps_version) >= 5:
            result['checks'].append(f'PowerShell version: {ps_version}')
        else:
            result['warnings'].append(f'PowerShell version: {ps_version} (minimum recommandé: 5)')
    except Exception as e:
        result['errors'].append(f'PowerShell non disponible: {e}')
        result['ready'] = False
    
    return result


def download_script(script_name: str) -> Optional[bytes]:
    """
    Télécharger le contenu d'un script.
    
    Args:
        script_name: Nom du script
    
    Returns:
        bytes: Contenu du script ou None si introuvable
    """
    script_path = get_script_path(script_name)
    if not script_path:
        return None
    
    try:
        with open(script_path, 'rb') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Erreur lecture script: {script_name} - {e}")
        return None


def get_script_content(script_name: str) -> Optional[str]:
    """
    Obtenir le contenu texte d'un script.
    
    Args:
        script_name: Nom du script
    
    Returns:
        str: Contenu du script ou None si introuvable
    """
    script_path = get_script_path(script_name)
    if not script_path:
        return None
    
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Erreur lecture script: {script_name} - {e}")
        return None


def parse_script_output(script_name: str, output: str) -> Dict[str, Any]:
    """
    Analyser la sortie d'un script pour extraire des informations structurées.
    
    Args:
        script_name: Nom du script
        output: Sortie du script
    
    Returns:
        dict: Informations extraites
    """
    result = {
        'success': False,
        'messages': [],
        'errors': [],
        'warnings': [],
        'data': {}
    }
    
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Détecter les messages de succès/erreur
        if 'SUCCESS' in line.upper() or 'RÉUSSI' in line.upper():
            result['success'] = True
            result['messages'].append(line)
        elif 'ERROR' in line.upper() or 'ERREUR' in line.upper() or 'Access is denied' in line:
            result['errors'].append(line)
        elif 'WARNING' in line.upper() or 'ATTENTION' in line.upper():
            result['warnings'].append(line)
        else:
            # Essayer d'extraire des données clé:valeur
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    result['data'][key] = value
    
    return result
