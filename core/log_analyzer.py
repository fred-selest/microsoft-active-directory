# -*- coding: utf-8 -*-
"""
Analyseur Automatique de Logs - Post-Redémarrage
Détecte les problèmes et propose/exécute des actions correctives.
"""
import os
import re
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Patterns de détection d'erreurs critiques
ERROR_PATTERNS = {
    'ldap_connection': {
        'pattern': r'(LDAP|ldaps?|connexion AD).*(erreur|error|échec|failed|timeout)',
        'severity': 'critical',
        'action': 'check_ldap_config',
        'description': 'Problème de connexion LDAP détecté'
    },
    'authentication': {
        'pattern': r'(authentification|auth|login).*(échec|failed|invalide|invalid)',
        'severity': 'high',
        'action': 'check_auth_config',
        'description': 'Problème d\'authentification détecté'
    },
    'permission': {
        'pattern': r'(permission|accès|access).*(refusé|denied|interdit)',
        'severity': 'high',
        'action': 'check_permissions',
        'description': 'Problème de permissions détecté'
    },
    'database': {
        'pattern': r'(database|sqlite|mysql|postgres).*(erreur|error|connexion)',
        'severity': 'critical',
        'action': 'check_database',
        'description': 'Problème de base de données détecté'
    },
    'template': {
        'pattern': r'(template|jinja2).*(erreur|error|introuvable|not found)',
        'severity': 'medium',
        'action': 'check_templates',
        'description': 'Problème de template détecté'
    },
    'import': {
        'pattern': r'(import|module).*(introuvable|not found|cannot import)',
        'severity': 'critical',
        'action': 'check_dependencies',
        'description': 'Problème de dépendance Python détecté'
    },
    'memory': {
        'pattern': r'(memory|mémoire|ram).*(plein|full|exhausted|limit)',
        'severity': 'critical',
        'action': 'check_resources',
        'description': 'Problème de mémoire détecté'
    },
    'disk': {
        'pattern': r'(disk|disque|storage).*(plein|full|espace|space)',
        'severity': 'high',
        'action': 'check_disk_space',
        'description': 'Problème d\'espace disque détecté'
    },
    'ssl': {
        'pattern': r'(ssl|tls|certificat|certificate).*(erreur|error|expiré|expired|invalide)',
        'severity': 'high',
        'action': 'check_ssl_certs',
        'description': 'Problème SSL/TLS détecté'
    },
    'service': {
        'pattern': r'(service|démon|daemon).*(démarrage|start).*(échec|failed)',
        'severity': 'critical',
        'action': 'check_service_config',
        'description': 'Problème de service détecté'
    }
}

# Actions correctives disponibles
CORRECTIVE_ACTIONS = {
    'check_ldap_config': {
        'name': 'Vérifier configuration LDAP',
        'script': 'scripts/test_ldap_config.ps1',
        'auto_fix': False,
        'description': 'Vérifie la connectivité et la configuration LDAP'
    },
    'check_auth_config': {
        'name': 'Vérifier configuration authentification',
        'script': None,
        'auto_fix': False,
        'description': 'Vérifie les paramètres d\'authentification'
    },
    'check_permissions': {
        'name': 'Vérifier permissions',
        'script': None,
        'auto_fix': False,
        'description': 'Vérifie les permissions des fichiers et répertoires'
    },
    'check_database': {
        'name': 'Vérifier base de données',
        'script': None,
        'auto_fix': False,
        'description': 'Vérifie l\'intégrité de la base de données'
    },
    'check_templates': {
        'name': 'Vérifier templates',
        'script': None,
        'auto_fix': True,
        'description': 'Vérifie la présence des templates et propose des corrections'
    },
    'check_dependencies': {
        'name': 'Vérifier dépendances',
        'script': 'scripts/check_deps.ps1',
        'auto_fix': True,
        'description': 'Vérifie et installe les dépendances manquantes'
    },
    'check_resources': {
        'name': 'Vérifier ressources système',
        'script': None,
        'auto_fix': False,
        'description': 'Vérifie l\'utilisation de la mémoire et CPU'
    },
    'check_disk_space': {
        'name': 'Vérifier espace disque',
        'script': None,
        'auto_fix': False,
        'description': 'Vérifie l\'espace disque disponible'
    },
    'check_ssl_certs': {
        'name': 'Vérifier certificats SSL',
        'script': None,
        'auto_fix': False,
        'description': 'Vérifie la validité des certificats SSL'
    },
    'check_service_config': {
        'name': 'Vérifier configuration service',
        'script': 'scripts/check_service.ps1',
        'auto_fix': False,
        'description': 'Vérifie la configuration du service Windows'
    }
}


class LogAnalyzer:
    """Analyseur de logs pour détection et correction automatique."""
    
    def __init__(self, logs_dir: str = 'logs'):
        self.logs_dir = Path(logs_dir)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'status': 'pending',
            'issues': [],
            'actions_taken': [],
            'recommendations': []
        }
    
    def analyze_all_logs(self, hours: int = 24) -> Dict[str, Any]:
        """
        Analyser tous les fichiers de logs récents.
        
        Args:
            hours: Nombre d'heures à analyser (défaut: 24)
        
        Returns:
            dict: Résultats de l'analyse
        """
        logger.info(f"Démarrage analyse des logs (dernières {hours}h)")
        
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'status': 'analyzing',
            'issues': [],
            'actions_taken': [],
            'recommendations': [],
            'summary': {
                'total_errors': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        # Fichiers à analyser
        log_files = [
            self.logs_dir / 'server.log',
            self.logs_dir / 'debug.log',
            self.logs_dir / 'audit.log',
            self.logs_dir / 'service.log',
            self.logs_dir / 'error.log'
        ]
        
        # Analyser chaque fichier
        for log_file in log_files:
            if log_file.exists():
                self._analyze_file(log_file, hours)
        
        # Trier les problèmes par sévérité
        self.results['issues'].sort(
            key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x['severity'], 4)
        )
        
        # Générer recommandations
        self._generate_recommendations()
        
        # Déterminer le statut global
        if self.results['summary']['critical'] > 0:
            self.results['status'] = 'critical'
        elif self.results['summary']['high'] > 0:
            self.results['status'] = 'warning'
        elif self.results['summary']['medium'] > 0:
            self.results['status'] = 'attention'
        else:
            self.results['status'] = 'healthy'
        
        logger.info(f"Analyse terminée: {len(self.results['issues'])} problème(s) détecté(s)")
        
        return self.results
    
    def _analyze_file(self, file_path: Path, hours: int):
        """Analyser un fichier de log spécifique."""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # Vérifier si la ligne est récente
                    line_time = self._extract_timestamp(line)
                    if line_time and line_time < cutoff_time:
                        continue
                    
                    # Chercher les patterns d'erreur
                    for error_type, config in ERROR_PATTERNS.items():
                        if re.search(config['pattern'], line, re.IGNORECASE):
                            self._add_issue(error_type, config, line, file_path.name)
                            
        except Exception as e:
            logger.error(f"Erreur lecture log {file_path}: {e}")
    
    def _extract_timestamp(self, line: str) -> datetime:
        """Extraire le timestamp d'une ligne de log."""
        patterns = [
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
            r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    ts = match.group(1)
                    if 'T' in ts:
                        return datetime.fromisoformat(ts)
                    elif '/' in ts:
                        return datetime.strptime(ts, '%d/%m/%Y %H:%M:%S')
                    else:
                        return datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                except:
                    pass
        return None
    
    def _add_issue(self, error_type: str, config: dict, line: str, source: str):
        """Ajouter un problème détecté."""
        # Vérifier si ce problème existe déjà
        issue_id = f"{error_type}_{hash(line) % 10000}"
        
        for existing in self.results['issues']:
            if existing.get('id') == issue_id:
                existing['count'] = existing.get('count', 1) + 1
                return
        
        # Créer nouveau problème
        issue = {
            'id': issue_id,
            'type': error_type,
            'severity': config['severity'],
            'description': config['description'],
            'message': line.strip()[:200],
            'source': source,
            'action': config['action'],
            'count': 1,
            'timestamp': datetime.now().isoformat()
        }
        
        self.results['issues'].append(issue)
        self.results['summary']['total_errors'] += 1
        self.results['summary'][config['severity']] += 1
    
    def _generate_recommendations(self):
        """Générer des recommandations basées sur les problèmes détectés."""
        actions_needed = set()
        
        for issue in self.results['issues']:
            action = issue.get('action')
            if action and action in CORRECTIVE_ACTIONS:
                actions_needed.add(action)
        
        for action_id in actions_needed:
            action_info = CORRECTIVE_ACTIONS[action_id]
            self.results['recommendations'].append({
                'action': action_id,
                'name': action_info['name'],
                'description': action_info['description'],
                'auto_fix_available': action_info['auto_fix'],
                'script': action_info['script'],
                'priority': 'high' if action_info['auto_fix'] else 'medium'
            })
    
    def execute_auto_fixes(self) -> List[Dict[str, Any]]:
        """
        Exécuter les corrections automatiques disponibles.
        
        Returns:
            list: Résultats des actions exécutées
        """
        results = []
        
        for recommendation in self.results['recommendations']:
            if recommendation['auto_fix_available']:
                action_id = recommendation['action']
                action_info = CORRECTIVE_ACTIONS[action_id]
                
                logger.info(f"Exécution correction automatique: {action_id}")
                
                try:
                    if action_id == 'check_templates':
                        result = self._fix_templates()
                    elif action_id == 'check_dependencies':
                        result = self._fix_dependencies()
                    else:
                        result = {'success': False, 'error': 'Action non implémentée'}
                    
                    result['action'] = action_id
                    result['name'] = action_info['name']
                    results.append(result)
                    self.results['actions_taken'].append(result)
                    
                except Exception as e:
                    logger.error(f"Erreur correction {action_id}: {e}")
                    results.append({
                        'action': action_id,
                        'success': False,
                        'error': str(e)
                    })
        
        return results
    
    def _fix_templates(self) -> Dict[str, Any]:
        """Vérifier et corriger les templates manquants."""
        templates_dir = Path('templates')
        required_templates = [
            'base.html', 'index.html', 'dashboard.html',
            'users.html', 'groups.html', 'computers.html', 'ous.html'
        ]
        
        missing = []
        for template in required_templates:
            if not (templates_dir / template).exists():
                missing.append(template)
        
        if missing:
            return {
                'success': False,
                'missing': missing,
                'message': f'Templates manquants: {", ".join(missing)}'
            }
        else:
            return {
                'success': True,
                'message': 'Tous les templates requis sont présents'
            }
    
    def _fix_dependencies(self) -> Dict[str, Any]:
        """Vérifier et installer les dépendances manquantes."""
        import subprocess
        
        try:
            result = subprocess.run(
                ['pip', 'install', '-r', 'requirements.txt'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout[-500:] if result.stdout else '',
                'error': result.stderr[-500:] if result.stderr else ''
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def save_report(self, output_path: str = None) -> str:
        """
        Sauvegarder le rapport d'analyse.
        
        Args:
            output_path: Chemin de sortie (défaut: logs/analysis_YYYYMMDD_HHMMSS.json)
        
        Returns:
            str: Chemin du fichier sauvegardé
        """
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = self.logs_dir / f'analysis_{timestamp}.json'
        else:
            output_path = Path(output_path)
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Rapport sauvegardé: {output_path}")
        return str(output_path)
    
    def get_summary_text(self) -> str:
        """Obtenir un résumé textuel de l'analyse."""
        lines = [
            "=" * 60,
            "RAPPORT D'ANALYSE DES LOGS",
            "=" * 60,
            f"Date: {self.results['timestamp']}",
            f"Statut: {self.results['status'].upper()}",
            "",
            "RÉSUMÉ:",
            f"  - Total erreurs: {self.results['summary']['total_errors']}",
            f"  - Critiques: {self.results['summary']['critical']}",
            f"  - Hautes: {self.results['summary']['high']}",
            f"  - Moyennes: {self.results['summary']['medium']}",
            f"  - Basses: {self.results['summary']['low']}",
            ""
        ]
        
        if self.results['issues']:
            lines.append("PROBLÈMES DÉTECTÉS:")
            for issue in self.results['issues'][:10]:  # Top 10
                lines.append(f"  [{issue['severity'].upper()}] {issue['description']}")
                lines.append(f"    → {issue['message'][:100]}")
            lines.append("")
        
        if self.results['recommendations']:
            lines.append("RECOMMANDATIONS:")
            for rec in self.results['recommendations']:
                auto = "✅ Auto" if rec['auto_fix_available'] else "❌ Manuel"
                lines.append(f"  {auto} - {rec['name']}")
            lines.append("")
        
        if self.results['actions_taken']:
            lines.append("ACTIONS EXÉCUTÉES:")
            for action in self.results['actions_taken']:
                status = "✅" if action['success'] else "❌"
                lines.append(f"  {status} {action['name']}")
            lines.append("")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)


# Instance globale pour accès rapide
analyzer = LogAnalyzer()


def analyze_logs_on_startup():
    """
    Fonction à appeler au démarrage de l'application.
    Analyse les logs et exécute les corrections automatiques.
    """
    logger.info("=" * 60)
    logger.info("DÉMARRAGE ANALYSE AUTOMATIQUE DES LOGS")
    logger.info("=" * 60)
    
    try:
        # Analyser les logs des dernières 24h
        results = analyzer.analyze_all_logs(hours=24)
        
        # Afficher le résumé
        summary = analyzer.get_summary_text()
        logger.info(summary)
        
        # Exécuter les corrections automatiques
        if results['recommendations']:
            logger.info("Exécution des corrections automatiques...")
            fix_results = analyzer.execute_auto_fixes()
            
            for fix in fix_results:
                status = "SUCCÈS" if fix['success'] else "ÉCHEC"
                logger.info(f"  {fix['name']}: {status}")
        
        # Sauvegarder le rapport
        report_path = analyzer.save_report()
        logger.info(f"Rapport sauvegardé: {report_path}")
        
        return results
        
    except Exception as e:
        logger.error(f"Erreur analyse automatique: {e}", exc_info=True)
        return {'status': 'error', 'error': str(e)}
