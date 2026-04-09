# -*- coding: utf-8 -*-
"""
Watchdog - Surveillance continue et autocorrection automatique.
Thread daemon qui vérifie la santé du système toutes les 5 minutes.
"""
import shutil
import socket
import threading
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# État partagé lisible par l'API
_watchdog_status = {
    'started': False,
    'last_check': None,
    'disk_free_gb': None,
    'issues': [],
    'fixes_applied': [],
    'status': 'starting'
}
_status_lock = threading.Lock()


def get_watchdog_status() -> dict:
    """Retourne une copie de l'état courant du watchdog."""
    with _status_lock:
        return dict(_watchdog_status)


class Watchdog(threading.Thread):
    def __init__(self, interval_seconds: int = 300):
        super().__init__(daemon=True, name='watchdog')
        self.interval = interval_seconds

    def run(self):
        with _status_lock:
            _watchdog_status['started'] = True
            _watchdog_status['status'] = 'running'
        # Délai initial pour laisser l'app démarrer
        time.sleep(30)
        while True:
            try:
                self._check_cycle()
            except Exception as e:
                logger.error(f"Watchdog erreur cycle: {e}")
                with _status_lock:
                    _watchdog_status['status'] = 'error'
                    _watchdog_status['issues'] = [f'Erreur interne watchdog: {e}']
            time.sleep(self.interval)

    def _check_cycle(self):
        issues = []
        fixes_applied = []

        # 1. Espace disque
        try:
            usage = shutil.disk_usage('C:\\')
            free_gb = round(usage.free / (1024 ** 3), 1)
        except Exception:
            try:
                usage = shutil.disk_usage('/')
                free_gb = round(usage.free / (1024 ** 3), 1)
            except Exception:
                free_gb = None

        if free_gb is not None and free_gb < 1.0:
            issues.append(f'disk_critical: {free_gb} Go restant')
            logger.critical(f"Watchdog: Disque presque plein ({free_gb} Go)")

        # 2. Rotation préventive des logs
        try:
            from core.log_analyzer import rotate_logs
            rotate_logs(max_size_mb=10)
        except Exception as e:
            logger.warning(f"Watchdog: Rotation logs: {e}")

        # 3. Dépendances Python critiques
        missing = _check_critical_imports()
        if missing:
            logger.warning(f"Watchdog: Dépendances manquantes: {missing}")
            if _fix_dependencies():
                fixes_applied.append(f'deps_reinstalled: {missing}')
                logger.info(f"Watchdog: Dépendances réinstallées: {missing}")
            else:
                issues.append(f'deps_missing: {missing}')

        # 4. Connectivité LDAP (si AD_SERVER configuré)
        try:
            from config import get_config
            cfg = get_config()
            ad_server = getattr(cfg, 'AD_SERVER', None)
            if ad_server:
                if not _test_ldap_port(ad_server):
                    issues.append(f'ldap_unreachable: {ad_server}')
                    logger.error(f"Watchdog: LDAP inaccessible sur {ad_server}:389")
        except Exception as e:
            logger.debug(f"Watchdog: Vérif LDAP ignorée: {e}")

        # 5. Vérification settings.json
        try:
            project_root = Path(__file__).resolve().parent.parent
            settings_file = project_root / 'data' / 'settings.json'
            if settings_file.exists():
                import json
                json.loads(settings_file.read_text(encoding='utf-8'))
        except Exception as e:
            issues.append(f'settings_json_corrupt: {e}')
            logger.error(f"Watchdog: settings.json corrompu: {e}")

        # Mise à jour statut
        overall = 'critical' if any('critical' in i for i in issues) else (
            'warning' if issues else 'ok'
        )
        with _status_lock:
            _watchdog_status.update({
                'last_check': time.strftime('%Y-%m-%d %H:%M:%S'),
                'disk_free_gb': free_gb,
                'issues': issues,
                'fixes_applied': fixes_applied,
                'status': overall
            })

        if issues:
            logger.warning(f"Watchdog: {len(issues)} problème(s) — {issues}")
        else:
            logger.debug("Watchdog: Système sain")


def _check_critical_imports() -> list:
    """Vérifie que les packages critiques sont importables."""
    missing = []
    for pkg in ['flask', 'ldap3', 'cryptography', 'waitress']:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    return missing


def _fix_dependencies() -> bool:
    """Réinstalle les dépendances via le venv pip."""
    try:
        from core.updater import update_dependencies
        return update_dependencies(silent=True)
    except Exception as e:
        logger.error(f"Watchdog: fix_dependencies: {e}")
        return False


def _test_ldap_port(server: str, port: int = 389, timeout: int = 5) -> bool:
    """Teste la connexion TCP au serveur LDAP."""
    try:
        with socket.create_connection((server, port), timeout=timeout):
            return True
    except Exception:
        return False


def start_watchdog(interval_seconds: int = 300):
    """Démarre le thread watchdog. Ne démarre qu'une seule instance."""
    with _status_lock:
        if _watchdog_status.get('started'):
            return
    w = Watchdog(interval_seconds)
    w.start()
    logger.info(f"Watchdog démarré (intervalle: {interval_seconds}s)")
