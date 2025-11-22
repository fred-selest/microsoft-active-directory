"""
Configuration multi-plateforme pour l'interface web Microsoft Active Directory.
Compatible avec les systèmes Windows et Linux.
"""

import os
import platform
from pathlib import Path

# Détection du système d'exploitation
CURRENT_OS = platform.system().lower()
IS_WINDOWS = CURRENT_OS == 'windows'
IS_LINUX = CURRENT_OS == 'linux'

# Répertoire de base (multi-plateforme)
BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Classe de configuration de base avec support multi-plateforme."""

    # Liaison du serveur - 0.0.0.0 permet l'accès depuis n'importe quelle interface réseau
    # Ceci est essentiel pour l'accès multi-plateforme et à distance
    HOST = os.environ.get('AD_WEB_HOST', '0.0.0.0')
    PORT = int(os.environ.get('AD_WEB_PORT', 5000))

    # Configuration Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'changer-ceci-en-production')
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

    # Vérification de sécurité: empêcher l'utilisation de la SECRET_KEY par défaut en production
    if not DEBUG and SECRET_KEY == 'changer-ceci-en-production':
        raise ValueError(
            "ERREUR DE SÉCURITÉ: Vous devez définir une SECRET_KEY forte via la variable d'environnement SECRET_KEY.\n"
            "Générez une clé sécurisée avec: python -c 'import secrets; print(secrets.token_hex(32))'\n"
            "Puis définissez-la dans votre fichier .env: SECRET_KEY=votre_cle_generee"
        )

    # Configuration Active Directory
    AD_SERVER = os.environ.get('AD_SERVER', '')
    AD_PORT = int(os.environ.get('AD_PORT', 389))
    AD_USE_SSL = os.environ.get('AD_USE_SSL', 'False').lower() == 'true'
    AD_BASE_DN = os.environ.get('AD_BASE_DN', '')

    # Configuration de session
    SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', 30))  # minutes
    PERMANENT_SESSION_LIFETIME = SESSION_TIMEOUT * 60  # secondes

    # Configuration RBAC (Role-Based Access Control)
    # Roles: admin, operator, reader
    # SÉCURITÉ: RBAC activé par défaut avec rôle 'reader' (privilège minimum)
    RBAC_ENABLED = os.environ.get('RBAC_ENABLED', 'true').lower() == 'true'
    DEFAULT_ROLE = os.environ.get('DEFAULT_ROLE', 'reader')

    # Groupes AD pour attribution automatique des rôles
    # Noms de groupes AD (CN) séparés par des virgules
    # Le premier groupe correspondant détermine le rôle (ordre: admin > operator > reader)
    ADMIN_GROUPS = [g.strip() for g in os.environ.get('RBAC_ADMIN_GROUPS', 'Domain Admins,Administrateurs du domaine').split(',') if g.strip()]
    OPERATOR_GROUPS = [g.strip() for g in os.environ.get('RBAC_OPERATOR_GROUPS', '').split(',') if g.strip()]
    READER_GROUPS = [g.strip() for g in os.environ.get('RBAC_READER_GROUPS', '').split(',') if g.strip()]

    # Configuration HTTPS
    # Force la redirection HTTP -> HTTPS (recommandé en production)
    FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'
    # Liste des proxys de confiance (pour X-Forwarded-Proto)
    TRUSTED_PROXIES = os.environ.get('TRUSTED_PROXIES', '127.0.0.1,::1').split(',')

    # Pagination
    ITEMS_PER_PAGE = int(os.environ.get('ITEMS_PER_PAGE', 25))

    # Chemins multi-plateformes
    if IS_WINDOWS:
        LOG_DIR = Path(os.environ.get('AD_LOG_DIR', 'C:/ProgramData/ADWebInterface/logs'))
        DATA_DIR = Path(os.environ.get('AD_DATA_DIR', 'C:/ProgramData/ADWebInterface/data'))
    else:
        LOG_DIR = Path(os.environ.get('AD_LOG_DIR', '/var/log/ad-web-interface'))
        DATA_DIR = Path(os.environ.get('AD_DATA_DIR', '/var/lib/ad-web-interface'))

    # Création des répertoires nécessaires
    @classmethod
    def init_directories(cls):
        """Créer les répertoires nécessaires s'ils n'existent pas."""
        for directory in [cls.LOG_DIR, cls.DATA_DIR]:
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                # Utiliser le répertoire utilisateur si les répertoires système ne sont pas accessibles
                fallback = BASE_DIR / directory.name
                fallback.mkdir(parents=True, exist_ok=True)
                if directory == cls.LOG_DIR:
                    cls.LOG_DIR = fallback
                else:
                    cls.DATA_DIR = fallback


class DevelopmentConfig(Config):
    """Configuration de développement."""
    DEBUG = True


class ProductionConfig(Config):
    """Configuration de production."""
    DEBUG = False


class TestConfig(Config):
    """Configuration de test."""
    TESTING = True
    DEBUG = True


# Dictionnaire de configuration
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Obtenir la configuration basée sur l'environnement."""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
