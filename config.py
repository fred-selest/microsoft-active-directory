"""
Cross-platform configuration for Microsoft Active Directory Web Interface.
Supports Windows and Linux systems.
"""

import os
import platform
from pathlib import Path

# Detect operating system
CURRENT_OS = platform.system().lower()
IS_WINDOWS = CURRENT_OS == 'windows'
IS_LINUX = CURRENT_OS == 'linux'

# Base directory (cross-platform)
BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base configuration class with cross-platform support."""

    # Server binding - 0.0.0.0 allows access from any network interface
    # This is critical for cross-platform and remote access
    HOST = os.environ.get('AD_WEB_HOST', '0.0.0.0')
    PORT = int(os.environ.get('AD_WEB_PORT', 5000))

    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'change-this-in-production')
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

    # Active Directory configuration
    AD_SERVER = os.environ.get('AD_SERVER', '')
    AD_PORT = int(os.environ.get('AD_PORT', 389))
    AD_USE_SSL = os.environ.get('AD_USE_SSL', 'False').lower() == 'true'
    AD_BASE_DN = os.environ.get('AD_BASE_DN', '')

    # Cross-platform paths
    if IS_WINDOWS:
        LOG_DIR = Path(os.environ.get('AD_LOG_DIR', 'C:/ProgramData/ADWebInterface/logs'))
        DATA_DIR = Path(os.environ.get('AD_DATA_DIR', 'C:/ProgramData/ADWebInterface/data'))
    else:
        LOG_DIR = Path(os.environ.get('AD_LOG_DIR', '/var/log/ad-web-interface'))
        DATA_DIR = Path(os.environ.get('AD_DATA_DIR', '/var/lib/ad-web-interface'))

    # Ensure directories exist
    @classmethod
    def init_directories(cls):
        """Create necessary directories if they don't exist."""
        for directory in [cls.LOG_DIR, cls.DATA_DIR]:
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                # Fall back to user directory if system directories are not accessible
                fallback = BASE_DIR / directory.name
                fallback.mkdir(parents=True, exist_ok=True)
                if directory == cls.LOG_DIR:
                    cls.LOG_DIR = fallback
                else:
                    cls.DATA_DIR = fallback


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False


class TestConfig(Config):
    """Testing configuration."""
    TESTING = True
    DEBUG = True


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Get configuration based on environment."""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
