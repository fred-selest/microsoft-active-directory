"""
Module de chiffrement pour les données sensibles en session.
Utilise Fernet (AES-128 en mode CBC) pour chiffrer les mots de passe.
"""
import base64
import os
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

_SALT_FILE = Path(__file__).resolve().parent / 'data' / 'crypto_salt.bin'


def _load_or_create_salt() -> bytes:
    """
    Charge le salt de chiffrement depuis le fichier data/crypto_salt.bin.
    Si le fichier n'existe pas, génère un salt aléatoire de 32 octets et le persiste.
    Cela garantit un salt unique par déploiement, stable entre les redémarrages.
    """
    if _SALT_FILE.exists():
        return _SALT_FILE.read_bytes()
    salt = os.urandom(32)
    _SALT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SALT_FILE.write_bytes(salt)
    return salt


class SessionCrypto:
    """Gestionnaire de chiffrement pour les données de session."""

    def __init__(self, secret_key: str):
        """
        Initialise le chiffreur avec une clé dérivée du SECRET_KEY et d'un salt
        propre à ce déploiement (généré une fois, stocké dans data/crypto_salt.bin).

        Args:
            secret_key: La SECRET_KEY de Flask
        """
        salt = _load_or_create_salt()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))
        self.fernet = Fernet(key)

    def encrypt(self, data: str) -> str:
        """
        Chiffre une chaîne de caractères.

        Args:
            data: La chaîne à chiffrer

        Returns:
            La chaîne chiffrée encodée en base64
        """
        if not data:
            return ''

        encrypted_bytes = self.fernet.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_bytes).decode()

    def decrypt(self, encrypted_data: str) -> str:
        """
        Déchiffre une chaîne de caractères.

        Args:
            encrypted_data: La chaîne chiffrée

        Returns:
            La chaîne déchiffrée

        Raises:
            ValueError: Si le déchiffrement échoue
        """
        if not encrypted_data:
            return ''

        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_bytes = self.fernet.decrypt(encrypted_bytes)
            return decrypted_bytes.decode()
        except Exception as e:
            raise ValueError(f"Échec du déchiffrement: {str(e)}")


# Instance globale (sera initialisée avec le SECRET_KEY de l'app)
_crypto_instance = None


def init_crypto(secret_key: str):
    """Initialise l'instance globale de chiffrement."""
    global _crypto_instance
    _crypto_instance = SessionCrypto(secret_key)


def get_crypto() -> SessionCrypto:
    """Récupère l'instance globale de chiffrement."""
    if _crypto_instance is None:
        raise RuntimeError("SessionCrypto n'a pas été initialisé. Appelez init_crypto() d'abord.")
    return _crypto_instance


def encrypt_password(password: str) -> str:
    """Raccourci pour chiffrer un mot de passe."""
    return get_crypto().encrypt(password)


def decrypt_password(encrypted_password: str) -> str:
    """Raccourci pour déchiffrer un mot de passe."""
    return get_crypto().decrypt(encrypted_password)
