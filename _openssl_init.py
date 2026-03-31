"""
Initialisation OpenSSL pour MD4/NTLM (Python 3.12+)

Module unique pour initialiser OPENSSL_CONF avant tout import cryptography/ldap3.
A importer en TOUT PREMIER dans app.py et routes/core.py
"""
import os
import hashlib

# Chemin vers openssl_legacy.cnf
_openssl_conf = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'openssl_legacy.cnf')

# Définir OPENSSL_CONF avant tout import de cryptography
if os.path.exists(_openssl_conf) and 'OPENSSL_CONF' not in os.environ:
    os.environ['OPENSSL_CONF'] = _openssl_conf


def _patch_md4_hashlib():
    """
    Monkey-patch hashlib.new pour supporter MD4 via pycryptodome.
    Nécessaire sur Python 3.12+ / OpenSSL 3.0 sans legacy provider.
    """
    # Vérifier si MD4 est déjà disponible
    try:
        hashlib.new('md4', b'test')
        return  # MD4 natif OK, rien à faire
    except (ValueError, Exception):
        pass

    # MD4 non disponible : injecter via pycryptodome
    try:
        from Crypto.Hash import MD4 as _CryptoMD4
    except ImportError:
        return  # pycryptodome absent, on ne peut rien faire

    _original_hashlib_new = hashlib.new

    class _MD4Wrapper:
        """Wrapper pycryptodome MD4 compatible avec l'interface hashlib."""
        name = 'md4'
        digest_size = 16
        block_size = 64

        def __init__(self, data=b''):
            self._h = _CryptoMD4.new(data)

        def update(self, data):
            self._h.update(data)

        def digest(self):
            return self._h.digest()

        def hexdigest(self):
            return self._h.hexdigest()

        def copy(self):
            w = _MD4Wrapper.__new__(_MD4Wrapper)
            w._h = self._h.copy()
            return w

    def _patched_new(name, data=b'', **kwargs):
        if name.lower() in ('md4',):
            return _MD4Wrapper(data)
        return _original_hashlib_new(name, data, **kwargs)

    hashlib.new = _patched_new


_patch_md4_hashlib()
