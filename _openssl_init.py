"""
Initialisation OpenSSL pour MD4/NTLM (Python 3.12+)

Module unique pour initialiser OPENSSL_CONF avant tout import cryptography/ldap3.
A importer en TOUT PREMIER dans app.py et routes/core.py
"""
import os
import sys

# Chemin vers openssl_legacy.cnf
_openssl_conf = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'openssl_legacy.cnf')

# Définir OPENSSL_CONF avant tout import de cryptography
if os.path.exists(_openssl_conf) and 'OPENSSL_CONF' not in os.environ:
    os.environ['OPENSSL_CONF'] = _openssl_conf
    # S'assurer que c'est disponible pour les subprocess
    sys.environ['OPENSSL_CONF'] = _openssl_conf
