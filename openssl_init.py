"""
Initialisation d'OpenSSL pour Python 3.12+
Active le provider legacy pour le support MD4/NTLM
"""
import os
import ssl

# Configuration pour OpenSSL 3.x - Activer le provider legacy
def init_openssl_legacy():
    """Initialiser OpenSSL avec le provider legacy pour MD4/NTLM."""
    
    # Définir OPENSSL_CONF avant tout import de cryptography
    openssl_conf = os.path.join(os.path.dirname(__file__), 'openssl_legacy.cnf')
    
    if os.path.exists(openssl_conf):
        os.environ['OPENSSL_CONF'] = openssl_conf
        
        # Forcer le rechargement de la configuration SSL
        try:
            # Créer un contexte SSL avec les providers legacy
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        except Exception:
            pass

# Initialiser dès l'import
init_openssl_legacy()
