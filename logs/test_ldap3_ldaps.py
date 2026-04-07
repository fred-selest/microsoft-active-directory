# Test LDAPS with ldap3
from ldap3 import Server, Connection, Tls, ALL
import ssl

# Create TLS config that ignores certificate validation
tls_config = Tls(
    validate=ssl.CERT_NONE,
    version=ssl.PROTOCOL_TLS,
    ssl_options=ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
)

# Test connection
server = Server('192.168.10.252', port=636, use_ssl=True, tls=tls_config, get_info=ALL)
conn = Connection(server, auto_bind=True)

if conn.bound:
    print("SUCCESS: LDAPS connection works!")
    print(f"Server: {server.info}")
    conn.unbind()
else:
    print(f"ERROR: {conn.result['description']}")