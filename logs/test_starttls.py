# Test STARTTLS with NTLM
from ldap3 import Server, Connection, Tls, NTLM, ALL
import ssl

# TLS config (ignore cert validation)
tls_config = Tls(
    validate=ssl.CERT_NONE,
    version=ssl.PROTOCOL_TLS,
    ssl_options=ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
)

# Test STARTTLS on port 389 with NTLM
server = Server('192.168.10.252', port=389, use_ssl=False, get_info=ALL)
conn = Connection(server, user='SELEST\\admin', password='Password123!', authentication=NTLM, auto_bind=False)

# Open connection
conn.open()
print("Connection opened")

# Start TLS
result = conn.start_tls(tls_config)
print(f"STARTTLS result: {result}")

# Bind
result = conn.bind()
print(f"Bind result: {result}, bound={conn.bound}")

if conn.bound:
    print("SUCCESS: STARTTLS + NTLM works!")
    conn.unbind()
else:
    print(f"FAILED: {conn.result}")