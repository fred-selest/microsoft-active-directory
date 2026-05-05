#!/usr/bin/env python3
"""Script temporaire pour vérifier les droits de l'utilisateur testino."""
import os
import sys

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Initialiser OpenSSL en premier
import _openssl_init

from ldap3 import Server, Connection, SUBTREE, NTLM, ALL
from dotenv import load_dotenv
from core.granular_permissions import get_available_permissions, load_permissions

load_dotenv()

# Configuration connexion AD
AD_SERVER = os.environ.get('AD_SERVER', 'srv-dc01')
AD_DOMAIN = os.environ.get('AD_DOMAIN', 'selest.local')
AD_USER = 'admin'
AD_PASS = '@Alfreddo68'

print('=== VÉRIFICATION DROITS UTILISATEUR: testino ===')
print()

# Construire la base DN
base_dn = ','.join([f'DC={p}' for p in AD_DOMAIN.split('.')])
ntlm_user = f'{AD_DOMAIN}\\{AD_USER}'

print(f'Serveur: {AD_SERVER}')
print(f'Domaine: {AD_DOMAIN}')
print(f'Base DN: {base_dn}')
print()

# Connexion avec le compte de service
print('Connexion AD...')
try:
    server = Server(AD_SERVER, get_info=ALL)
    conn = Connection(server, user=ntlm_user, password=AD_PASS, authentication=NTLM, auto_bind=True)
    print('✅ Connecté')
except Exception as e:
    print(f'❌ ERREUR CONNEXION: {e}')
    sys.exit(1)

try:
    print()
    
    # Rechercher l'utilisateur testino
    conn.search(base_dn, '(sAMAccountName=testino)', SUBTREE,
               attributes=['sAMAccountName', 'displayName', 'memberOf', 'primaryGroupID', 'description'])
    
    if not conn.entries:
        print('❌ UTILISATEUR "testino" NON TROUVÉ dans AD')
        sys.exit(1)
    
    user = conn.entries[0]
    print(f'👤 Utilisateur: {user.sAMAccountName}')
    print(f'📝 Nom affiché: {user.displayName if user.displayName else "N/A"}')
    print(f'📋 Description: {user.description if user.description else "N/A"}')
    print()
    
    # Lister les groupes
    groups = []
    print('📁 Groupes AD:')
    if hasattr(user, 'memberOf') and user.memberOf and user.memberOf.values:
        for dn in user.memberOf.values:
            cn = str(dn).split(',')[0].replace('CN=', '')
            groups.append(str(dn))
            print(f'   - {cn}')
    else:
        print('   (aucun groupe - groupe primaire Domain Users uniquement)')
    
    print(f'\n📊 Total: {len(groups)} groupe(s)')
    
    # Vérifier les permissions granulaires
    print()
    print('=' * 50)
    print('PERMISSIONS GRANULAIRES')
    print('=' * 50)
    
    all_perms = get_available_permissions()
    user_permissions = set()
    perm_file = load_permissions()
    
    for group_dn in groups:
        group_cn = group_dn.split(',')[0].replace('CN=', '')
        perm_data = perm_file.get(group_cn, {})
        if perm_data.get('enabled', True):
            for perm in perm_data.get('permissions', []):
                user_permissions.add(perm)
    
    if user_permissions:
        print(f'✅ {len(user_permissions)} permission(s) accordée(s):')
        print()
        for perm in sorted(user_permissions):
            desc = next((p.description for p in all_perms if p.id == perm), perm)
            print(f'   ✅ {perm}')
            print(f'      → {desc}')
    else:
        print('⚠️  AUCUNE PERMISSION GRANULAIRE CONFIGURÉE')
        print()
        print('   Pour assigner des droits:')
        print('   1. Va sur http://localhost:5000/permissions')
        print('   2. Sélectionne un des groupes ci-dessus')
        print('   3. Coche les permissions souhaitées')
        print('   4. Sauvegarde')

finally:
    conn.unbind()
