"""
Test des Boutons de Correction Rapide - Password Audit
"""
import requests
import json

# Session
session = requests.Session()

# Charger les cookies si existants
try:
    with open('test_cookies.json', 'r') as f:
        cookies = json.load(f)
    for cookie in cookies:
        session.cookies.set(cookie['name'], cookie['value'], domain='localhost', path='/')
    print("✅ Cookies chargés")
except Exception as e:
    print(f"❌ Erreur cookies: {e}")
    print("\n⚠️  Veuillez vous connecter d'abord via le navigateur")
    print("   Puis sauvegardez les cookies avec test_cookies.py")
    exit(1)

print("\n" + "="*60)
print(" TEST DES BOUTONS DE CORRECTION RAPIDE")
print("="*60 + "\n")

# Test 1: Page Password Audit
print("1️⃣  Test page Password Audit...")
try:
    resp = session.get('http://localhost:5000/password-audit', timeout=10)
    if resp.status_code == 200:
        print(f"✅ Page accessible (HTTP {resp.status_code})")
        
        # Vérifier présence des nouveaux éléments
        html = resp.text
        checks = {
            'Checkbox Sélection': 'select-all-weak' in html,
            'Checkbox Admin': 'select-all-admin' in html,
            'Barre actions weak': 'weak-actions-bar' in html,
            'Barre actions admin': 'admin-actions-bar' in html,
            'Bouton Correction Rapide': 'Correction Rapide' in html,
        }
        
        print("\n📋 Éléments vérifiés:")
        for element, present in checks.items():
            status = "✅" if present else "❌"
            print(f"   {status} {element}")
    else:
        print(f"❌ Erreur (HTTP {resp.status_code})")
except Exception as e:
    print(f"❌ Erreur: {e}")

# Test 2: API Quick Fix (sans comptes - devrait retourner tous)
print("\n2️⃣  Test API Quick Fix (structure)...")
try:
    resp = session.post(
        'http://localhost:5000/api/password-audit/quick-fix',
        json={'fix_type': 'force_password_change', 'accounts': []},
        timeout=10
    )
    print(f"   HTTP Status: {resp.status_code}")
    
    if resp.status_code == 200:
        data = resp.json()
        print(f"✅ API fonctionne")
        print(f"   Success: {data.get('success', False)}")
        print(f"   Total: {data.get('total', 0)}")
        print(f"   Modified: {data.get('modified', 0)}")
    else:
        print(f"❌ Erreur API")
except Exception as e:
    print(f"❌ Erreur: {e}")

# Test 3: API Quick Fix avec comptes spécifiques
print("\n3️⃣  Test API Quick Fix (comptes spécifiques)...")
try:
    # Test avec un DN fictif pour vérifier que l'API accepte la structure
    resp = session.post(
        'http://localhost:5000/api/password-audit/quick-fix',
        json={
            'fix_type': 'force_password_change',
            'accounts': [
                {'dn': 'CN=Test User,OU=Users,DC=test,DC=local', 'username': 'testuser'}
            ]
        },
        timeout=10
    )
    print(f"   HTTP Status: {resp.status_code}")
    
    if resp.status_code == 200:
        data = resp.json()
        print(f"✅ API accepte les comptes spécifiques")
        print(f"   Response keys: {list(data.keys())}")
    else:
        print(f"❌ Erreur API")
except Exception as e:
    print(f"❌ Erreur: {e}")

print("\n" + "="*60)
print(" TEST TERMINÉ")
print("="*60 + "\n")

print("📋 POUR TESTER MANUELLEMENT:")
print("1. Ouvrez http://localhost:5000/password-audit")
print("2. Lancez un audit")
print("3. Vérifiez les checkboxes 'Sélection'")
print("4. Cochez des comptes individuellement")
print("5. La barre d'actions doit apparaître")
print("6. Cliquez sur '🔧 Appliquer aux sélectionnés'")
print("7. Le modal doit afficher la liste des comptes")
print("8. Confirmez et vérifiez le résultat\n")
