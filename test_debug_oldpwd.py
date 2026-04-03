"""
Debug - Vérifier les données old_passwords
"""
import requests
import json

session = requests.Session()

try:
    with open('test_cookies.json', 'r') as f:
        cookies = json.load(f)
    for cookie in cookies:
        session.cookies.set(cookie['name'], cookie['value'], domain='localhost', path='/')
except Exception as e:
    print(f"❌ Erreur cookies: {e}")
    exit(1)

print("🔍 Appel API...\n")

try:
    resp = session.get('http://localhost:5000/api/password-audit', timeout=30)
    data = resp.json()
    
    # Vérifier old_passwords
    if 'old_passwords' in data:
        old = data['old_passwords']
        print(f"old_passwords: {len(old)} entrées")
        
        for i, pwd in enumerate(old[:3]):  # Premières 3 entrées
            print(f"\n[{i}] {pwd}")
            print(f"    Type: {type(pwd)}")
            if isinstance(pwd, dict):
                for key, value in pwd.items():
                    print(f"    {key}: {value} (type: {type(value).__name__})")
    else:
        print("❌ old_passwords NOT FOUND")
        print(f"Keys: {list(data.keys())}")
        
except Exception as e:
    print(f"❌ Erreur: {e}")
    # Try to see HTML error
    try:
        print(f"Response: {resp.text[:500]}")
    except:
        pass
