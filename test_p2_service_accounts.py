"""
Test P2 - Comptes de Service
"""
import requests
import json

# Create session with cookies
session = requests.Session()

try:
    with open('test_cookies.json', 'r') as f:
        cookies = json.load(f)
    
    for cookie in cookies:
        session.cookies.set(cookie['name'], cookie['value'], domain='localhost', path='/')
except Exception as e:
    print(f"❌ Erreur chargement cookies: {e}")
    exit(1)

print("📄 Test P2 - Comptes de Service\n")
print("🔍 Appel API /api/password-audit...")

try:
    resp = session.get('http://localhost:5000/api/password-audit', timeout=30)
    print(f"\n✅ Status: {resp.status_code}")
    
    data = resp.json()
    
    # Check service_accounts
    if 'service_accounts' in data:
        service_data = data['service_accounts']
        print(f"\n✅ service_accounts found!")
        print(f"   Count: {len(service_data)}")
        
        if service_data:
            print(f"\n   Résultats:")
            for acc in service_data[:5]:
                acc_type = acc.get('type', 'N/A')
                issue = acc.get('issue', 'N/A')[:50]
                severity = acc.get('severity', 'N/A')
                print(f"   - {acc_type}: {issue} ({severity})")
        else:
            print(f"   (liste vide)")
    else:
        print(f"\n❌ service_accounts NOT found!")
        print(f"   Keys: {list(data.keys())}")
    
    # Check summary
    if 'summary' in data:
        print(f"\n📊 Summary:")
        summary = data['summary']
        if 'service_weak_count' in summary:
            print(f"   service_weak_count: {summary.get('service_weak_count', 0)}")
    
    print(f"\n✅ Test P2 terminé!")
    
except Exception as e:
    print(f"\n❌ Erreur: {e}")
