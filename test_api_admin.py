"""
Test API Password Audit - Check admin_weak_accounts
"""
import requests
import json

# Create session with cookies
session = requests.Session()

# Load cookies from file
try:
    with open('test_cookies.json', 'r') as f:
        cookies = json.load(f)
    
    for cookie in cookies:
        session.cookies.set(cookie['name'], cookie['value'], domain='localhost', path='/')
except Exception as e:
    print(f"Error loading cookies: {e}")
    print("Please run save_cookies_simple.py first")
    exit(1)

# Call API
print("📄 Calling /api/password-audit...\n")

try:
    resp = session.get('http://localhost:5000/api/password-audit', timeout=30)
    print(f"Status: {resp.status_code}")
    
    data = resp.json()
    
    print(f"\nKeys returned: {list(data.keys())}")
    
    # Check admin_weak_accounts
    if 'admin_weak_accounts' in data:
        admin_data = data['admin_weak_accounts']
        print(f"\n✅ admin_weak_accounts found!")
        print(f"   Count: {len(admin_data)}")
        
        if admin_data:
            print(f"\n   Contents:")
            for acc in admin_data[:5]:  # Show first 5
                print(f"   - {acc.get('type', 'N/A')}: {acc.get('issue', 'N/A')[:60]} ({acc.get('severity', 'N/A')})")
        else:
            print(f"   (empty list)")
    else:
        print(f"\n❌ admin_weak_accounts NOT found in response!")
        print(f"   Available keys: {list(data.keys())}")
    
    # Check summary
    if 'summary' in data:
        print(f"\n📊 Summary:")
        summary = data['summary']
        print(f"   total_issues: {summary.get('total_issues', 0)}")
        print(f"   critical_issues: {summary.get('critical_issues', 0)}")
        if 'admin_weak_count' in summary:
            print(f"   admin_weak_count: {summary.get('admin_weak_count', 0)}")
    
except Exception as e:
    print(f"Error: {e}")
