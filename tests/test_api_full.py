"""
Test /api/diagnostic full response
"""
import requests
import json

session = requests.Session()

try:
    resp = session.get('http://localhost:5000/api/diagnostic')
    print(f"Status: {resp.status_code}")
    print(f"Content-Type: {resp.headers.get('Content-Type')}")
    
    data = resp.json()
    print(f"\nFull response:")
    print(json.dumps(data, indent=2))
    
    # Check each field type
    print(f"\nTypes:")
    for key, value in data.items():
        print(f"  {key}: {type(value).__name__} = {value if not isinstance(value, list) else f'list[{len(value)}]'}")
        
except Exception as e:
    print(f"Error: {e}")
