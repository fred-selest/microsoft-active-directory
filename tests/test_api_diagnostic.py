"""
Test /api/diagnostic endpoint
"""
import requests
import json

# Get session cookie
session = requests.Session()

# Try to access API (will fail if not connected)
try:
    resp = session.get('http://localhost:5000/api/diagnostic')
    print(f"Status: {resp.status_code}")
    data = resp.json()
    print(f"Keys: {list(data.keys())}")
    print(f"Status: {data.get('status')}")
    print(f"Checks: {len(data.get('checks', []))}")
    print(f"Errors: {len(data.get('errors', []))}")
    print(f"Warnings: {len(data.get('warnings', []))}")
    print(f"Suggestions: {len(data.get('suggestions', []))}")
    
    if data.get('suggestions'):
        print(f"\nSuggestions type: {type(data['suggestions'])}")
        print(f"First suggestion: {data['suggestions'][0] if data['suggestions'] else 'None'}")
except Exception as e:
    print(f"Error: {e}")
