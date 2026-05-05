import sys
sys.path.insert(0, r'C:\AD-WebInterface')

# Test Flask app loading (same as run.py)
try:
    from app import app
    print("OK - Flask app loaded successfully")
    print(f"Debug mode: {app.debug}")
    
    # Check routes are registered
    routes = [str(rule) for rule in app.url_map.iter_rules()]
    print(f"Total routes: {len(routes)}")
    
    # Check key routes
    key_routes = ['/login', '/api/status', '/password-audit', '/api/fix-password']
    for route in key_routes:
        found = any(route in str(r) for r in routes)
        status = "OK" if found else "MISSING"
        print(f"  {route}: {status}")
    
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
