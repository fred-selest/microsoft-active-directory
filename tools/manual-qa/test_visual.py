"""
Test visuel des pages AD Web Interface
Ouvre le navigateur et prend des captures d'écran
"""

from playwright.sync_api import sync_playwright
import time
import os

print("\n" + "="*60)
print(" TEST VISUEL - AD Web Interface")
print("="*60)

with sync_playwright() as p:
    # Lancer le navigateur en mode visible
    browser = p.chromium.launch(headless=False, slow_mo=50)
    context = browser.new_context(
        viewport={'width': 1920, 'height': 1080},
        device_scale_factor=1
    )
    page = context.new_page()
    
    pages_to_test = [
        ('/dashboard', 'Dashboard'),
        ('/users', 'Utilisateurs'),
        ('/groups', 'Groupes'),
        ('/password-policy', 'Password Policy'),
        ('/password-audit', 'Password Audit'),
    ]
    
    os.makedirs('logs/screenshots', exist_ok=True)
    
    for url, name in pages_to_test:
        print(f"\n📸 Testing: {name} ({url})")
        try:
            page.goto(f'http://localhost:5000{url}', wait_until='networkidle')
            time.sleep(1)
            
            # Capture plein page
            screenshot_path = f'logs/screenshots/{name.replace(" ", "_")}.png'
            page.screenshot(path=screenshot_path, full_page=True)
            print(f"   ✅ Screenshot: {screenshot_path}")
            
            # Vérifier erreurs JS
            errors = []
            page.on('pageerror', lambda e: errors.append(str(e)))
            
            if errors:
                print(f"   ⚠️  JS Errors: {len(errors)}")
                for err in errors[:3]:
                    print(f"      - {err[:80]}")
            
        except Exception as e:
            print(f"   ❌ Error: {str(e)[:100]}")
    
    print("\n" + "="*60)
    print(" ✅ Tests terminés !")
    print(" 📁 Screenshots: logs/screenshots/")
    print("="*60 + "\n")
    
    # Garder le navigateur ouvert 10 secondes pour inspection visuelle
    print("👀 Laissez le navigateur ouvert pour inspection visuelle...")
    time.sleep(10)
    
    browser.close()
