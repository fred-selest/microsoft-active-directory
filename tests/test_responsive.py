"""
Script de test responsive pour AD Web Interface.
Permet de tester l'affichage sur différentes résolutions d'écran.

Usage: python test_responsive.py http://localhost:5000
"""

import sys
import time
from playwright.sync_api import sync_playwright

# Résolutions à tester
RESOLUTIONS = [
    {'name': 'Mobile (iPhone 14)', 'width': 390, 'height': 844},
    {'name': 'Mobile (iPhone 14 Pro Max)', 'width': 430, 'height': 932},
    {'name': 'Tablette (iPad)', 'width': 768, 'height': 1024},
    {'name': 'Tablette (iPad Pro)', 'width': 1024, 'height': 1366},
    {'name': 'Laptop (13")', 'width': 1280, 'height': 800},
    {'name': 'Desktop (15")', 'width': 1366, 'height': 768},
    {'name': 'Desktop (17")', 'width': 1600, 'height': 900},
    {'name': 'Large Desktop', 'width': 1920, 'height': 1080},
]

# Pages à tester
PAGES = [
    '/',
    '/connect',
    '/dashboard',
    '/admin/',
    '/password-audit',
    '/password-policy',
    '/errors',
    '/_debug/',
]


def test_responsive(base_url, headless=True):
    """
    Tester le responsive design sur différentes résolutions.
    
    Args:
        base_url: URL de base de l'application
        headless: Mode sans tête (True/False)
    """
    print(f"\n{'='*70}")
    print(f" TEST RESPONSIVE - AD Web Interface")
    print(f"{'='*70}")
    print(f"URL: {base_url}")
    print(f"Résolutions: {len(RESOLUTIONS)}")
    print(f"Pages: {len(PAGES)}")
    print(f"{'='*70}\n")
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        
        for resolution in RESOLUTIONS:
            print(f"\n📱 Testing: {resolution['name']} ({resolution['width']}x{resolution['height']})")
            print(f"{'-'*60}")
            
            context = browser.new_context(
                viewport={'width': resolution['width'], 'height': resolution['height']}
            )
            
            for page_url in PAGES:
                page = context.new_page()
                full_url = f"{base_url}{page_url}"
                
                try:
                    # Navigation avec timeout
                    response = page.goto(full_url, timeout=10000)
                    
                    # Attendre le chargement complet
                    page.wait_for_load_state('networkidle')
                    time.sleep(0.5)
                    
                    # Vérifier les erreurs JavaScript
                    errors = []
                    page.on('pageerror', lambda e: errors.append(str(e)))
                    
                    # Capture screenshot (optionnel)
                    # screenshot_dir = f"screenshots/{resolution['width']}x{resolution['height']}"
                    # os.makedirs(screenshot_dir, exist_ok=True)
                    # page.screenshot(path=f"{screenshot_dir}/{page_url.replace('/', '_') or 'index'}.png")
                    
                    # Vérifier le status HTTP
                    status = response.status if response else 'N/A'
                    status_icon = '✅' if status == 200 else '⚠️'
                    
                    print(f"  {status_icon} {page_url:25} -> HTTP {status}")
                    
                    if errors:
                        print(f"     ❌ JS Errors: {len(errors)}")
                        for err in errors[:3]:
                            print(f"        - {err[:80]}")
                    
                except Exception as e:
                    print(f"  ❌ {page_url:25} -> ERROR: {str(e)[:60]}")
                
                page.close()
            
            context.close()
        
        browser.close()
    
    print(f"\n{'='*70}")
    print(f" ✅ Tests terminés !")
    print(f"{'='*70}\n")


if __name__ == '__main__':
    # URL par défaut
    url = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:5000'
    
    # Mode headless (False pour voir le navigateur)
    headless = len(sys.argv) <= 2 or sys.argv[2].lower() != '--visible'
    
    test_responsive(url, headless=headless)
