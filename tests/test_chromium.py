"""
Test responsive avec Chromium - AD Web Interface
"""
from playwright.sync_api import sync_playwright
import time

print("\n" + "="*70)
print(" TEST RESPONSIVE AVEC CHROMIUM")
print("="*70 + "\n")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    
    tests = [
        {'name': 'Desktop', 'width': 1920, 'height': 1080},
        {'name': 'Tablette', 'width': 768, 'height': 1024},
        {'name': 'Mobile', 'width': 390, 'height': 844},
    ]
    
    for test in tests:
        print(f"📱 Test {test['name']} ({test['width']}x{test['height']})...")
        
        page = browser.new_page(viewport={'width': test['width'], 'height': test['height']})
        
        try:
            page.goto('http://localhost:5000/connect', wait_until='networkidle', timeout=15000)
            
            # Vérifier overflow horizontal
            overflow = page.evaluate('document.documentElement.scrollWidth > document.documentElement.clientWidth')
            
            # Vérifier éléments coupés
            cut_elements = page.evaluate('''() => {
                const cuts = [];
                document.querySelectorAll('h1, h2, .btn').forEach(el => {
                    const rect = el.getBoundingClientRect();
                    if (rect.right > window.innerWidth) {
                        cuts.push(el.tagName);
                    }
                });
                return cuts;
            }''')
            
            # Screenshot
            page.screenshot(path=f'logs/test_{test["name"].lower()}.png')
            
            print(f"   ✅ Screenshot: logs/test_{test['name'].lower()}.png")
            
            if overflow:
                print(f"   ❌ OVERFLOW HORIZONTAL!")
            else:
                print(f"   ✅ Pas de scroll horizontal")
            
            if cut_elements:
                print(f"   ❌ Éléments coupés: {cut_elements}")
            else:
                print(f"   ✅ Aucun élément coupé")
                
        except Exception as e:
            print(f"   ❌ Erreur: {str(e)[:100]}")
        
        page.close()
        print()
    
    browser.close()

print("="*70)
print(" TESTS TERMINÉS")
print("="*70 + "\n")
