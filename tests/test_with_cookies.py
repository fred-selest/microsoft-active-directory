"""
Test CSS avec cookies de session - AD Web Interface
Utilise les cookies sauvegardés pour éviter la connexion manuelle
"""
from playwright.sync_api import sync_playwright
import json
import os
import time

os.makedirs('logs/screenshots', exist_ok=True)

def load_cookies():
    """Charge les cookies depuis le fichier JSON."""
    if not os.path.exists('test_cookies.json'):
        return None
    with open('test_cookies.json', 'r', encoding='utf-8') as f:
        return json.load(f)

def test_page(page_name, page_url):
    """Test une page avec cookies."""
    cookies = load_cookies()
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        
        context = browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            storage_state={'cookies': cookies} if cookies else None
        )
        page = context.new_page()
        
        print(f"\n📄 Test: {page_name} ({page_url})")
        
        try:
            page.goto(f'http://localhost:5000{page_url}', wait_until='networkidle', timeout=15000)
            
            # Vérifier si redirigé vers login
            if '/connect' in page.url:
                print("   ❌ Session expirée ou cookies invalides")
                print("   Relancez: python save_cookies.py")
                browser.close()
                return False
            
            print("   ✅ Page chargée")
            
            # Screenshot
            page.screenshot(path=f'logs/screenshots/{page_name}.png', full_page=True)
            print(f"   📸 Screenshot: logs/screenshots/{page_name}.png")
            
            # Check overflow
            overflow = page.evaluate('''() => {
                return document.documentElement.scrollWidth > window.innerWidth;
            }''')
            
            if overflow:
                diff = page.evaluate('''() => {
                    return document.documentElement.scrollWidth - window.innerWidth;
                }''')
                print(f"   ❌ OVERFLOW: +{diff}px")
            else:
                print(f"   ✅ Pas d'overflow")
            
            # Check header tableau si applicable
            if 'computers' in page_url or 'users' in page_url or 'groups' in page_url:
                thead_check = page.evaluate('''() => {
                    const thead = document.querySelector('.data-table thead');
                    if (!thead) return { error: 'not found' };
                    const rect = thead.getBoundingClientRect();
                    // Header est visible s'il est dans le viewport ou proche
                    const isVisible = rect.top >= -50 && rect.top < window.innerHeight;
                    const isSticky = rect.top >= 55 && rect.top <= 65; // Sticky à ~60px
                    return {
                        top: rect.top,
                        visible: isVisible,
                        sticky: isSticky,
                        height: rect.height
                    };
                }''')
                
                if 'error' in thead_check:
                    print(f"   ⚠️  Header: {thead_check['error']}")
                elif not thead_check['visible']:
                    print(f"   ❌ Header invisible (top: {thead_check['top']}px)")
                elif thead_check['sticky']:
                    print(f"   ✅ Header visible et sticky (top: {thead_check['top']}px)")
                else:
                    print(f"   ⚠️  Header visible mais pas sticky (top: {thead_check['top']}px)")
            
            browser.close()
            return True
            
        except Exception as e:
            print(f"   ❌ Erreur: {str(e)[:80]}")
            browser.close()
            return False

# Pages à tester
pages = [
    ('dashboard', '/dashboard'),
    ('computers', '/computers'),
    ('users', '/users'),
    ('groups', '/groups'),
]

print("\n" + "="*70)
print(" TEST CSS AVEC SESSION SAUVEGARDÉE")
print("="*70)

if not load_cookies():
    print("\n❌ Cookies non trouvés!")
    print("   Lancez d'abord: python save_cookies.py")
    exit(1)

print("\n✅ Cookies chargés")

for name, url in pages:
    test_page(name, url)
    time.sleep(1)

print("\n" + "="*70)
print(" TESTS TERMINÉS")
print("="*70 + "\n")
