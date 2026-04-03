"""
Test affichage mobile - AD Web Interface
"""
from playwright.sync_api import sync_playwright
import json
import time

with open('test_cookies.json', 'r') as f:
    cookies = json.load(f)

with sync_playwright() as p:
    # Viewport mobile (iPhone 12/13)
    browser = p.chromium.launch(headless=False)
    context = browser.new_context(
        viewport={'width': 390, 'height': 844},
        device_scale_factor=3,
        is_mobile=True,
        has_touch=True,
        storage_state={'cookies': cookies}
    )
    page = context.new_page()
    
    pages_to_test = [
        ('Dashboard', '/dashboard'),
        ('Computers', '/computers'),
        ('Users', '/users'),
    ]
    
    print("\n" + "="*70)
    print(" TEST AFFICHAGE MOBILE (390x844 - iPhone)")
    print("="*70 + "\n")
    
    for name, url in pages_to_test:
        print(f"📱 Test: {name} ({url})")
        
        page.goto(f'http://localhost:5000{url}', wait_until='networkidle', timeout=15000)
        time.sleep(1)
        
        # Check overflow
        overflow = page.evaluate('''() => {
            return {
                horizontal: document.documentElement.scrollWidth > window.innerWidth,
                vertical: document.documentElement.scrollHeight > window.innerHeight,
                diffX: document.documentElement.scrollWidth - window.innerWidth,
                diffY: document.documentElement.scrollHeight - window.innerHeight
            };
        }''')
        
        if overflow['horizontal']:
            print(f"   ❌ Overflow horizontal: +{overflow['diffX']}px")
        else:
            print(f"   ✅ Pas d'overflow horizontal")
        
        # Check éléments coupés
        cut_elements = page.evaluate('''() => {
            const cuts = [];
            document.querySelectorAll('h1, h2, .btn, th, td, .stat-card').forEach(el => {
                const rect = el.getBoundingClientRect();
                if (rect.right > window.innerWidth - 10) {
                    cuts.push({
                        type: el.tagName,
                        text: el.textContent?.substring(0, 20) || '',
                        width: rect.width
                    });
                }
            });
            return cuts.slice(0, 10);
        }''')
        
        if cut_elements:
            print(f"   ❌ {len(cut_elements)} élément(s) coupé(s)")
            for el in cut_elements[:3]:
                print(f"      - {el['type']}: \"{el['text']}\" ({el['width']}px)")
        else:
            print(f"   ✅ Aucun élément coupé")
        
        # Check sidebar
        sidebar_check = page.evaluate('''() => {
            const sidebar = document.querySelector('.sidebar');
            if (!sidebar) return { error: 'not found' };
            const styles = window.getComputedStyle(sidebar);
            const rect = sidebar.getBoundingClientRect();
            return {
                transform: styles.transform,
                visible: rect.left < window.innerWidth,
                rect: { left: rect.left, width: rect.width }
            };
        }''')
        
        if 'error' not in sidebar_check:
            if sidebar_check['transform'] == 'none' or sidebar_check['visible']:
                print(f"   ⚠️  Sidebar: visible (peut-être ouverte)")
            else:
                print(f"   ✅ Sidebar: fermée")
        
        # Screenshot
        page.screenshot(path=f'logs/screenshots/mobile_{name.lower()}.png')
        print(f"   📸 logs/screenshots/mobile_{name.lower()}.png")
        print()
    
    browser.close()
    
    print("="*70)
    print(" TESTS MOBILES TERMINÉS")
    print("="*70 + "\n")
