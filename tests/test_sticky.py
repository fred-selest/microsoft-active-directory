"""
Test sticky header - Scroll et visibilité
"""
from playwright.sync_api import sync_playwright
import time

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page(viewport={'width': 1920, 'height': 1080})
    
    page.goto('http://localhost:5000/computers', wait_until='networkidle', timeout=15000)
    
    if '/connect' in page.url:
        print("Connectez-vous manuellement...")
        for i in range(15, 0, -1):
            print(f"{i}s...", end='\r')
            time.sleep(1)
        page.goto('http://localhost:5000/computers', wait_until='networkidle', timeout=15000)
    
    time.sleep(2)
    
    # Screenshot avant scroll
    page.screenshot(path='logs/screenshots/before_scroll.png')
    print("Screenshot avant scroll: logs/screenshots/before_scroll.png")
    
    # Scroll vers le bas
    page.evaluate('window.scrollBy(0, 300)')
    time.sleep(1)
    
    # Screenshot après scroll
    page.screenshot(path='logs/screenshots/after_scroll.png')
    print("Screenshot après scroll: logs/screenshots/after_scroll.png")
    
    # Vérifier position du thead après scroll
    result = page.evaluate('''() => {
        const thead = document.querySelector('.data-table thead');
        const rect = thead.getBoundingClientRect();
        
        return {
            top: rect.top,
            y: rect.y,
            height: rect.height,
            expectedTop: 60  // Devrait être collé à 60px (sous top-bar)
        };
    }''')
    
    print(f"\nPosition du header après scroll:")
    print(f"  top: {result['top']}px (devrait être ~60px)")
    
    if abs(result['top'] - 60) < 5:
        print("  ✅ Sticky fonctionne correctement!")
    else:
        print("  ❌ Sticky ne fonctionne pas comme attendu")
    
    browser.close()
