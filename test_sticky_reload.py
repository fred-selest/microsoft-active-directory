"""
Test sticky header avec hard reload
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
    
    # Hard reload
    print("Hard reload...")
    page.keyboard.press('Control+Shift+R')
    time.sleep(2)
    
    # Scroll pour vérifier sticky
    page.evaluate('window.scrollBy(0, 300)')
    time.sleep(1)
    
    # Vérifier position du thead
    result = page.evaluate('''() => {
        const thead = document.querySelector('.data-table thead');
        if (!thead) return { error: 'thead not found' };
        
        const th = thead.querySelector('th');
        if (!th) return { error: 'th not found' };
        
        const thRect = th.getBoundingClientRect();
        const theadRect = thead.getBoundingClientRect();
        
        return {
            theadTop: theadRect.top,
            thTop: thRect.top,
            thHeight: thRect.height,
            expectedTop: 60
        };
    }''')
    
    print("Position:", result)
    
    if 'thTop' in result:
        if abs(result['thTop'] - 60) < 10:
            print("✅ Sticky fonctionne!")
        else:
            print(f"❌ Sticky ne fonctionne pas (top: {result['thTop']}px)")
    
    # Screenshot
    page.screenshot(path='logs/screenshots/sticky_test.png', clip={'x': 0, 'y': 0, 'width': 1920, 'height': 300})
    print("Screenshot: logs/screenshots/sticky_test.png")
    
    browser.close()
