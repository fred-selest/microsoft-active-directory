"""
Check parent elements of thead for sticky issues
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
    
    # Check all parent elements
    result = page.evaluate('''() => {
        const thead = document.querySelector('.data-table thead');
        const table = document.querySelector('.data-table');
        const container = document.querySelector('.table-container');
        const main = document.querySelector('.main-content');
        
        const elements = [
            { name: 'thead', el: thead },
            { name: 'table', el: table },
            { name: 'container', el: container },
            { name: 'main', el: main },
            { name: 'body', el: document.body },
            { name: 'html', el: document.documentElement }
        ];
        
        return elements.map(item => {
            if (!item.el) return { name: item.name, error: 'not found' };
            const s = window.getComputedStyle(item.el);
            return {
                name: item.name,
                overflow: s.overflow,
                overflowX: s.overflowX,
                overflowY: s.overflowY,
                position: s.position,
                transform: s.transform,
                perspective: s.perspective
            };
        });
    }''')
    
    print("Parent elements check:")
    for item in result:
        print(f"\n{item['name']}:")
        if 'error' in item:
            print(f"  Error: {item['error']}")
        else:
            print(f"  overflow: {item['overflow']}")
            print(f"  overflowX: {item['overflowX']}")
            print(f"  position: {item['position']}")
            print(f"  transform: {item['transform']}")
    
    browser.close()
