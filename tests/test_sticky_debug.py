"""
Debug sticky header - inspection détaillée
"""
from playwright.sync_api import sync_playwright
import json
import time

# Charger les cookies
with open('test_cookies.json', 'r') as f:
    cookies = json.load(f)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    context = browser.new_context(
        viewport={'width': 1920, 'height': 1080},
        storage_state={'cookies': cookies}
    )
    page = context.new_page()
    
    page.goto('http://localhost:5000/computers', wait_until='networkidle')
    time.sleep(2)
    
    # Inspection complète
    result = page.evaluate('''() => {
        const thead = document.querySelector('.data-table thead');
        const th = document.querySelector('.data-table thead th');
        const container = document.querySelector('.table-container');
        const main = document.querySelector('.main-content');
        
        if (!thead || !th || !container) {
            return { error: 'Elements not found' };
        }
        
        const theadStyles = window.getComputedStyle(thead);
        const thStyles = window.getComputedStyle(th);
        const containerStyles = window.getComputedStyle(container);
        const mainStyles = window.getComputedStyle(main);
        
        const theadRect = thead.getBoundingClientRect();
        const thRect = th.getBoundingClientRect();
        
        return {
            thead: {
                position: theadStyles.position,
                top: theadStyles.top,
                zIndex: theadStyles.zIndex,
                rect: { top: theadRect.top, height: theadRect.height }
            },
            th: {
                position: thStyles.position,
                top: thStyles.top,
                zIndex: thStyles.zIndex,
                background: thStyles.backgroundColor,
                rect: { top: thRect.top, height: thRect.height }
            },
            container: {
                overflow: containerStyles.overflow,
                overflowX: containerStyles.overflowX,
                position: containerStyles.position
            },
            main: {
                position: mainStyles.position,
                marginTop: mainStyles.marginTop,
                paddingTop: mainStyles.paddingTop
            },
            scrollY: window.scrollY
        };
    }''')
    
    print("=== INSPECTION STICKY HEADER ===\n")
    print("THEAD:")
    print(f"  position: {result['thead']['position']}")
    print(f"  top: {result['thead']['top']}")
    print(f"  rect.top: {result['thead']['rect']['top']}px")
    
    print("\nTH (première cellule header):")
    print(f"  position: {result['th']['position']}")
    print(f"  top: {result['th']['top']}")
    print(f"  rect.top: {result['th']['rect']['top']}px")
    
    print("\nCONTAINER:")
    print(f"  overflow: {result['container']['overflow']}")
    print(f"  overflowX: {result['container']['overflowX']}")
    print(f"  position: {result['container']['position']}")
    
    print("\nMAIN:")
    print(f"  position: {result['main']['position']}")
    print(f"  marginTop: {result['main']['marginTop']}")
    print(f"  paddingTop: {result['main']['paddingTop']}")
    
    print(f"\nSCROLL Y: {result['scrollY']}px")
    
    browser.close()
