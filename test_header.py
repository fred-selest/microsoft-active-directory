"""
Test affichage header tableau
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
    
    # Check thead
    result = page.evaluate('''() => {
        const thead = document.querySelector('.data-table thead');
        if (!thead) return { error: 'thead not found' };
        
        const s = window.getComputedStyle(thead);
        const ths = document.querySelectorAll('.data-table thead th');
        
        return {
            display: s.display,
            visibility: s.visibility,
            opacity: s.opacity,
            position: s.position,
            top: s.top,
            zIndex: s.zIndex,
            backgroundColor: s.backgroundColor,
            color: s.color,
            height: s.height,
            thCount: ths.length,
            thText: Array.from(ths).map(th => th.textContent.trim())
        };
    }''')
    
    print("Thead styles:", result)
    
    # Screenshot
    page.screenshot(path='logs/screenshots/computers_header.png', clip={'x': 0, 'y': 0, 'width': 1920, 'height': 200})
    print("\nScreenshot: logs/screenshots/computers_header.png")
    
    browser.close()
