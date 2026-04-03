"""
Test overflow table-container
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
    
    # Check table-container overflow - try different selectors
    result = page.evaluate('''() => {
        const selectors = ['.table-container', 'div.table-container', 'table-container'];
        let container = null;
        
        for (const sel of selectors) {
            container = document.querySelector(sel);
            if (container) break;
        }
        
        if (!container) {
            // Fallback: find parent of table
            const table = document.querySelector('table.data-table');
            if (table) container = table.parentElement;
        }
        
        if (!container) return { error: 'container not found' };
        
        const s = window.getComputedStyle(container);
        const table = container.querySelector('table') || container.querySelector('table.data-table');
        
        return {
            containerTag: container.tagName,
            containerClass: container.className,
            overflow: s.overflow,
            overflowX: s.overflowX,
            overflowY: s.overflowY,
            tableWidth: table?.scrollWidth || 0,
            containerWidth: container.clientWidth,
            hasScrollbar: container.scrollWidth > container.clientWidth
        };
    }''')
    
    print("Table container:", result)
    
    browser.close()
