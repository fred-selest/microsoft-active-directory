"""
Check HTML structure of computers page
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
    
    # Get table structure
    result = page.evaluate('''() => {
        const tables = document.querySelectorAll('table');
        const info = [];
        
        tables.forEach((table, i) => {
            info.push({
                index: i,
                class: table.className,
                id: table.id,
                hasThead: !!table.querySelector('thead'),
                hasTbody: !!table.querySelector('tbody'),
                thCount: table.querySelectorAll('th').length,
                tdCount: table.querySelectorAll('td').length,
                parentClass: table.parentElement?.className || 'none'
            });
        });
        
        return info;
    }''')
    
    print("Tables found:", result)
    
    # Also check for any thead
    theads = page.evaluate('''() => {
        return Array.from(document.querySelectorAll('thead')).map(th => ({
            class: th.className,
            parent: th.parentElement?.tagName,
            parentClass: th.parentElement?.className
        }));
    }''')
    
    print("\nTheads found:", theads)
    
    browser.close()
