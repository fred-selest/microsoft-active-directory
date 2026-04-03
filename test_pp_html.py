"""
Check password-policy HTML structure
"""
from playwright.sync_api import sync_playwright
import json
import time

with open('test_cookies.json', 'r') as f:
    cookies = json.load(f)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    context = browser.new_context(
        viewport={'width': 390, 'height': 844},
        is_mobile=True,
        has_touch=True,
        storage_state={'cookies': cookies}
    )
    page = context.new_page()
    
    page.goto('http://localhost:5000/password-policy', wait_until='networkidle', timeout=15000)
    time.sleep(2)
    
    # Get HTML structure
    html = page.evaluate('''() => {
        const content = document.querySelector('[block="content"]') || document.querySelector('.main-content');
        if (!content) return { error: 'content not found' };
        
        // Get all classes in the page
        const allClasses = Array.from(document.querySelectorAll('[class]'))
            .map(el => el.className)
            .filter(c => c.includes('policy') || c.includes('section') || c.includes('container'));
        
        // Check table structure
        const tables = document.querySelectorAll('table');
        const tableInfo = Array.from(tables).map(t => ({
            class: t.className,
            rows: t.querySelectorAll('tr').length,
            parent: t.parentElement?.tagName,
            parentClass: t.parentElement?.className
        }));
        
        return {
            classes: allClasses.slice(0, 20),
            tables: tableInfo,
            url: window.location.href
        };
    }''')
    
    print("Classes found:", html.get('classes', []))
    print("\nTables:", html.get('tables', []))
    
    browser.close()
