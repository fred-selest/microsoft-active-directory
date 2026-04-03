"""
Check table HTML structure
"""
from playwright.sync_api import sync_playwright
import json
import time

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
    
    # Get table structure
    result = page.evaluate('''() => {
        const table = document.querySelector('table');
        if (!table) return { error: 'no table found' };
        
        return {
            class: table.className,
            hasThead: !!table.querySelector('thead'),
            hasTbody: !!table.querySelector('tbody'),
            thCount: table.querySelectorAll('th').length,
            theadClass: table.querySelector('thead')?.className || 'none',
            innerHTML: table.innerHTML.substring(0, 500)
        };
    }''')
    
    print(result)
    
    browser.close()
