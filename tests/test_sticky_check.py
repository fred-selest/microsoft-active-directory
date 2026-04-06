"""
Test sticky header - detailed
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
    
    # Check thead et th
    result = page.evaluate('''() => {
        const thead = document.querySelector('.data-table thead');
        const th = document.querySelector('.data-table thead th');
        
        if (!thead) return { error: 'thead not found' };
        if (!th) return { error: 'th not found' };
        
        const theadStyles = window.getComputedStyle(thead);
        const thStyles = window.getComputedStyle(th);
        const thRect = th.getBoundingClientRect();
        
        return {
            thead: {
                position: theadStyles.position,
                top: theadStyles.top,
                display: theadStyles.display
            },
            th: {
                position: thStyles.position,
                top: thStyles.top,
                zIndex: thStyles.zIndex,
                rect: { top: thRect.top, height: thRect.height }
            }
        };
    }''')
    
    print(result)
    
    # Scroll et recheck
    page.evaluate('window.scrollBy(0, 200)')
    time.sleep(1)
    
    result2 = page.evaluate('''() => {
        const th = document.querySelector('.data-table thead th');
        if (!th) return { error: 'th not found' };
        const rect = th.getBoundingClientRect();
        return { rect: { top: rect.top, height: rect.height } };
    }''')
    
    print("Après scroll:", result2)
    
    browser.close()
