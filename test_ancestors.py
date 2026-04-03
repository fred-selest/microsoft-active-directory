"""
Check all ancestors for sticky blocking
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
    
    result = page.evaluate('''() => {
        const th = document.querySelector('.data-table thead th');
        if (!th) return { error: 'th not found' };
        
        const ancestors = [];
        let el = th.parentElement;
        
        while (el && el !== document) {
            const s = window.getComputedStyle(el);
            if (s.overflow !== 'visible' || s.position !== 'static' || s.transform !== 'none') {
                ancestors.push({
                    tag: el.tagName,
                    class: el.className,
                    overflow: s.overflow,
                    overflowX: s.overflowX,
                    position: s.position,
                    transform: s.transform
                });
            }
            el = el.parentElement;
        }
        
        return ancestors;
    }''')
    
    print("Ancestors with non-default values:")
    for a in result:
        print(f"\n{a['tag']}.{a['class']}:")
        print(f"  overflow: {a['overflow']}")
        print(f"  overflowX: {a['overflowX']}")
        print(f"  position: {a['position']}")
        print(f"  transform: {a['transform']}")
    
    browser.close()
