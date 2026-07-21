"""
Test alerts mobile detailed
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
    
    page.goto('http://localhost:5000/alerts', wait_until='networkidle', timeout=15000)
    time.sleep(2)
    
    # Check what's causing overflow
    result = page.evaluate('''() => {
        const wide = [];
        document.querySelectorAll('*').forEach(el => {
            const rect = el.getBoundingClientRect();
            if (rect.width > 390) {
                wide.push({
                    tag: el.tagName,
                    class: el.className,
                    width: rect.width
                });
            }
        });
        return wide.slice(0, 10);
    }''')
    
    print("Éléments trop larges (> 390px):")
    for el in result:
        print(f"  - {el['tag']}.{el['class']}: {el['width']}px")
    
    browser.close()
