"""
Check password-policy content
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
    
    # Get page content
    content = page.evaluate('''() => {
        const main = document.querySelector('.main-content');
        return {
            innerText: main?.innerText?.substring(0, 1000) || 'N/A',
            innerHTML: main?.innerHTML?.substring(0, 2000) || 'N/A'
        };
    }''')
    
    print("Page content (text):")
    print(content['innerText'][:500])
    print("\n\nPage content (HTML snippets):")
    print(content['innerHTML'][:1000])
    
    browser.close()
