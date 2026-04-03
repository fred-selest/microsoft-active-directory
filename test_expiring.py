"""
Test expiring page
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
    
    print("\n📄 Test /expiring\n")
    
    page.goto('http://localhost:5000/expiring', wait_until='networkidle', timeout=15000)
    time.sleep(2)
    
    # Check page content
    content = page.evaluate('''() => {
        const main = document.querySelector('.main-content');
        return {
            title: document.querySelector('h2')?.textContent || 'N/A',
            hasTable: !!document.querySelector('table'),
            hasCards: !!document.querySelector('.stat-card'),
            innerText: main?.innerText?.substring(0, 500) || 'N/A'
        };
    }''')
    
    print(f"Title: {content['title']}")
    print(f"Has table: {content['hasTable']}")
    print(f"Has cards: {content['hasCards']}")
    print(f"Content preview: {content['innerText'][:200]}...")
    
    # Check overflow
    overflow = page.evaluate('''() => {
        return document.documentElement.scrollWidth > window.innerWidth;
    }''')
    
    print(f"\nOverflow: {overflow}")
    
    # Screenshot
    page.screenshot(path='logs/screenshots/expiring.png')
    print("\n📸 logs/screenshots/expiring.png")
    
    browser.close()
