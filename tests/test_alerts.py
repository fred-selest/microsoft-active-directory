"""
Check alerts page content
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
    
    print("\n📄 Test /alerts\n")
    
    page.goto('http://localhost:5000/alerts', wait_until='networkidle', timeout=15000)
    time.sleep(2)
    
    # Get page content
    content = page.evaluate('''() => {
        const main = document.querySelector('.main-content');
        return {
            title: document.querySelector('h2')?.textContent || 'N/A',
            innerText: main?.innerText?.substring(0, 1500) || 'N/A'
        };
    }''')
    
    print(f"Title: {content['title']}")
    print(f"\nContent:\n{content['innerText']}")
    
    # Check mobile
    page.set_viewport_size({'width': 390, 'height': 844})
    time.sleep(1)
    
    overflow = page.evaluate('''() => {
        return document.documentElement.scrollWidth > window.innerWidth;
    }''')
    
    print(f"\n📱 Mobile overflow: {overflow}")
    
    # Screenshot
    page.screenshot(path='logs/screenshots/alerts.png')
    print("\n📸 logs/screenshots/alerts.png")
    
    browser.close()
