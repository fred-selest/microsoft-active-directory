"""
Test expiring mobile
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
    
    print("\n📱 Test /expiring mobile\n")
    
    page.goto('http://localhost:5000/expiring', wait_until='networkidle', timeout=15000)
    time.sleep(2)
    
    # Check overflow
    overflow = page.evaluate('''() => {
        return {
            horizontal: document.documentElement.scrollWidth > window.innerWidth,
            diff: document.documentElement.scrollWidth - window.innerWidth
        };
    }''')
    
    print(f"Overflow: {'+' + str(overflow['diff']) + 'px' if overflow['horizontal'] else 'OK'}")
    
    # Check elements
    content = page.evaluate('''() => {
        const tables = document.querySelectorAll('table');
        const cards = document.querySelectorAll('.stat-card');
        return {
            tablesCount: tables.length,
            cardsCount: cards.length,
            tables: Array.from(tables).map(t => ({
                width: t.getBoundingClientRect().width,
                class: t.className
            }))
        };
    }''')
    
    print(f"Tables: {content['tablesCount']}")
    print(f"Cards: {content['cardsCount']}")
    if content['tables']:
        for t in content['tables']:
            print(f"  - {t['class']}: {t['width']}px")
    
    # Screenshot
    page.screenshot(path='logs/screenshots/mobile_expiring.png')
    print("\n📸 logs/screenshots/mobile_expiring.png")
    
    browser.close()
