"""
Test alerts page implementation
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
        const statCards = document.querySelectorAll('.stat-card, .alert-card');
        return {
            title: document.querySelector('h2')?.textContent || 'N/A',
            statCardsCount: statCards.length,
            hasTable: !!document.querySelector('table'),
            innerText: main?.innerText?.substring(0, 1000) || 'N/A'
        };
    }''')
    
    print(f"Title: {content['title']}")
    print(f"Stat cards: {content['statCardsCount']}")
    print(f"Has table: {content['hasTable']}")
    print(f"Content preview: {content['innerText'][:300]}...")
    
    # Check overflow
    overflow = page.evaluate('''() => {
        return document.documentElement.scrollWidth > window.innerWidth;
    }''')
    print(f"\nOverflow: {overflow}")
    
    # Mobile test
    print("\n📱 Mobile test...")
    page.set_viewport_size({'width': 390, 'height': 844})
    time.sleep(1)
    
    overflow_mobile = page.evaluate('''() => {
        return document.documentElement.scrollWidth > window.innerWidth;
    }''')
    print(f"Mobile overflow: {overflow_mobile}")
    
    # Screenshots
    page.set_viewport_size({'width': 1920, 'height': 1080})
    page.screenshot(path='logs/screenshots/alerts_desktop.png')
    
    page.set_viewport_size({'width': 390, 'height': 844})
    page.screenshot(path='logs/screenshots/alerts_mobile.png')
    
    print("\n📸 logs/screenshots/alerts_desktop.png")
    print("📸 logs/screenshots/alerts_mobile.png")
    
    browser.close()
    print("\n✅ Test terminé")
