"""
Test sticky header avec scroll - version avec cookies
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
    
    # Position avant scroll
    before = page.evaluate('''() => {
        const thead = document.querySelector('.data-table thead');
        if (!thead) return { error: 'not found' };
        const rect = thead.getBoundingClientRect();
        return { top: rect.top, height: rect.height };
    }''')
    
    print(f"Avant scroll: top = {before.get('top', 'N/A')}px")
    
    # Scroll de 300px
    page.evaluate('window.scrollBy(0, 300)')
    time.sleep(1)
    
    # Position après scroll
    after = page.evaluate('''() => {
        const thead = document.querySelector('.data-table thead');
        if (!thead) return { error: 'not found' };
        const rect = thead.getBoundingClientRect();
        return { top: rect.top, height: rect.height };
    }''')
    
    print(f"Après scroll (300px): top = {after.get('top', 'N/A')}px")
    
    if 'top' in after:
        if abs(after['top'] - 60) < 10:
            print("✅ Sticky fonctionne ! Header collé à ~60px")
        elif after['top'] < before.get('top', 9999):
            print(f"⚠️  Sticky partiel (devrait être à 60px, est à {after['top']}px)")
        else:
            print(f"❌ Sticky ne fonctionne pas (top: {after['top']}px)")
    
    # Screenshot
    page.screenshot(path='logs/screenshots/sticky_after.png', clip={'x': 0, 'y': 0, 'width': 1920, 'height': 300})
    print("\nScreenshot: logs/screenshots/sticky_after.png")
    
    browser.close()
