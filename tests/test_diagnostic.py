"""
Test /diagnostic page
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
    
    print("\n📄 Test /diagnostic - Desktop\n")
    
    page.goto('http://localhost:5000/diagnostic', wait_until='networkidle', timeout=15000)
    time.sleep(2)
    
    # Get page content
    content = page.evaluate('''() => {
        const main = document.querySelector('.main-content');
        return {
            title: document.querySelector('h2')?.textContent || 'N/A',
            hasTable: !!document.querySelector('table'),
            innerText: main?.innerText?.substring(0, 800) || 'N/A'
        };
    }''')
    
    print(f"Title: {content['title']}")
    print(f"Has table: {content['hasTable']}")
    print(f"Content preview: {content['innerText'][:300]}...")
    
    # Check overflow
    overflow = page.evaluate('''() => {
        return document.documentElement.scrollWidth > window.innerWidth;
    }''')
    print(f"\nOverflow desktop: {overflow}")
    
    # Mobile test
    print("\n📱 Mobile test (390x844)...")
    page.set_viewport_size({'width': 390, 'height': 844})
    time.sleep(1)
    
    overflow_mobile = page.evaluate('''() => {
        return document.documentElement.scrollWidth > window.innerWidth;
    }''')
    
    if overflow_mobile:
        diff = page.evaluate('document.documentElement.scrollWidth - window.innerWidth')
        print(f"Overflow mobile: +{diff}px")
        
        # Find wide elements
        wide = page.evaluate('''() => {
            const result = [];
            document.querySelectorAll('*').forEach(el => {
                const rect = el.getBoundingClientRect();
                if (rect.width > 390) {
                    result.push({ tag: el.tagName, class: el.className, width: rect.width });
                }
            });
            return result.slice(0, 5);
        }''')
        print("Éléments larges:")
        for el in wide:
            print(f"  - {el['tag']}.{el['class']}: {el['width']}px")
    else:
        print("Overflow mobile: OK")
    
    # Screenshots
    page.set_viewport_size({'width': 1920, 'height': 1080})
    page.screenshot(path='logs/screenshots/diagnostic_desktop.png')
    
    page.set_viewport_size({'width': 390, 'height': 844})
    page.screenshot(path='logs/screenshots/diagnostic_mobile.png')
    
    print("\n📸 logs/screenshots/diagnostic_*.png")
    
    browser.close()
    print("\n✅ Test terminé")
