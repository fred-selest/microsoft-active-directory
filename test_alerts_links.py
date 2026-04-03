"""
Test /alerts - Menu links content
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
    
    print("\n📄 Test /alerts - Menu links content\n")
    
    page.goto('http://localhost:5000/alerts', wait_until='networkidle', timeout=15000)
    time.sleep(2)
    
    # Get all sidebar links
    links = page.evaluate('''() => {
        const sidebarLinks = document.querySelectorAll('.sidebar-link');
        return Array.from(sidebarLinks).map(link => ({
            text: link.textContent.trim(),
            href: link.href,
            active: link.classList.contains('active')
        }));
    }''')
    
    print("Sidebar links:")
    for link in links:
        active = " (active)" if link['active'] else ""
        print(f"  - {link['text']}{active}")
    
    # Get sidebar sections
    sections = page.evaluate('''() => {
        const labels = document.querySelectorAll('.sidebar-label');
        return Array.from(labels).map(l => l.textContent.trim());
    }''')
    
    print(f"\nSidebar sections: {sections}")
    
    browser.close()
    print("\n✅ Test terminé")
