"""
Test alerts - Check user permissions
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
    
    print("\n📄 Test /alerts - User permissions\n")
    
    page.goto('http://localhost:5000/alerts', wait_until='networkidle', timeout=15000)
    time.sleep(2)
    
    # Check what variables are available
    context_vars = page.evaluate('''() => {
        // This won't work directly, but we can check rendered content
        const sidebar = document.querySelector('.sidebar');
        const sections = sidebar.querySelectorAll('.sidebar-section');
        const adminLinks = sidebar.querySelectorAll('.sidebar-link[href*="admin"]');
        const toolLinks = sidebar.querySelectorAll('.sidebar-link[href*="tools"]');
        
        return {
            sectionsCount: sections.length,
            adminLinksCount: adminLinks.length,
            toolLinksCount: toolLinks.length,
            sidebarHtml: sidebar.innerHTML.substring(0, 500)
        };
    }''')
    
    print(f"Sidebar sections: {context_vars['sectionsCount']}")
    print(f"Admin links: {context_vars['adminLinksCount']}")
    print(f"Tool links: {context_vars['toolLinksCount']}")
    
    browser.close()
    print("\n✅ Test terminé")
