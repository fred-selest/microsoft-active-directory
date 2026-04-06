"""
Test /alerts menu visibility
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
    
    print("\n📄 Test /alerts - Menu visibility\n")
    
    page.goto('http://localhost:5000/alerts', wait_until='networkidle', timeout=15000)
    time.sleep(2)
    
    # Check sidebar
    sidebar_check = page.evaluate('''() => {
        const sidebar = document.querySelector('.sidebar');
        const sidebarNav = document.querySelector('.sidebar-nav');
        const links = document.querySelectorAll('.sidebar-link');
        
        if (!sidebar) return { error: 'sidebar not found' };
        
        const styles = window.getComputedStyle(sidebar);
        
        return {
            visible: sidebar.offsetLeft < 300,  // Should be at left: 0
            transform: styles.transform,
            display: styles.display,
            linksCount: links.length,
            navHeight: sidebarNav ? sidebarNav.scrollHeight : 0
        };
    }''')
    
    print(f"Sidebar: {sidebar_check}")
    
    # Check topbar
    topbar_check = page.evaluate('''() => {
        const topbar = document.querySelector('.top-bar');
        if (!topbar) return { error: 'topbar not found' };
        return {
            visible: topbar.offsetHeight > 0,
            height: topbar.offsetHeight
        };
    }''')
    
    print(f"Topbar: {topbar_check}")
    
    # Scroll down and check if menu stays visible
    page.evaluate('window.scrollTo(0, 500)')
    time.sleep(1)
    
    sidebar_after_scroll = page.evaluate('''() => {
        const sidebar = document.querySelector('.sidebar');
        if (!sidebar) return { error: 'not found' };
        const styles = window.getComputedStyle(sidebar);
        return {
            offsetLeft: sidebar.offsetLeft,
            transform: styles.transform,
            position: styles.position
        };
    }''')
    
    print(f"\nAfter scroll (500px): {sidebar_after_scroll}")
    
    # Screenshots
    page.screenshot(path='logs/screenshots/alerts_full.png')
    print("\n📸 logs/screenshots/alerts_full.png")
    
    browser.close()
    print("\n✅ Test terminé")
