"""
Test alerts - Check session role
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
    
    print("\n📄 Test - Check session\n")
    
    page.goto('http://localhost:5000/dashboard', wait_until='networkidle', timeout=15000)
    time.sleep(1)
    
    # Check if admin links are visible on dashboard
    dashboard_admin_links = page.evaluate('''() => {
        const links = document.querySelectorAll('.sidebar-link[href*="admin"], .sidebar-link[href*="tools"]');
        return links.length;
    }''')
    
    print(f"Dashboard admin/tool links: {dashboard_admin_links}")
    
    # Now go to alerts
    page.goto('http://localhost:5000/alerts', wait_until='networkidle', timeout=15000)
    time.sleep(1)
    
    alerts_admin_links = page.evaluate('''() => {
        const links = document.querySelectorAll('.sidebar-link[href*="admin"], .sidebar-link[href*="tools"]');
        return links.length;
    }''')
    
    print(f"Alerts admin/tool links: {alerts_admin_links}")
    
    browser.close()
    
    if dashboard_admin_links > 0 and alerts_admin_links == 0:
        print("\n⚠️  PROBLEM: Menu is different on alerts page!")
    else:
        print("\n✅ Menu is consistent")
