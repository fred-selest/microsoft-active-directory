"""
Compare menus: alerts vs dashboard
"""
from playwright.sync_api import sync_playwright
import json
import time

with open('test_cookies.json', 'r') as f:
    cookies = json.load(f)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    
    # Test dashboard
    context = browser.new_context(
        viewport={'width': 1920, 'height': 1080},
        storage_state={'cookies': cookies}
    )
    page = context.new_page()
    
    print("="*60)
    print("DASHBOARD MENU:")
    print("="*60)
    page.goto('http://localhost:5000/dashboard', wait_until='networkidle', timeout=15000)
    time.sleep(1)
    
    dashboard_links = page.evaluate('''() => {
        return Array.from(document.querySelectorAll('.sidebar-link')).map(l => l.textContent.trim());
    }''')
    dashboard_sections = page.evaluate('''() => {
        return Array.from(document.querySelectorAll('.sidebar-label')).map(l => l.textContent.trim());
    }''')
    
    print(f"Sections: {dashboard_sections}")
    print(f"Links count: {len(dashboard_links)}")
    
    # Test alerts
    print("\n" + "="*60)
    print("ALERTS MENU:")
    print("="*60)
    page.goto('http://localhost:5000/alerts', wait_until='networkidle', timeout=15000)
    time.sleep(1)
    
    alerts_links = page.evaluate('''() => {
        return Array.from(document.querySelectorAll('.sidebar-link')).map(l => l.textContent.trim());
    }''')
    alerts_sections = page.evaluate('''() => {
        return Array.from(document.querySelectorAll('.sidebar-label')).map(l => l.textContent.trim());
    }''')
    
    print(f"Sections: {alerts_sections}")
    print(f"Links count: {len(alerts_links)}")
    
    # Compare
    print("\n" + "="*60)
    print("DIFFERENCE:")
    print("="*60)
    missing = set(dashboard_links) - set(alerts_links)
    if missing:
        print(f"Missing links: {missing}")
    else:
        print("Menus are identical")
    
    browser.close()
