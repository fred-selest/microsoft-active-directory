"""
Test Password Audit page with progress bar
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
    
    print("\n📄 Test /password-audit - Progress Bar\n")
    
    page.goto('http://localhost:5000/password-audit', wait_until='networkidle', timeout=15000)
    time.sleep(2)
    
    # Check if page loaded
    title = page.evaluate('document.querySelector("h2")?.textContent')
    print(f"Page title: {title}")
    
    # Check if progress container exists
    has_progress = page.evaluate('!!document.getElementById("audit-progress-container")')
    print(f"Progress container exists: {has_progress}")
    
    # Check initial state
    progress_display = page.evaluate('''() => {
        const container = document.getElementById("audit-progress-container");
        return container ? container.style.display : "not found";
    }''')
    print(f"Initial progress display: {progress_display}")
    
    # Click the audit button
    print("\n🔍 Clicking audit button...")
    page.click('#audit-start-btn')
    
    # Monitor progress
    print("\n📊 Monitoring progress...")
    for i in range(10):
        time.sleep(0.5)
        progress = page.evaluate('''() => {
            const bar = document.getElementById("audit-progress-bar");
            const text = document.getElementById("audit-progress-text");
            const msg = document.getElementById("audit-progress-message");
            return {
                width: bar ? bar.style.width : "N/A",
                text: text ? text.textContent : "N/A",
                msg: msg ? msg.textContent : "N/A"
            };
        }''')
        print(f"   Progress: {progress['width']} - {progress['text']} - {progress['msg']}")
        
        # Check if completed
        if progress['text'] == '100%':
            print("\n✅ Audit completed!")
            break
    
    # Wait for results to display
    time.sleep(2)
    
    # Check if dashboard is visible
    dashboard_visible = page.evaluate('''() => {
        const dashboard = document.getElementById("audit-dashboard");
        return dashboard && dashboard.style.display !== "none";
    }''')
    print(f"\nDashboard visible: {dashboard_visible}")
    
    # Check progress bar hidden after completion
    progress_hidden = page.evaluate('''() => {
        const container = document.getElementById("audit-progress-container");
        return container && container.style.display === "none";
    }''')
    print(f"Progress hidden after completion: {progress_hidden}")
    
    # Screenshot
    page.screenshot(path='logs/screenshots/password_audit.png')
    print("\n📸 logs/screenshots/password_audit.png")
    
    browser.close()
    print("\n✅ Test terminé")
