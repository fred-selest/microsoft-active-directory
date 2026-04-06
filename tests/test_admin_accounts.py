"""
Test P1 - Comptes Administrateurs
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
    
    print("\n📄 Test Password Audit - Comptes Admins\n")
    
    page.goto('http://localhost:5000/password-audit', wait_until='networkidle', timeout=15000)
    time.sleep(2)
    
    # Click audit button
    print("🔍 Lancement de l'audit...")
    page.click('#audit-start-btn')
    
    # Wait for audit to complete
    time.sleep(10)
    
    # Check if admin section exists and is visible
    admin_section = page.evaluate('''() => {
        const section = document.getElementById('admin-accounts-section');
        if (!section) return { error: 'section not found' };
        return {
            display: section.style.display,
            hasContent: section.innerHTML.length > 0
        };
    }''')
    
    print(f"\nAdmin section: {admin_section}")
    
    # Check if data was returned
    admin_data = page.evaluate('''() => {
        // Check console logs for admin_weak_accounts
        return window.auditData ? window.auditData.admin_weak_accounts : 'not available';
    }''')
    
    print(f"Admin data: {admin_data}")
    
    # Screenshot
    page.screenshot(path='logs/screenshots/password_audit_admin.png')
    print("\n📸 logs/screenshots/password_audit_admin.png")
    
    browser.close()
    print("\n✅ Test terminé")
