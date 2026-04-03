"""
Test specific password-policy page mobile
"""
from playwright.sync_api import sync_playwright
import json
import time

with open('test_cookies.json', 'r') as f:
    cookies = json.load(f)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    context = browser.new_context(
        viewport={'width': 390, 'height': 844},
        device_scale_factor=3,
        is_mobile=True,
        has_touch=True,
        storage_state={'cookies': cookies}
    )
    page = context.new_page()
    
    print("\n📱 Test password-policy mobile (390x844)\n")
    
    page.goto('http://localhost:5000/password-policy', wait_until='networkidle', timeout=15000)
    time.sleep(2)
    
    # Check overflow
    overflow = page.evaluate('''() => {
        return {
            horizontal: document.documentElement.scrollWidth > window.innerWidth,
            diff: document.documentElement.scrollWidth - window.innerWidth,
            scrollWidth: document.documentElement.scrollWidth,
            windowWidth: window.innerWidth
        };
    }''')
    
    print(f"Overflow horizontal: {overflow['horizontal']}")
    print(f"  scrollWidth: {overflow['scrollWidth']}px")
    print(f"  windowWidth: {overflow['windowWidth']}px")
    print(f"  diff: +{overflow['diff']}px")
    
    # Check policy elements
    policy_check = page.evaluate('''() => {
        const container = document.querySelector('.policy-container');
        const sections = document.querySelectorAll('.policy-section');
        const tables = document.querySelectorAll('.policy-section .data-table');
        
        return {
            container: container ? {
                width: container.getBoundingClientRect().width,
                maxWidth: window.getComputedStyle(container).maxWidth
            } : null,
            sectionsCount: sections.length,
            tables: Array.from(tables).map(t => ({
                width: t.getBoundingClientRect().width,
                minWidth: window.getComputedStyle(t).minWidth || 'auto'
            }))
        };
    }''')
    
    print(f"\nPolicy container: {policy_check['container']}")
    print(f"Sections count: {policy_check['sectionsCount']}")
    print(f"Tables: {policy_check['tables']}")
    
    # Check CSS loaded
    css_check = page.evaluate('''() => {
        const styles = Array.from(document.styleSheets);
        const hasPolicyRule = styles.some(sheet => {
            try {
                return Array.from(sheet.cssRules || []).some(rule => 
                    rule.selectorText && rule.selectorText.includes('.policy')
                );
            } catch (e) {
                return false;
            }
        });
        return hasPolicyRule;
    }''')
    
    print(f"\nCSS policy rules loaded: {css_check}")
    
    # Screenshot
    page.screenshot(path='logs/screenshots/mobile_password_policy.png', full_page=True)
    print(f"\n📸 logs/screenshots/mobile_password_policy.png")
    
    browser.close()
