"""
Check if styles.css is loaded
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
    
    result = page.evaluate('''() => {
        const stylesheets = Array.from(document.styleSheets);
        const loaded = stylesheets.map(sheet => {
            try {
                return {
                    href: sheet.href,
                    rules: sheet.cssRules?.length || 0
                };
            } catch (e) {
                return { href: sheet.href, error: 'CORS' };
            }
        });
        
        // Check if .top-bar rule exists
        const topBarRule = Array.from(document.styleSheets).some(sheet => {
            try {
                return Array.from(sheet.cssRules || []).some(rule => 
                    rule.selectorText && rule.selectorText.includes('.top-bar')
                );
            } catch (e) {
                return false;
            }
        });
        
        return {
            stylesheets: loaded,
            hasTopBarRule: topBarRule
        };
    }''')
    
    print("Stylesheets loaded:")
    for sheet in result['stylesheets']:
        print(f"  {sheet['href']} ({sheet.get('rules', 'N/A')} rules)")
    
    print(f"\nHas .top-bar rule: {result['hasTopBarRule']}")
    
    browser.close()
