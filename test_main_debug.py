"""
Debug main-content padding
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
        const main = document.querySelector('.main-content');
        if (!main) return { error: 'main not found' };
        
        const styles = window.getComputedStyle(main);
        const rect = main.getBoundingClientRect();
        
        return {
            marginTop: styles.marginTop,
            paddingTop: styles.paddingTop,
            marginBottom: styles.marginBottom,
            paddingBottom: styles.paddingBottom,
            height: rect.height,
            scrollHeight: main.scrollHeight,
            offsetTop: main.offsetTop
        };
    }''')
    
    print("Main content:", result)
    
    browser.close()
