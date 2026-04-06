"""
Debug display thead
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
        const thead = document.querySelector('.data-table thead');
        const table = document.querySelector('.data-table');
        
        return {
            thead: {
                display: window.getComputedStyle(thead).display,
                position: window.getComputedStyle(thead).position,
                tagName: thead.tagName
            },
            table: {
                display: window.getComputedStyle(table).display
            }
        };
    }''')
    
    print(result)
    
    browser.close()
