"""
Check page load
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
    
    print("Going to /computers...")
    page.goto('http://localhost:5000/computers', wait_until='networkidle')
    time.sleep(2)
    
    print(f"Current URL: {page.url}")
    
    # Check if we're on login page
    if '/connect' in page.url:
        print("Redirected to login!")
    else:
        # Get page content
        html = page.content()
        print(f"Page HTML length: {len(html)}")
        
        # Check for table
        has_table = page.evaluate('!!document.querySelector("table")')
        print(f"Has table: {has_table}")
        
        # Check for data-table
        has_data_table = page.evaluate('!!document.querySelector(".data-table")')
        print(f"Has .data-table: {has_data_table}")
        
        # Get all classes
        classes = page.evaluate('''() => {
            return Array.from(document.querySelectorAll('[class]')).map(el => el.className).filter(c => c.includes('table') || c.includes('data')).slice(0, 20);
        }''')
        print(f"Classes with 'table' or 'data': {classes}")
    
    browser.close()
