"""
Debug structure HTML table
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
        const table = document.querySelector('.data-table');
        const container = document.querySelector('.table-container');
        const thead = document.querySelector('.data-table thead');
        
        if (!table || !container || !thead) {
            return { error: 'Elements missing' };
        }
        
        const tableRect = table.getBoundingClientRect();
        const containerRect = container.getBoundingClientRect();
        const theadRect = thead.getBoundingClientRect();
        
        return {
            table: {
                display: window.getComputedStyle(table).display,
                rect: { top: tableRect.top, height: tableRect.height },
                children: table.children.length
            },
            container: {
                display: window.getComputedStyle(container).display,
                rect: { top: containerRect.top, height: containerRect.height },
                overflow: window.getComputedStyle(container).overflow
            },
            thead: {
                display: window.getComputedStyle(thead).display,
                position: window.getComputedStyle(thead).position,
                top: window.getComputedStyle(thead).top,
                rect: { top: theadRect.top, height: theadRect.height },
                parent: thead.parentElement.tagName
            }
        };
    }''')
    
    print(result)
    
    browser.close()
