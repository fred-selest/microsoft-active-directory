"""
Debug full page structure
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
        const body = document.body;
        const children = [];
        
        for (const child of body.children) {
            const rect = child.getBoundingClientRect();
            const styles = window.getComputedStyle(child);
            children.push({
                tag: child.tagName,
                id: child.id,
                class: child.className,
                height: rect.height,
                top: rect.top,
                display: styles.display,
                position: styles.position,
                visibility: styles.visibility
            });
        }
        
        return {
            bodyHeight: body.scrollHeight,
            children: children
        };
    }''')
    
    print(f"Body scrollHeight: {result['bodyHeight']}px\n")
    print("Body children:")
    for child in result['children']:
        print(f"  <{child['tag']}> class='{child['class']}'")
        print(f"    top={child['top']}px, height={child['height']}px, display={child['display']}, position={child['position']}, visibility={child['visibility']}")
    
    browser.close()
