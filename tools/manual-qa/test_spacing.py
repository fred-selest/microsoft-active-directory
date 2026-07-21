"""
Debug spacing before table
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
        const container = document.querySelector('.table-container');
        if (!container) return { error: 'container not found' };
        
        // Get all previous siblings
        const siblings = [];
        let el = container.previousElementSibling;
        while (el) {
            const rect = el.getBoundingClientRect();
            const styles = window.getComputedStyle(el);
            siblings.push({
                tag: el.tagName,
                class: el.className,
                height: rect.height,
                marginTop: styles.marginTop,
                marginBottom: styles.marginBottom,
                display: styles.display
            });
            el = el.previousElementSibling;
        }
        
        // Also check page-header
        const header = document.querySelector('.page-header');
        const searchBox = document.querySelector('.search-box');
        
        return {
            header: header ? {
                height: header.getBoundingClientRect().height,
                marginBottom: window.getComputedStyle(header).marginBottom
            } : null,
            searchBox: searchBox ? {
                height: searchBox.getBoundingClientRect().height,
                marginBottom: window.getComputedStyle(searchBox).marginBottom
            } : null,
            previousSiblings: siblings
        };
    }''')
    
    print("Page header:", result.get('header'))
    print("Search box:", result.get('searchBox'))
    print("Previous siblings:", result.get('previousSiblings'))
    
    browser.close()
