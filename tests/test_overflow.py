"""
Test rapide - Check computed styles
"""
from playwright.sync_api import sync_playwright
import time

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page(viewport={'width': 1920, 'height': 1080})
    
    page.goto('http://localhost:5000/computers', wait_until='networkidle', timeout=15000)
    
    if '/connect' in page.url:
        print("Connectez-vous manuellement...")
        for i in range(30, 0, -1):
            print(f"{i}s...", end='\r')
            time.sleep(1)
        page.goto('http://localhost:5000/computers', wait_until='networkidle', timeout=15000)
    
    time.sleep(2)
    
    # Check tous les overflow
    result = page.evaluate('''() => {
        const main = document.querySelector('.main-content');
        const html = document.documentElement;
        const body = document.body;
        
        const mainStyles = window.getComputedStyle(main);
        
        return {
            html: {
                scrollWidth: html.scrollWidth,
                clientWidth: html.clientWidth,
                overflow: html.scrollWidth - html.clientWidth
            },
            body: {
                scrollWidth: body.scrollWidth,
                clientWidth: body.clientWidth,
                overflow: body.scrollWidth - body.clientWidth
            },
            main: {
                width: main.offsetWidth,
                scrollWidth: main.scrollWidth,
                paddingLeft: mainStyles.paddingLeft,
                paddingRight: mainStyles.paddingRight,
                marginLeft: mainStyles.marginLeft,
                marginRight: mainStyles.marginRight,
                boxSizing: mainStyles.boxSizing,
                overflowX: mainStyles.overflowX
            },
            cssRules: []
        };
    }''')
    
    print("HTML:", result['html'])
    print("Body:", result['body'])
    print("Main:", result['main'])
    
    browser.close()
