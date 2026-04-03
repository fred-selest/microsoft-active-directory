"""
Test overflow détaillé
"""
from playwright.sync_api import sync_playwright
import time

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page(viewport={'width': 1920, 'height': 1080})
    
    page.goto('http://localhost:5000/computers', wait_until='networkidle', timeout=15000)
    
    if '/connect' in page.url:
        print("Connectez-vous manuellement...")
        for i in range(20, 0, -1):
            print(f"{i}s...", end='\r')
            time.sleep(1)
        page.goto('http://localhost:5000/computers', wait_until='networkidle', timeout=15000)
    
    time.sleep(2)
    
    # Check detailed box model
    result = page.evaluate('''() => {
        const html = document.documentElement;
        const body = document.body;
        const main = document.querySelector('.main-content');
        
        const htmlStyles = window.getComputedStyle(html);
        const bodyStyles = window.getComputedStyle(body);
        const mainStyles = window.getComputedStyle(main);
        
        return {
            viewport: { width: window.innerWidth, height: window.innerHeight },
            html: {
                scrollWidth: html.scrollWidth,
                clientWidth: html.clientWidth,
                offsetWidth: html.offsetWidth,
                margin: {
                    left: htmlStyles.marginLeft,
                    right: htmlStyles.marginRight
                },
                padding: {
                    left: htmlStyles.paddingLeft,
                    right: htmlStyles.paddingRight
                }
            },
            body: {
                scrollWidth: body.scrollWidth,
                clientWidth: body.clientWidth,
                offsetWidth: body.offsetWidth,
                margin: {
                    left: bodyStyles.marginLeft,
                    right: bodyStyles.marginRight
                },
                padding: {
                    left: bodyStyles.paddingLeft,
                    right: bodyStyles.paddingRight
                }
            },
            main: {
                width: main.offsetWidth,
                scrollWidth: main.scrollWidth,
                clientWidth: main.clientWidth,
                margin: {
                    left: mainStyles.marginLeft,
                    right: mainStyles.marginRight
                },
                padding: {
                    left: mainStyles.paddingLeft,
                    right: mainStyles.paddingRight
                },
                boxSizing: mainStyles.boxSizing,
                widthComputed: mainStyles.width
            }
        };
    }''')
    
    print("Viewport:", result['viewport'])
    print("\nHTML:", result['html'])
    print("\nBody:", result['body'])
    print("\nMain:", result['main'])
    
    browser.close()
