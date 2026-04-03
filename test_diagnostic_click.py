"""
Test /diagnostic with button click
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
    
    print("\n📄 Test /diagnostic avec clic bouton\n")
    
    page.goto('http://localhost:5000/diagnostic', wait_until='networkidle', timeout=15000)
    time.sleep(2)  # Wait for page to fully load
    
    # Hard reload to clear cache
    page.keyboard.press('Control+Shift+R')
    time.sleep(2)
    
    # Click the diagnostic button
    print("Clic sur le bouton de diagnostic...")
    page.click('button:has-text("Lancer le diagnostic")')
    time.sleep(3)  # Wait for API call
    
    # Check for errors
    errors = page.evaluate('''() => {
        const errs = [];
        document.querySelectorAll('.alert-danger, .alert-error').forEach(el => {
            errs.push(el.innerText);
        });
        // Check console errors
        return errs;
    }''')
    
    if errors:
        print(f"Erreurs trouvées: {errors}")
    else:
        print("✅ Aucune erreur affichée")
    
    # Check results
    results = page.evaluate('''() => {
        const summary = document.querySelector('#diagnostic-summary');
        const checks = document.querySelector('#diagnostic-checks');
        return {
            hasSummary: !!summary && summary.innerHTML.length > 0,
            checksCount: checks ? checks.querySelectorAll('tr').length : 0
        };
    }''')
    
    print(f"Résultats: {results}")
    
    # Screenshot
    page.screenshot(path='logs/screenshots/diagnostic_with_results.png')
    print("\n📸 logs/screenshots/diagnostic_with_results.png")
    
    browser.close()
    print("\n✅ Test terminé")
