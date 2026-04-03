"""
Sauvegarde simple des cookies - Ouvre le navigateur et attend la connexion
"""
from playwright.sync_api import sync_playwright
import json
import time

print("\n🍪 Sauvegarde des cookies de session\n")
print("Le navigateur va s'ouvrir...")
print("1. Connecte-toi avec tes identifiants AD")
print("2. Va sur le dashboard ou n'importe quelle page")
print("3. Les cookies seront sauvegardés automatiquement après 60s\n")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    context = browser.new_context(viewport={'width': 1920, 'height': 1080})
    page = context.new_page()
    
    page.goto('http://localhost:5000/connect')
    
    print("⏳ Attente de la connexion (60s max)...")
    
    for i in range(60):
        url = page.url
        if '/connect' not in url:
            print(f"\n✅ Connecté ! URL: {url}")
            break
        time.sleep(1)
        if i % 10 == 0 and i > 0:
            print(f"   ... {i}s")
    
    # Sauvegarder tous les cookies
    cookies = context.cookies()
    
    with open('test_cookies.json', 'w', encoding='utf-8') as f:
        json.dump(cookies, f, indent=2)
    
    print(f"\n✅ Cookies sauvegardés: test_cookies.json ({len(cookies)} cookies)")
    
    time.sleep(3)
    browser.close()

print("\nTerminé !")
