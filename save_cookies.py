"""
Sauvegarde des cookies de session pour tests automatisés
"""
from playwright.sync_api import sync_playwright
import json
import time
import os

print("\n" + "="*70)
print(" CONNEXION ET SAUVEGARDE DES COOKIES")
print("="*70 + "\n")

print("Ouverture du navigateur...")
print("Connectez-vous avec vos identifiants AD\n")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    context = browser.new_context(viewport={'width': 1920, 'height': 1080})
    page = context.new_page()
    
    # Page de connexion
    print("\n📄 Ouverture de la page de connexion...")
    page.goto('http://localhost:5000/connect', wait_until='networkidle', timeout=15000)
    
    print("\n⏳ En attente de votre connexion...")
    print("   Une fois connecté, la page Dashboard devrait s'afficher")
    print("   J'attends 60 secondes maximum...\n")
    
    # Attendre jusqu'à 60 secondes que l'utilisateur se connecte
    for i in range(60):
        current_url = page.url
        if '/connect' not in current_url:
            break
        time.sleep(1)
        if i % 10 == 0:
            print(f"   Attente... {i}s")
    
    # Vérifier qu'on est connecté
    current_url = page.url
    print(f"   URL actuelle: {current_url}")
    
    if '/dashboard' in current_url or '/users' in current_url or '/computers' in current_url:
        print("   ✅ Connecté avec succès!\n")
        
        # Sauvegarder les cookies
        cookies = context.cookies()
        
        # Filtrer uniquement les cookies de session
        session_cookies = [c for c in cookies if c['name'] == 'session']
        
        if session_cookies:
            # Sauvegarder dans un fichier JSON
            with open('test_cookies.json', 'w', encoding='utf-8') as f:
                json.dump(session_cookies, f, indent=2)
            
            print(f"   ✅ Cookies sauvegardés: test_cookies.json")
            print(f"   Nombre de cookies: {len(session_cookies)}")
        else:
            print("   ⚠️  Aucun cookie de session trouvé")
            # Sauvegarder tous les cookies
            with open('test_cookies.json', 'w', encoding='utf-8') as f:
                json.dump(cookies, f, indent=2)
            print(f"   ✅ Tous les cookies sauvegardés: test_cookies.json")
    else:
        print("   ❌ Pas connecté. URL: " + current_url)
    
    browser.close()

print("\n" + "="*70)
print(" TERMINÉ")
print("="*70 + "\n")

print("Prochaine étape: Lancez les tests avec --cookies pour utiliser la session sauvegardée")
