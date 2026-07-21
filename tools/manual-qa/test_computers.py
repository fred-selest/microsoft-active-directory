"""
Test CSS de la page Ordinateurs - AD Web Interface
Utilise Playwright pour inspecter le rendu réel
"""
from playwright.sync_api import sync_playwright
import json
import os
import time

os.makedirs('logs/screenshots', exist_ok=True)

print("\n" + "="*80)
print(" TEST CSS - Page Ordinateurs (/computers)")
print("="*80 + "\n")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page(viewport={'width': 1920, 'height': 1080})
    
    try:
        # Navigation
        print("📄 Navigation vers /computers...")
        page.goto('http://localhost:5000/computers', wait_until='networkidle', timeout=15000)
        
        # Vérifier si on est redirigé vers la page de connexion
        if '/connect' in page.url:
            print("   ⚠️  Redirigé vers la page de connexion (session expirée)")
            print("   Connectez-vous manuellement puis revenez sur http://localhost:5000/computers")
            print("\n⏳ Attente de 30 secondes pour connexion manuelle...")
            for i in range(30, 0, -1):
                print(f"   {i} secondes restantes...", end='\r')
                time.sleep(1)
            print("\n\n🔄 Nouvelle tentative vers /computers...")
            page.goto('http://localhost:5000/computers', wait_until='networkidle', timeout=15000)
        
        if '/computers' in page.url:
            print("   ✅ Page chargée\n")
        else:
            print(f"   ❌ Toujours sur {page.url}\n")
        
        # Screenshot
        print("📸 Capture du screenshot...")
        page.screenshot(path='logs/screenshots/computers.png', full_page=True)
        print("   ✅ logs/screenshots/computers.png\n")
        
        # Inspection CSS
        print("🔍 Inspection du CSS...")
        css_result = page.evaluate('''() => {
            const main = document.querySelector('.main-content');
            const table = document.querySelector('.data-table');
            const tableContainer = document.querySelector('.table-container');
            
            return {
                main: main ? {
                    width: main.getBoundingClientRect().width,
                    scrollWidth: main.scrollWidth,
                    overflowX: window.getComputedStyle(main).overflowX
                } : null,
                table: table ? {
                    width: table.getBoundingClientRect().width,
                    scrollWidth: table.scrollWidth
                } : null,
                tableContainer: tableContainer ? {
                    width: tableContainer.getBoundingClientRect().width,
                    scrollWidth: tableContainer.scrollWidth
                } : null,
                html_overflow: document.documentElement.scrollWidth > window.innerWidth,
                body_overflow: document.body.scrollWidth > window.innerWidth,
                diff: document.documentElement.scrollWidth - window.innerWidth
            };
        }''')
        
        print(f"   Main content:")
        if css_result['main']:
            print(f"      - width: {css_result['main']['width']}px")
            print(f"      - scrollWidth: {css_result['main']['scrollWidth']}px")
            print(f"      - overflowX: {css_result['main']['overflowX']}")
        else:
            print(f"      - introuvable")
        
        print(f"\n   Table:")
        if css_result['table']:
            print(f"      - width: {css_result['table']['width']}px")
            print(f"      - scrollWidth: {css_result['table']['scrollWidth']}px")
        else:
            print(f"      - introuvable")
        
        print(f"\n   Table container:")
        if css_result['tableContainer']:
            print(f"      - width: {css_result['tableContainer']['width']}px")
            print(f"      - scrollWidth: {css_result['tableContainer']['scrollWidth']}px")
        else:
            print(f"      - introuvable")
        
        print(f"\n   Overflow global:")
        if css_result['html_overflow']:
            print(f"      ❌ OVERFLOW: +{css_result['diff']}px")
        else:
            print(f"      ✅ Pas d'overflow")
        
        # Éléments coupés
        print("\n✂️  Éléments coupés...")
        cut_elements = page.evaluate('''() => {
            const cuts = [];
            document.querySelectorAll('h1, h2, .btn, th, td').forEach(el => {
                const rect = el.getBoundingClientRect();
                if (rect.right > window.innerWidth - 20) {
                    cuts.push({
                        type: el.tagName,
                        text: el.textContent.substring(0, 30),
                        rect: { width: rect.width, right: rect.right }
                    });
                }
            });
            return cuts;
        }''')
        
        if cut_elements:
            print(f"   ❌ {len(cut_elements)} élément(s) coupé(s):")
            for el in cut_elements[:10]:  # Afficher max 10
                print(f"      - {el['type']}: \"{el['text']}\"")
        else:
            print(f"   ✅ Aucun élément coupé")
        
        # Sauvegarder les résultats
        results = {
            'css': css_result,
            'cut_elements': cut_elements,
            'screenshot': 'logs/screenshots/computers.png'
        }
        
        with open('logs/computers_diagnostic.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Résultats sauvegardés: logs/computers_diagnostic.json")
        
    except Exception as e:
        print(f"\n❌ ERREUR: {str(e)}")
    
    print("\n" + "="*80)
    print(" TEST TERMINÉ")
    print("="*80 + "\n")
    
    time.sleep(3)
    browser.close()
