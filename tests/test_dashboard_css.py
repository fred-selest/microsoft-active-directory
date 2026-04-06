"""
Diagnostic CSS du Dashboard - AD Web Interface
Utilise Playwright pour inspecter le rendu réel et identifier les problèmes
"""
from playwright.sync_api import sync_playwright
import json
import os
import http.cookiejar

os.makedirs('logs/screenshots', exist_ok=True)

print("\n" + "="*80)
print(" DIAGNOSTIC CSS - Dashboard Stats Grid")
print("="*80 + "\n")

def load_cookies_from_file(filename):
    """Charge les cookies depuis un fichier au format Netscape."""
    cookies = []
    if not os.path.exists(filename):
        return cookies
    
    with open(filename, 'r') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue
            parts = line.strip().split('\t')
            if len(parts) >= 7:
                cookies.append({
                    'name': parts[5],
                    'value': parts[6],
                    'domain': 'localhost',
                    'path': '/',
                })
    return cookies

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    
    # Charger les cookies existants
    context = browser.new_context(
        viewport={'width': 1920, 'height': 1080},
        storage_state={
            'cookies': load_cookies_from_file('cookies.txt')
        } if os.path.exists('cookies.txt') else None
    )
    page = context.new_page()
    
    try:
        # Navigation vers le dashboard
        print("📄 Navigation vers le dashboard...")
        page.goto('http://localhost:5000/dashboard', wait_until='networkidle', timeout=15000)
        
        # Vérifier si on est redirigé vers la page de connexion
        if '/connect' in page.url:
            print("   ⚠️  Redirigé vers la page de connexion (session expirée)")
            print("   Veuillez vous connecter manuellement et réessayer.\n")
            print("💾 Résultats sauvegardés: logs/dashboard_diagnostic.json")
            browser.close()
            exit(0)
        
        print("   ✅ Page chargée (session valide)\n")
        
        # 4. Screenshot initial
        print("📸 Capture du screenshot...")
        page.screenshot(path='logs/screenshots/dashboard_avant.png')
        print("   ✅ logs/screenshots/dashboard_avant.png\n")
        
        # 4. Inspecter le CSS appliqué à .stats-grid
        print("🔍 Inspection du CSS appliqué à .stats-grid...")
        css_result = page.evaluate('''() => {
            const grid = document.querySelector('.stats-grid');
            if (!grid) return { error: 'stats-grid not found' };
            
            const styles = window.getComputedStyle(grid);
            const rules = [];
            
            // Récupérer toutes les feuilles de style
            for (const sheet of document.styleSheets) {
                try {
                    for (const rule of sheet.cssRules) {
                        if (rule.selectorText && rule.selectorText.includes('stats-grid')) {
                            rules.push({
                                selector: rule.selectorText,
                                gridTemplateColumns: rule.style.gridTemplateColumns || 'N/A',
                                gap: rule.style.gap || 'N/A',
                                media: rule.media ? rule.media.mediaText : 'none'
                            });
                        }
                    }
                } catch (e) {}
            }
            
            return {
                computed: {
                    gridTemplateColumns: styles.gridTemplateColumns,
                    gap: styles.gap,
                    display: styles.display,
                    width: styles.width,
                    columnCount: grid.children.length
                },
                cssRules: rules,
                inlineStyles: grid.getAttribute('style')
            };
        }''')
        
        if css_result.get('error'):
            print(f"   ❌ {css_result['error']}")
            css_rules = {'computed': {}, 'cssRules': []}
        else:
            css_rules = css_result
            print(f"   Computed styles:")
            print(f"      - grid-template-columns: {css_rules['computed']['gridTemplateColumns']}")
            print(f"      - gap: {css_rules['computed']['gap']}")
            print(f"      - display: {css_rules['computed']['display']}")
            print(f"      - Nombre de cartes: {css_rules['computed']['columnCount']}")
            if css_rules.get('inlineStyles'):
                print(f"      - Inline styles: {css_rules['inlineStyles']}")
            print()
            
            print(f"   Règles CSS trouvées:")
            for rule in css_rules['cssRules']:
                print(f"      • {rule['selector']}")
                print(f"        → grid-template-columns: {rule['gridTemplateColumns']}")
                print(f"        → gap: {rule['gap']}")
                print(f"        → media: {rule['media']}")
            print()
        
        # 3. Vérifier overflow horizontal
        print("📏 Vérification overflow horizontal...")
        overflow = page.evaluate('''() => {
            return {
                html_overflow: document.documentElement.scrollWidth > window.innerWidth,
                body_overflow: document.body.scrollWidth > window.innerWidth,
                diff: document.documentElement.scrollWidth - window.innerWidth,
                body_width: document.documentElement.scrollWidth,
                window_width: window.innerWidth
            };
        }''')
        
        if overflow['html_overflow']:
            print(f"   ❌ OVERFLOW: +{overflow['diff']}px (body: {overflow['body_width']}px / window: {overflow['window_width']}px)")
        else:
            print(f"   ✅ Pas d'overflow horizontal")
        print()
        
        # 4. Vérifier éléments coupés
        print("✂️  Vérification éléments coupés...")
        cut_elements = page.evaluate('''() => {
            const cuts = [];
            document.querySelectorAll('h1, h2, .btn, .stat-card').forEach(el => {
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
            for el in cut_elements:
                print(f"      - {el['type']}: \"{el['text']}\" (width: {el['rect']['width']}px)")
        else:
            print(f"   ✅ Aucun élément coupé")
        print()
        
        # 5. Dimensions des stat-cards
        print("📐 Dimensions des stat-cards...")
        card_dimensions = page.evaluate('''() => {
            const cards = document.querySelectorAll('.stat-card');
            return Array.from(cards).map((card, i) => {
                const rect = card.getBoundingClientRect();
                return { index: i, width: rect.width, height: rect.height };
            });
        }''')
        
        for card in card_dimensions:
            print(f"   Carte {card['index']}: {card['width']}x{card['height']}px")
        print()
        
        # Sauvegarder les résultats
        results = {
            'css_rules': css_rules,
            'overflow': overflow,
            'cut_elements': cut_elements,
            'card_dimensions': card_dimensions,
            'screenshot': 'logs/screenshots/dashboard_avant.png'
        }
        
        with open('logs/dashboard_diagnostic.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print("💾 Résultats sauvegardés: logs/dashboard_diagnostic.json")
        
    except Exception as e:
        print(f"\n❌ ERREUR: {str(e)}")
        print("   Le serveur est-il démarré ? (http://localhost:5000)")
    
    browser.close()

print("\n" + "="*80)
print(" DIAGNOSTIC TERMINÉ")
print("="*80 + "\n")
