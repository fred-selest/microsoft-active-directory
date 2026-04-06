"""
Debug visuel avec Chromium - Détecte les problèmes d'affichage
"""
from playwright.sync_api import sync_playwright
import time
import json

print("\n" + "="*70)
print(" DEBUG VISUEL - AD Web Interface")
print("="*70 + "\n")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page(viewport={'width': 1920, 'height': 1080})
    
    # Intercepter les erreurs console
    console_errors = []
    page.on('console', lambda msg: console_errors.append(f"[{msg.type}] {msg.text}"))
    
    # Intercepter les erreurs JS
    js_errors = []
    page.on('pageerror', lambda err: js_errors.append(str(err)))
    
    pages = [
        ('/dashboard', 'Dashboard'),
        ('/users', 'Utilisateurs'),
        ('/groups', 'Groupes'),
    ]
    
    issues_found = []
    
    for url, name in pages:
        print(f"📄 Testing: {name}")
        console_errors.clear()
        js_errors.clear()
        
        try:
            page.goto(f'http://localhost:5000{url}', wait_until='networkidle')
            time.sleep(1)
            
            # Vérifier overflow horizontal
            overflow = page.evaluate('''() => {
                return {
                    body_overflow: document.body.scrollWidth > window.innerWidth,
                    html_overflow: document.documentElement.scrollWidth > window.innerWidth,
                    body_width: document.body.scrollWidth,
                    window_width: window.innerWidth
                }
            }''')
            
            if overflow['body_overflow'] or overflow['html_overflow']:
                issues_found.append({
                    'page': name,
                    'issue': 'OVERFLOW_HORIZONTAL',
                    'details': f"Body: {overflow['body_width']}px > Window: {overflow['window_width']}px"
                })
                print(f"   ⚠️  OVERFLOW HORIZONTAL détecté!")
            
            # Vérifier éléments coupés
            cut_elements = page.evaluate('''() => {
                const cuts = [];
                // Vérifier headers
                document.querySelectorAll('h1, h2').forEach(el => {
                    const rect = el.getBoundingClientRect();
                    const style = window.getComputedStyle(el);
                    if (rect.right > window.innerWidth || style.overflow === 'hidden') {
                        cuts.push({tag: el.tagName, text: el.textContent.substring(0, 50)})
                    }
                })
                // Vérifier boutons
                document.querySelectorAll('.btn').forEach(el => {
                    const rect = el.getBoundingClientRect();
                    if (rect.right > window.innerWidth) {
                        cuts.push({tag: 'BUTTON', text: el.textContent.substring(0, 30)})
                    }
                })
                return cuts
            }''')
            
            if cut_elements:
                issues_found.append({
                    'page': name,
                    'issue': 'ELEMENTS_COUPES',
                    'details': cut_elements
                })
                print(f"   ⚠️  Éléments coupés: {len(cut_elements)}")
            
            # Vérifier tables
            table_overflow = page.evaluate('''() => {
                const issues = [];
                document.querySelectorAll('.table-container').forEach(el => {
                    const rect = el.getBoundingClientRect();
                    if (rect.width > window.innerWidth) {
                        issues.push('table-container trop large')
                    }
                })
                return issues
            }''')
            
            if table_overflow:
                issues_found.append({
                    'page': name,
                    'issue': 'TABLE_OVERFLOW',
                    'details': table_overflow
                })
                print(f"   ⚠️  Table overflow: {table_overflow}")
            
            # Capture screenshot
            page.screenshot(path=f'logs/debug_{name.replace(" ", "_")}.png', full_page=True)
            print(f"   ✅ Screenshot: logs/debug_{name}.png")
            
        except Exception as e:
            print(f"   ❌ Erreur: {str(e)[:100]}")
        
        print()
    
    # Résumé
    print("="*70)
    print(" RÉSULTATS")
    print("="*70)
    
    if issues_found:
        print(f"\n⚠️  {len(issues_found)} problèmes trouvés:\n")
        for issue in issues_found:
            print(f"📄 {issue['page']}")
            print(f"   Type: {issue['issue']}")
            print(f"   Détails: {issue['details']}")
            print()
    else:
        print("\n✅ Aucun problème détecté!")
    
    print(f"\n📁 Screenshots: logs/debug_*.png")
    print("="*70 + "\n")
    
    browser.close()
