"""
Test complet avec Chromium - AD Web Interface
Ouvre le navigateur, teste toutes les pages, capture les problèmes
"""
from playwright.sync_api import sync_playwright
import time
import os
import json

os.makedirs('logs/screenshots', exist_ok=True)

print("\n" + "="*80)
print(" TEST COMPLET - AD Web Interface avec Chromium")
print("="*80)
print("\n📋 Pages à tester:")
print("   - Dashboard")
print("   - Utilisateurs")
print("   - Groupes")
print("   - Password Policy")
print("   - Password Audit")
print("   - Admin")
print("\n🔍 Tests effectués:")
print("   - Overflow horizontal")
print("   - Éléments coupés")
print("   - Tableaux responsive")
print("   - Boutons alignés")
print("   - Erreurs JavaScript")
print("="*80 + "\n")

with sync_playwright() as p:
    # Lancer Chromium en mode visible
    browser = p.chromium.launch(
        headless=False,
        args=[
            '--start-maximized',
            '--disable-blink-features=AutomationControlled',
            '--disable-dev-shm-usage'
        ]
    )
    
    context = browser.new_context(
        viewport={'width': 1920, 'height': 1080},
        device_scale_factor=1
    )
    
    page = context.new_page()
    
    # Collecter toutes les erreurs
    all_errors = {
        'console': [],
        'js': [],
        'css': [],
        'overflow': [],
        'cut_elements': []
    }
    
    page.on('console', lambda msg: all_errors['console'].append({
        'type': msg.type,
        'text': msg.text
    }))
    
    page.on('pageerror', lambda err: all_errors['js'].append(str(err)))
    
    # Pages à tester
    test_pages = [
        {'url': '/dashboard', 'name': '01_Dashboard'},
        {'url': '/users', 'name': '02_Utilisateurs'},
        {'url': '/groups', 'name': '03_Groupes'},
        {'url': '/computers', 'name': '04_Ordinateurs'},
        {'url': '/ous', 'name': '05_OUs'},
        {'url': '/password-policy', 'name': '06_Password_Policy'},
        {'url': '/password-audit', 'name': '07_Password_Audit'},
        {'url': '/admin/', 'name': '08_Admin'},
    ]
    
    results = []
    
    for test in test_pages:
        url = test['url']
        name = test['name']
        
        print(f"📄 Testing: {name} ({url})")
        print(f"   Status: ", end='', flush=True)
        
        # Reset errors
        all_errors['console'] = []
        all_errors['js'] = []
        
        try:
            # Navigation
            response = page.goto(f'http://localhost:5000{url}', wait_until='networkidle', timeout=15000)
            status = response.status if response else 'N/A'
            print(f"{status}", end=' → ')
            
            time.sleep(1.5)  # Attendre le rendu complet
            
            # Capture screenshot
            screenshot_path = f'logs/screenshots/{name}.png'
            page.screenshot(path=screenshot_path, full_page=True)
            print(f"📸 OK", end=' → ')
            
            # Test 1: Overflow horizontal
            overflow_check = page.evaluate('''() => {
                return {
                    body_overflow: document.body.scrollWidth > window.innerWidth,
                    html_overflow: document.documentElement.scrollWidth > window.innerWidth,
                    body_width: document.body.scrollWidth,
                    window_width: window.innerWidth,
                    diff: document.body.scrollWidth - window.innerWidth
                }
            }''')
            
            overflow_status = "✅" if not overflow_check['body_overflow'] else f"❌ +{overflow_check['diff']}px"
            print(f"Overflow: {overflow_status}", end=' → ')
            
            if overflow_check['body_overflow']:
                all_errors['overflow'].append({
                    'page': name,
                    'body_width': overflow_check['body_width'],
                    'window_width': overflow_check['window_width'],
                    'diff': overflow_check['diff']
                })
            
            # Test 2: Éléments coupés
            cut_check = page.evaluate('''() => {
                const cuts = [];
                
                // Headers
                document.querySelectorAll('h1, h2, .page-header h2').forEach(el => {
                    const rect = el.getBoundingClientRect();
                    if (rect.right > window.innerWidth - 50) {
                        cuts.push({type: 'HEADER', text: el.textContent.substring(0, 40)})
                    }
                });
                
                // Boutons dans header-actions
                document.querySelectorAll('.header-actions .btn').forEach(el => {
                    const rect = el.getBoundingClientRect();
                    const parent = el.parentElement;
                    if (parent) {
                        const parentRect = parent.getBoundingClientRect();
                        if (rect.right > parentRect.right) {
                            cuts.push({type: 'BUTTON', text: el.textContent.substring(0, 30)})
                        }
                    }
                });
                
                // Stats cards
                document.querySelectorAll('.stat-card').forEach(el => {
                    const rect = el.getBoundingClientRect();
                    if (rect.width < 150) {
                        cuts.push({type: 'STAT_CARD', width: rect.width})
                    }
                });
                
                return cuts;
            }''')
            
            cut_status = f"✅" if len(cut_check) == 0 else f"❌ {len(cut_check)} éléments"
            print(f"Éléments: {cut_status}")
            
            if cut_check:
                all_errors['cut_elements'].append({
                    'page': name,
                    'elements': cut_check
                })
            
            # Test 3: Tables responsive
            table_check = page.evaluate('''() => {
                const issues = [];
                document.querySelectorAll('.table-container').forEach(container => {
                    const table = container.querySelector('table');
                    if (table) {
                        const containerWidth = container.getBoundingClientRect().width;
                        const tableWidth = table.scrollWidth;
                        if (tableWidth > containerWidth + 100) {
                            issues.push({
                                container: containerWidth,
                                table: tableWidth,
                                scroll: container.scrollWidth
                            })
                        }
                    }
                });
                return issues;
            }''')
            
            if table_check:
                print(f"   📊 Tables: ⚠️  Scroll nécessaire ({table_check[0]['table']}px)")
            
            results.append({
                'page': name,
                'url': url,
                'status': status,
                'screenshot': screenshot_path,
                'overflow': overflow_check,
                'cut_elements': cut_check,
                'tables': table_check,
                'js_errors': len(all_errors['js']),
                'console_messages': len(all_errors['console'])
            })
            
        except Exception as e:
            print(f"❌ ERROR: {str(e)[:80]}")
            results.append({
                'page': name,
                'url': url,
                'status': 'ERROR',
                'error': str(e)
            })
        
        time.sleep(0.5)
    
    # Résumé final
    print("\n" + "="*80)
    print(" RÉSULTATS COMPLETS")
    print("="*80)
    
    # Sauvegarder les résultats
    with open('logs/test_results.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # Compter les problèmes
    overflow_pages = [r for r in results if r.get('overflow', {}).get('body_overflow')]
    cut_pages = [r for r in results if r.get('cut_elements')]
    error_pages = [r for r in results if r.get('js_errors', 0) > 0]
    
    print(f"\n📊 Résumé:")
    print(f"   Pages testées: {len(results)}")
    print(f"   Overflow horizontal: {len(overflow_pages)} pages")
    print(f"   Éléments coupés: {len(cut_pages)} pages")
    print(f"   Erreurs JS: {len(error_pages)} pages")
    
    if overflow_pages:
        print(f"\n⚠️  OVERFLOW HORIZONTAL:")
        for r in overflow_pages:
            diff = r['overflow'].get('diff', 0)
            print(f"   • {r['page']}: +{diff}px")
    
    if cut_pages:
        print(f"\n⚠️  ÉLÉMENTS COUPÉS:")
        for r in cut_pages:
            print(f"   • {r['page']}:")
            for el in r['cut_elements']:
                print(f"      - {el['type']}: {el.get('text', el.get('width', 'N/A'))}")
    
    print(f"\n📁 Fichiers générés:")
    print(f"   • logs/screenshots/*.png (captures d'écran)")
    print(f"   • logs/test_results.json (résultats détaillés)")
    
    print("\n" + "="*80)
    print(" ✅ Tests terminés !")
    print("="*80 + "\n")
    
    # Garder le navigateur ouvert pour inspection
    print("👀 Navigation manuelle dans les 10 prochaines secondes...")
    print("   - Dashboard: http://localhost:5000/dashboard")
    print("   - Utilisateurs: http://localhost:5000/users")
    print("   - Groupes: http://localhost:5000/groups")
    time.sleep(10)
    
    browser.close()
