"""
Test complet mobile - Toutes les pages
"""
from playwright.sync_api import sync_playwright
import json
import time

with open('test_cookies.json', 'r') as f:
    cookies = json.load(f)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    context = browser.new_context(
        viewport={'width': 390, 'height': 844},
        device_scale_factor=3,
        is_mobile=True,
        has_touch=True,
        storage_state={'cookies': cookies}
    )
    page = context.new_page()
    
    # Toutes les pages à tester
    pages = [
        ('Dashboard', '/dashboard'),
        ('Users', '/users'),
        ('Groups', '/groups'),
        ('Computers', '/computers'),
        ('OUs', '/ous'),
        ('Password Policy', '/password-policy'),
        ('Password Audit', '/password-audit'),
        ('Alerts', '/alerts'),
        ('Admin', '/admin/'),
        ('Locked Accounts', '/tools/locked-accounts'),
        ('Expiring', '/tools/expiring'),
        ('Backups', '/tools/backups'),
    ]
    
    print("\n" + "="*70)
    print(" TEST COMPLET MOBILE - TOUTES LES PAGES")
    print("="*70 + "\n")
    
    results = []
    
    for name, url in pages:
        print(f"📱 {name} ({url})")
        
        try:
            page.goto(f'http://localhost:5000{url}', wait_until='networkidle', timeout=15000)
            time.sleep(1)
            
            # Check overflow
            overflow = page.evaluate('''() => {
                return {
                    horizontal: document.documentElement.scrollWidth > window.innerWidth,
                    diff: document.documentElement.scrollWidth - window.innerWidth
                };
            }''')
            
            # Check tables
            tables = page.evaluate('''() => {
                return Array.from(document.querySelectorAll('table')).map(t => ({
                    class: t.className,
                    width: t.getBoundingClientRect().width,
                    minWidth: window.getComputedStyle(t).minWidth || 'auto'
                }));
            }''')
            
            # Check elements coupés
            cut = page.evaluate('''() => {
                const cuts = [];
                document.querySelectorAll('h1, h2, .btn, th, td').forEach(el => {
                    const rect = el.getBoundingClientRect();
                    if (rect.right > window.innerWidth - 10) {
                        cuts.push(el.tagName);
                    }
                });
                return cuts.length;
            }''')
            
            # Status
            status = '✅ OK' if not overflow['horizontal'] and cut == 0 else '❌ PB'
            print(f"   {status} | Overflow: {'+' + str(overflow['diff']) + 'px' if overflow['horizontal'] else 'OK'} | Cut: {cut} | Tables: {len(tables)}")
            
            if tables:
                for t in tables[:3]:
                    print(f"      - {t['class']}: {t['width']}px (min: {t['minWidth']})")
            
            results.append({
                'name': name,
                'url': url,
                'overflow': overflow['horizontal'],
                'overflow_diff': overflow['diff'],
                'cut_elements': cut,
                'tables_count': len(tables),
                'tables': tables
            })
            
        except Exception as e:
            print(f"   ❌ Erreur: {str(e)[:50]}")
            results.append({'name': name, 'url': url, 'error': str(e)})
        
        print()
    
    browser.close()
    
    # Résumé
    print("="*70)
    print(" RÉSUMÉ")
    print("="*70 + "\n")
    
    ok_pages = [r for r in results if not r.get('overflow') and r.get('cut_elements', 0) == 0]
    pb_pages = [r for r in results if r.get('overflow') or r.get('cut_elements', 0) > 0]
    
    print(f"✅ OK: {len(ok_pages)}/{len(results)}")
    print(f"❌ PB: {len(pb_pages)}/{len(results)}")
    
    if pb_pages:
        print("\n📋 Pages avec problèmes:")
        for r in pb_pages:
            print(f"   - {r['name']}: overflow=+{r.get('overflow_diff', 0)}px, cut={r.get('cut_elements', 0)}")
    
    print("\n" + "="*70 + "\n")
