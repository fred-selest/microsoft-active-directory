"""
Identifier l'élément causant l'overflow
"""
from playwright.sync_api import sync_playwright

print("\n🔍 Recherche des éléments causant l'overflow...\n")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={'width': 1920, 'height': 1080})
    
    page.goto('http://localhost:5000/connect', wait_until='networkidle')
    
    # Trouver l'élément le plus large
    widest = page.evaluate('''() => {
        let max = 0;
        let culprit = null;
        
        document.querySelectorAll('*').forEach(el => {
            const rect = el.getBoundingClientRect();
            if (rect.width > max && rect.width > window.innerWidth) {
                max = rect.width;
                culprit = {
                    tag: el.tagName,
                    class: el.className || 'none',
                    width: rect.width,
                    scrollWidth: el.scrollWidth
                };
            }
        });
        
        return {widest: culprit, windowWidth: window.innerWidth, scrollWidth: document.documentElement.scrollWidth};
    }''')
    
    print(f"Largeur fenêtre: {widest['windowWidth']}px")
    print(f"Largeur scroll: {widest['scrollWidth']}px")
    print(f"Débordement: {widest['scrollWidth'] - widest['windowWidth']}px")
    
    if widest['widest']:
        print(f"\n❌ ÉLÉMENT PROBLÈME:")
        print(f"   Tag: {widest['widest']['tag']}")
        print(f"   Class: {widest['widest']['class']}")
        print(f"   Largeur: {widest['widest']['width']}px")
    else:
        print("\n✅ Aucun élément spécifique trouvé")
    
    # Vérifier le body et main-content
    body_width = page.evaluate('document.body.scrollWidth')
    main = page.evaluate('document.querySelector(".main-content")?.scrollWidth || 0')
    sidebar = page.evaluate('document.querySelector(".sidebar")?.scrollWidth || 0')
    
    print(f"\n📊 Mesures:")
    print(f"   Body scrollWidth: {body_width}px")
    print(f"   Main-content scrollWidth: {main}px")
    print(f"   Sidebar scrollWidth: {sidebar}px")
    
    browser.close()
