"""
Test CSS du Dashboard - AD Web Interface
Attend une connexion manuelle, puis teste l'affichage
"""
from playwright.sync_api import sync_playwright
import json
import os
import time

os.makedirs('logs/screenshots', exist_ok=True)

print("\n" + "="*80)
print(" TEST CSS DASHBOARD - Attente de connexion manuelle")
print("="*80)
print("\n📋 Instructions:")
print("1. Une fenêtre browser va s'ouvrir")
print("2. Connectez-vous avec vos credentials AD")
print("3. Naviguez vers le dashboard")
print("4. Le test se lancera automatiquement après 30 secondes")
print("="*80 + "\n")

input("Appuyez sur ENTRÉE pour ouvrir le navigateur...")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page(viewport={'width': 1920, 'height': 1080})
    
    print("\n🌐 Ouverture de http://localhost:5000/connect")
    page.goto('http://localhost:5000/connect')
    
    print("⏳ Attente de 30 secondes pour connexion manuelle...")
    for i in range(30, 0, -1):
        print(f"   {i} secondes restantes...", end='\r')
        time.sleep(1)
    
    print("\n\n📸 Capture du dashboard...")
    
    # Naviguer vers le dashboard
    page.goto('http://localhost:5000/dashboard', wait_until='networkidle', timeout=15000)
    time.sleep(2)  # Attendre le rendu complet
    
    # Screenshot
    page.screenshot(path='logs/screenshots/dashboard_apres.png')
    print("   ✅ logs/screenshots/dashboard_apres.png")
    
    # Inspection CSS
    print("\n🔍 Inspection du CSS...")
    css_result = page.evaluate('''() => {
        const grid = document.querySelector('.stats-grid');
        if (!grid) return { error: 'stats-grid not found' };
        
        const styles = window.getComputedStyle(grid);
        return {
            gridTemplateColumns: styles.gridTemplateColumns,
            gap: styles.gap,
            display: styles.display,
            cardCount: grid.children.length,
            cardWidths: Array.from(grid.children).map(c => 
                Math.round(c.getBoundingClientRect().width)
            )
        };
    }''')
    
    if css_result.get('error'):
        print(f"   ❌ {css_result['error']}")
    else:
        print(f"   ✅ grid-template-columns: {css_result['gridTemplateColumns']}")
        print(f"   ✅ gap: {css_result['gap']}")
        print(f"   ✅ Nombre de cartes: {css_result['cardCount']}")
        print(f"   ✅ Largeurs des cartes: {css_result['cardWidths']}")
        
        # Vérifier si 6 colonnes égales
        if len(css_result['cardWidths']) == 6:
            if len(set(css_result['cardWidths'])) == 1:
                print(f"   ✅ PARFAIT: 6 colonnes égales de {css_result['cardWidths'][0]}px")
            else:
                print(f"   ⚠️  6 colonnes mais largeurs inégales")
        elif len(css_result['cardWidths']) > 6:
            print(f"   ❌ Trop de colonnes ({len(css_result['cardWidths'])})")
        else:
            print(f"   ❌ Pas assez de colonnes ({len(css_result['cardWidths'])})")
    
    # Overflow check
    print("\n📏 Vérification overflow...")
    overflow = page.evaluate('''() => {
        return {
            overflow: document.documentElement.scrollWidth > window.innerWidth,
            diff: document.documentElement.scrollWidth - window.innerWidth
        };
    }''')
    
    if overflow['overflow']:
        print(f"   ❌ OVERFLOW: +{overflow['diff']}px")
    else:
        print(f"   ✅ Pas d'overflow horizontal")
    
    # Sauvegarder les résultats
    results = {
        'css': css_result,
        'overflow': overflow,
        'screenshot': 'logs/screenshots/dashboard_apres.png'
    }
    
    with open('logs/dashboard_test_apres.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print("\n💾 Résultats sauvegardés: logs/dashboard_test_apres.json")
    
    print("\n" + "="*80)
    print(" TEST TERMINÉ - Vous pouvez fermer le navigateur")
    print("="*80 + "\n")
    
    time.sleep(5)
    browser.close()
