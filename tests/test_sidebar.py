"""
Test sidebar toggle functionality
"""
from playwright.sync_api import sync_playwright
import time

print("\n🔍 Test Sidebar Toggle\n")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)  # Visible pour debug
    page = browser.new_page(viewport={'width': 1920, 'height': 1080})
    
    page.goto('http://localhost:5000/connect')
    page.wait_for_load_state('networkidle')
    
    # Vérifier si le bouton toggle est visible
    toggle_button = page.query_selector('#sidebarToggle')
    if toggle_button:
        print("✅ Bouton sidebar-toggle trouvé")
        
        # Vérifier s'il est visible
        is_visible = toggle_button.is_visible()
        print(f"   Visible: {is_visible}")
        
        # Cliquer dessus
        print("\n📱 Clic sur le bouton...")
        toggle_button.click()
        time.sleep(0.5)
        
        # Vérifier si la sidebar est ouverte
        sidebar = page.query_selector('#sidebar')
        if sidebar:
            has_open_class = sidebar.evaluate('el => el.classList.contains("open")')
            transform = sidebar.evaluate('el => el.style.transform')
            print(f"   Sidebar classe 'open': {has_open_class}")
            print(f"   Transform: {transform}")
            
            # Screenshot
            page.screenshot(path='logs/test_sidebar_open.png')
            print("\n✅ Screenshot: logs/test_sidebar_open.png")
    else:
        print("❌ Bouton sidebar-toggle NON trouvé")
    
    time.sleep(3)  # Garder ouvert pour voir
    browser.close()

print("\n✅ Test terminé\n")
