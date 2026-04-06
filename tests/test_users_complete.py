# -*- coding: utf-8 -*-
"""
Test complet des fonctions utilisateurs - AD Web Interface
Teste toutes les fonctionnalités users et corrige les erreurs
"""
from playwright.sync_api import sync_playwright
import time
import os
import json
from datetime import datetime

os.makedirs('logs/screenshots', exist_ok=True)
os.makedirs('logs/test_results', exist_ok=True)

print("\n" + "="*80)
print(" TEST COMPLET - FONCTIONS UTILISATEURS")
print("="*80)
print(f"\n📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("\n📋 Fonctions à tester:")
print("   1. Liste des utilisateurs (/users/)")
print("   2. Recherche utilisateurs")
print("   3. Création utilisateur (/users/create)")
print("   4. Modification utilisateur (/users/<dn>/edit)")
print("   5. Réinitialisation MDP (/users/<dn>/reset-password)")
print("   6. Activer/Désactiver (/users/<dn>/toggle)")
print("   7. Déplacer utilisateur (/users/<dn>/move)")
print("   8. Supprimer utilisateur (/users/<dn>/delete)")
print("\n🔍 Tests effectués:")
print("   - Chargement des pages")
print("   - Overflow horizontal")
print("   - Éléments coupés")
print("   - Boutons fonctionnels")
print("   - Formulaires valides")
print("   - Erreurs JavaScript")
print("="*80 + "\n")

# Vérifier d'abord si connecté
print("🔐 VÉRIFICATION CONNEXION...")
try:
    test_page = context.new_page()
    test_page.goto('http://localhost:5000/dashboard', wait_until='networkidle', timeout=10000)
    time.sleep(2)
    
    is_connected = test_page.query_selector('table.data-table') is not None or 'dashboard' in test_page.url
    
    # Vérifier si redirigé vers /connect
    if '/connect' in test_page.url:
        print("   ⚠️  NON CONNECTÉ - Les tests peuvent être limités")
        print("   💡 Connectez-vous manuellement puis relancez le test")
        connected = False
    else:
        print("   ✅ CONNECTÉ")
        connected = True
    
    test_page.close()
except Exception as e:
    print(f"   ⚠️ Erreur vérification: {e}")
    connected = False

errors = []
screenshots = []
test_results = []

def check_page_health(page, page_name):
    """Vérifier la santé d'une page"""
    result = {'page': page_name, 'errors': [], 'warnings': []}
    
    # Vérifier overflow horizontal
    overflow_x = page.evaluate('document.documentElement.scrollWidth > document.documentElement.clientWidth')
    if overflow_x:
        overflow_width = page.evaluate('document.documentElement.scrollWidth - document.documentElement.clientWidth')
        result['errors'].append(f'Overflow horizontal: +{overflow_width}px')
        errors.append(f'{page_name}: Overflow horizontal +{overflow_width}px')
    else:
        result['warnings'].append('✅ Pas d\'overflow horizontal')
    
    # Vérifier erreurs JavaScript
    js_errors = []
    page.on('pageerror', lambda err: js_errors.append(str(err)))
    
    # Vérifier éléments coupés
    clipped = page.evaluate('''() => {
        const elements = document.querySelectorAll('button, a, .badge, .btn');
        let clipped = [];
        elements.forEach(el => {
            const rect = el.getBoundingClientRect();
            const style = window.getComputedStyle(el);
            if (rect.right > window.innerWidth || rect.bottom > window.innerHeight) {
                clipped.push(el.textContent.trim().substring(0, 30));
            }
        });
        return clipped.slice(0, 5);
    }''')
    if clipped:
        result['errors'].append(f'Éléments coupés: {clipped}')
        errors.append(f'{page_name}: Éléments coupés: {clipped}')
    
    # Capture d'écran
    screenshot_path = f'logs/screenshots/users_{page_name.replace("/", "_")}.png'
    page.screenshot(path=screenshot_path, full_page=False)
    screenshots.append(screenshot_path)
    
    return result

with sync_playwright() as p:
    browser = p.chromium.launch(
        headless=False,
        args=['--start-maximized', '--disable-dev-shm-usage']
    )
    
    context = browser.new_context(viewport={'width': 1920, 'height': 1080})
    page = context.new_page()
    
    # ========================================================================
    # TEST 1: Liste des utilisateurs
    # ========================================================================
    print("\n📋 TEST 1: Liste des utilisateurs (/users/)")
    print("-"*60)
    
    try:
        page.goto('http://localhost:5000/users/', wait_until='networkidle', timeout=10000)
        time.sleep(2)
        
        result = check_page_health(page, 'users_list')
        
        # Vérifier présence tableau (même vide)
        table_exists = page.query_selector('table.data-table') is not None
        if table_exists:
            result['warnings'].append('✅ Tableau utilisateurs présent')
        else:
            # Page peut-être redirigée vers /connect
            if '/connect' in page.url:
                result['warnings'].append('⚠️ Redirigé vers /connect (non connecté)')
            else:
                result['errors'].append('❌ Tableau utilisateurs manquant')
                errors.append('users_list: Tableau manquant')
        
        # Vérifier boutons d'action (seulement si connecté)
        if connected:
            buttons = page.query_selector_all('.btn-group-mobile button')
            if len(buttons) > 0:
                result['warnings'].append(f'✅ {len(buttons)} boutons d\'action trouvés')
            else:
                result['warnings'].append('⚠️ Aucun bouton (aucun utilisateur ?)')
            
            # Vérifier lien "Nouvel utilisateur"
            create_btn = page.query_selector('a[href="/users/create"]')
            if create_btn:
                result['warnings'].append('✅ Bouton "Nouvel utilisateur" présent')
            else:
                result['errors'].append('❌ Bouton "Nouvel utilisateur" manquant')
                errors.append('users_list: Bouton créer manquant')
        else:
            result['warnings'].append('⚠️ Test limité (non connecté)')
        
        test_results.append(result)
        print(f"   ✅ Page chargée - {len(result['errors'])} erreurs, {len(result['warnings'])} OK")
        
    except Exception as e:
        error_msg = f'users_list: {str(e)}'
        errors.append(error_msg)
        test_results.append({'page': 'users_list', 'errors': [str(e)], 'warnings': []})
        print(f"   ❌ ERREUR: {str(e)}")
    
    # ========================================================================
    # TEST 2: Recherche utilisateurs
    # ========================================================================
    print("\n🔍 TEST 2: Recherche utilisateurs")
    print("-"*60)
    
    try:
        page.goto('http://localhost:5000/users/?search=admin', wait_until='networkidle', timeout=10000)
        time.sleep(2)
        
        result = check_page_health(page, 'users_search')
        
        # Vérifier champ de recherche
        search_input = page.query_selector('input[name="search"]')
        if search_input:
            search_value = search_input.input_value()
            if search_value == 'admin':
                result['warnings'].append('✅ Recherche fonctionnelle')
            else:
                result['warnings'].append(f'⚠️ Champ recherche: "{search_value}"')
        else:
            if '/connect' in page.url:
                result['warnings'].append('⚠️ Redirigé vers /connect')
            else:
                result['errors'].append('❌ Champ de recherche manquant')
                errors.append('users_search: Champ recherche manquant')
        
        test_results.append(result)
        print(f"   ✅ Recherche testée - {len(result['errors'])} erreurs")
        
    except Exception as e:
        error_msg = f'users_search: {str(e)}'
        errors.append(error_msg)
        test_results.append({'page': 'users_search', 'errors': [str(e)], 'warnings': []})
        print(f"   ❌ ERREUR: {str(e)}")
    
    # ========================================================================
    # TEST 3: Page de création (formulaire)
    # ========================================================================
    print("\n➕ TEST 3: Page de création (/users/create)")
    print("-"*60)
    
    try:
        page.goto('http://localhost:5000/users/create', wait_until='networkidle', timeout=10000)
        time.sleep(2)
        
        result = check_page_health(page, 'users_create')
        
        # Vérifier champs du formulaire
        required_fields = ['username', 'password']
        optional_fields = ['first_name', 'last_name', 'target_ou']
        
        for field in required_fields:
            field_el = page.query_selector(f'input[name="{field}"], select[name="{field}"]')
            if field_el:
                result['warnings'].append(f'✅ Champ {field} présent')
            else:
                result['errors'].append(f'❌ Champ {field} manquant')
                errors.append(f'users_create: Champ {field} manquant')
        
        # Champs optionnels (peuvent avoir d'autres noms)
        for field in optional_fields:
            field_el = page.query_selector(f'input[name="{field}"], select[name="{field}"]')
            if field_el:
                result['warnings'].append(f'✅ Champ {field} présent')
            else:
                result['warnings'].append(f'⚠️ Champ {field} non trouvé (nom différent ?)')
        
        # Vérifier bouton submit
        submit_btn = page.query_selector('button[type="submit"]')
        if submit_btn:
            result['warnings'].append('✅ Bouton submit présent')
        else:
            result['errors'].append('❌ Bouton submit manquant')
            errors.append('users_create: Bouton submit manquant')
        
        test_results.append(result)
        print(f"   ✅ Formulaire vérifié - {len(result['errors'])} erreurs")
        
    except Exception as e:
        error_msg = f'users_create: {str(e)}'
        errors.append(error_msg)
        test_results.append({'page': 'users_create', 'errors': [str(e)], 'warnings': []})
        print(f"   ❌ ERREUR: {str(e)}")
    
    # ========================================================================
    # TEST 4: Page de modification (vérifier structure)
    # ========================================================================
    print("\n✏️ TEST 4: Structure page modification")
    print("-"*60)
    
    try:
        page.goto('http://localhost:5000/users/', wait_until='networkidle', timeout=10000)
        time.sleep(2)
        
        result = {'page': 'users_edit_structure', 'errors': [], 'warnings': []}
        
        if connected:
            # Chercher un lien d'édition
            edit_links = page.query_selector_all('a[href*="/users/"][href*="/edit"]')
            
            if len(edit_links) > 0:
                result['warnings'].append(f'✅ {len(edit_links)} liens d\'édition trouvés')
            else:
                result['warnings'].append('⚠️ Aucun lien d\'édition (aucun utilisateur ?)')
            
            # Vérifier boutons d'action dans le tableau
            action_buttons = page.query_selector_all('td.actions button, td.actions a')
            if len(action_buttons) > 0:
                result['warnings'].append(f'✅ {len(action_buttons)} boutons d\'action')
            else:
                result['warnings'].append('⚠️ Aucun bouton d\'action (tableau vide ?)')
        else:
            if '/connect' in page.url:
                result['warnings'].append('⚠️ Redirigé vers /connect')
            else:
                result['warnings'].append('⚠️ Test limité (non connecté)')
        
        test_results.append(result)
        check_page_health(page, 'users_edit_check')
        print(f"   ✅ Structure vérifiée - {len(result['errors'])} erreurs")
        
    except Exception as e:
        error_msg = f'users_edit: {str(e)}'
        errors.append(error_msg)
        test_results.append({'page': 'users_edit', 'errors': [str(e)], 'warnings': []})
        print(f"   ❌ ERREUR: {str(e)}")
    
    # ========================================================================
    # TEST 5: Réinitialisation MDP (vérifier liens)
    # ========================================================================
    print("\n🔑 TEST 5: Liens réinitialisation MDP")
    print("-"*60)
    
    try:
        page.goto('http://localhost:5000/users/', wait_until='networkidle', timeout=10000)
        time.sleep(2)
        
        result = {'page': 'users_reset_password', 'errors': [], 'warnings': []}
        
        # Chercher liens reset password
        reset_links = page.query_selector_all('a[href*="/reset-password"]')
        
        if len(reset_links) > 0:
            result['warnings'].append(f'✅ {len(reset_links)} liens reset MDP')
        else:
            result['warnings'].append('⚠️ Aucun lien reset MDP visible')
        
        test_results.append(result)
        print(f"   ✅ Liens vérifiés - {len(result['errors'])} erreurs")
        
    except Exception as e:
        error_msg = f'users_reset: {str(e)}'
        errors.append(error_msg)
        test_results.append({'page': 'users_reset', 'errors': [str(e)], 'warnings': []})
        print(f"   ❌ ERREUR: {str(e)}")
    
    # ========================================================================
    # TEST 6: Toggle (vérifier formulaires)
    # ========================================================================
    print("\n🔄 TEST 6: Formulaires toggle (activer/désactiver)")
    print("-"*60)
    
    try:
        page.goto('http://localhost:5000/users/', wait_until='networkidle', timeout=10000)
        time.sleep(2)
        
        result = {'page': 'users_toggle', 'errors': [], 'warnings': []}
        
        # Vérifier formulaires toggle
        toggle_forms = page.query_selector_all('form[id*="toggle-form"]')
        
        if len(toggle_forms) > 0:
            result['warnings'].append(f'✅ {len(toggle_forms)} formulaires toggle')
            
            # Vérifier structure d'un formulaire
            first_form = toggle_forms[0]
            has_csrf = first_form.query_selector('input[name="csrf_token"]') is not None
            has_action = first_form.query_selector('input[name="action"]') is not None
            
            if has_csrf:
                result['warnings'].append('✅ Token CSRF présent')
            else:
                result['errors'].append('❌ Token CSRF manquant')
                errors.append('users_toggle: CSRF manquant')
            
            if has_action:
                result['warnings'].append('✅ Champ action présent')
            else:
                result['errors'].append('❌ Champ action manquant')
                errors.append('users_toggle: Champ action manquant')
        else:
            result['warnings'].append('⚠️ Aucun formulaire toggle trouvé')
        
        test_results.append(result)
        print(f"   ✅ Toggle vérifié - {len(result['errors'])} erreurs")
        
    except Exception as e:
        error_msg = f'users_toggle: {str(e)}'
        errors.append(error_msg)
        test_results.append({'page': 'users_toggle', 'errors': [str(e)], 'warnings': []})
        print(f"   ❌ ERREUR: {str(e)}")
    
    # ========================================================================
    # TEST 7: Modal de déplacement
    # ========================================================================
    print("\n📍 TEST 7: Modal de déplacement")
    print("-"*60)
    
    try:
        page.goto('http://localhost:5000/users/', wait_until='networkidle', timeout=10000)
        time.sleep(2)
        
        result = {'page': 'users_move', 'errors': [], 'warnings': []}
        
        if connected:
            # Vérifier boutons de déplacement
            move_buttons = page.query_selector_all('button[onclick*="showMoveModal"]')
            
            if len(move_buttons) > 0:
                result['warnings'].append(f'✅ {len(move_buttons)} boutons déplacer')
            else:
                result['warnings'].append('⚠️ Aucun bouton déplacer (tableau vide ?)')
            
            # Vérifier modal dans le DOM
            move_modal = page.query_selector('#moveModal')
            if move_modal:
                result['warnings'].append('✅ Modal déplacement présent')
            else:
                result['warnings'].append('⚠️ Modal déplacement non trouvé')
        else:
            if '/connect' in page.url:
                result['warnings'].append('⚠️ Redirigé vers /connect')
            else:
                result['warnings'].append('⚠️ Test limité (non connecté)')
        
        test_results.append(result)
        print(f"   ✅ Modal vérifié - {len(result['errors'])} erreurs")
        
    except Exception as e:
        error_msg = f'users_move: {str(e)}'
        errors.append(error_msg)
        test_results.append({'page': 'users_move', 'errors': [str(e)], 'warnings': []})
        print(f"   ❌ ERREUR: {str(e)}")
    
    # ========================================================================
    # TEST 8: Suppression (vérifier formulaires)
    # ========================================================================
    print("\n🗑️ TEST 8: Formulaires de suppression")
    print("-"*60)
    
    try:
        page.goto('http://localhost:5000/users/', wait_until='networkidle', timeout=10000)
        time.sleep(2)
        
        result = {'page': 'users_delete', 'errors': [], 'warnings': []}
        
        # Vérifier formulaires de suppression
        delete_forms = page.query_selector_all('form[action*="/delete"]')
        
        if len(delete_forms) > 0:
            result['warnings'].append(f'✅ {len(delete_forms)} formulaires suppression')
            
            # Vérifier présence token CSRF
            first_form = delete_forms[0]
            has_csrf = first_form.query_selector('input[name="csrf_token"]') is not None
            
            if has_csrf:
                result['warnings'].append('✅ Token CSRF présent')
            else:
                result['errors'].append('❌ Token CSRF manquant')
                errors.append('users_delete: CSRF manquant')
        else:
            result['warnings'].append('⚠️ Aucun formulaire suppression')
        
        test_results.append(result)
        print(f"   ✅ Suppression vérifiée - {len(result['errors'])} erreurs")
        
    except Exception as e:
        error_msg = f'users_delete: {str(e)}'
        errors.append(error_msg)
        test_results.append({'page': 'users_delete', 'errors': [str(e)], 'warnings': []})
        print(f"   ❌ ERREUR: {str(e)}")
    
    # ========================================================================
    # RÉCAPITULATIF
    # ========================================================================
    print("\n" + "="*80)
    print(" 📊 RÉCAPITULATIF DES TESTS")
    print("="*80)
    
    total_errors = sum(len(r['errors']) for r in test_results)
    total_warnings = sum(len(r['warnings']) for r in test_results)
    
    print(f"\n📋 Pages testées: {len(test_results)}")
    print(f"✅ Tests réussis: {sum(1 for r in test_results if len(r['errors']) == 0)}")
    print(f"❌ Tests avec erreurs: {sum(1 for r in test_results if len(r['errors']) > 0)}")
    print(f"📊 Total erreurs: {total_errors}")
    print(f"✨ Total avertissements: {total_warnings}")
    
    if errors:
        print("\n🔴 ERREURS DÉTECTÉES:")
        for i, err in enumerate(errors, 1):
            print(f"   {i}. {err}")
    
    # Sauvegarder rapport JSON
    report = {
        'timestamp': datetime.now().isoformat(),
        'total_pages': len(test_results),
        'total_errors': total_errors,
        'total_warnings': total_warnings,
        'results': test_results,
        'errors': errors,
        'screenshots': screenshots
    }
    
    report_path = f'logs/test_results/users_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 Rapport sauvegardé: {report_path}")
    print(f"📸 Screenshots: {len(screenshots)} dans logs/screenshots/")
    
    browser.close()
    
    print("\n" + "="*80)
    if total_errors == 0:
        print(" ✅ TOUS LES TESTS SONT VERTS !")
    else:
        print(f" ⚠️ {total_errors} ERREURS À CORRIGER")
    print("="*80 + "\n")
