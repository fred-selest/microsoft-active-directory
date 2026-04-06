# -*- coding: utf-8 -*-
"""
Test des fonctions utilisateurs avec connexion automatique
Utilise les identifiants admin pour tester toutes les fonctionnalités
"""
from playwright.sync_api import sync_playwright
import time
import os
import json
from datetime import datetime

os.makedirs('logs/screenshots', exist_ok=True)
os.makedirs('logs/test_results', exist_ok=True)

print("\n" + "="*80)
print(" TEST FONCTIONS UTILISATEURS AVEC CONNEXION")
print("="*80)
print(f"\n📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("\n🔐 Mode de connexion:")
print("   1. Cookies sauvegardés (si disponibles)")
print("   2. Identifiants manuels (admin / ********)")
print("="*80 + "\n")

errors = []
screenshots = []
test_results = []
connected = False

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
    
    # Capture d'écran
    screenshot_path = f'logs/screenshots/{page_name}.png'
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
    # ÉTAPE 1: CONNEXION (COOKIES OU MANUELLE)
    # ========================================================================
    print("\n🔐 ÉTAPE 1: CONNEXION AU DOMAINE")
    print("-"*60)
    
    # Essayer de charger les cookies sauvegardés
    cookies_file = 'test_cookies.json'
    cookies_loaded = False
    
    if os.path.exists(cookies_file):
        print(f"   📂 Tentative de chargement des cookies depuis {cookies_file}...")
        try:
            with open(cookies_file, 'r', encoding='utf-8') as f:
                cookies = json.load(f)
            
            if isinstance(cookies, list) and len(cookies) > 0:
                context.add_cookies(cookies)
                print(f"   ✅ {len(cookies)} cookies chargés")
                cookies_loaded = True
                
                # Aller directement au dashboard pour tester
                page.goto('http://localhost:5000/dashboard', wait_until='networkidle', timeout=10000)
                time.sleep(2)
                
                if '/dashboard' in page.url or '/users' in page.url:
                    print("   ✅ CONNECTÉ VIA COOKIES")
                    connected = True
                else:
                    print("   ⚠️ Cookies expirés ou invalides")
                    cookies_loaded = False
            else:
                print("   ⚠️ Fichier cookies vide ou invalide")
        except Exception as e:
            print(f"   ⚠️ Erreur lecture cookies: {e}")
    
    # Si pas de cookies valides, essayer connexion manuelle
    if not cookies_loaded:
        print("   📝 Connexion manuelle avec identifiants...")
        
        try:
            page.goto('http://localhost:5000/connect', wait_until='networkidle', timeout=10000)
            time.sleep(2)
            
            # Remplir le formulaire de connexion
            username_input = page.query_selector('input[name="username"]')
            password_input = page.query_selector('input[name="password"]')
            
            if username_input and password_input:
                print("   📝 Formulaire de connexion trouvé")
                
                # Remplir identifiants
                username_input.fill('admin')
                password_input.fill('@Alfreddo68')
                
                print("   ✅ Identifiants remplis")
                
                # Soumettre
                submit_btn = page.query_selector('button[type="submit"]')
                if submit_btn:
                    submit_btn.click()
                    print("   🔄 Connexion en cours...")
                    time.sleep(5)  # Attendre plus longtemps pour la connexion AD
                    
                    # Vérifier si connecté
                    if '/dashboard' in page.url or '/users' in page.url:
                        print("   ✅ CONNECTÉ AVEC SUS")
                        connected = True
                        
                        # Sauvegarder les cookies pour la prochaine fois
                        cookies = context.cookies()
                        with open(cookies_file, 'w', encoding='utf-8') as f:
                            json.dump(cookies, f, indent=2)
                        print(f"   💾 {len(cookies)} cookies sauvegardés dans {cookies_file}")
                        
                    elif '/connect' in page.url:
                        error_div = page.query_selector('.alert-danger, .flash-error')
                        if error_div:
                            error_text = error_div.inner_text()
                            print(f"   ❌ ÉCHEC CONNEXION: {error_text}")
                            errors.append(f'Connexion échouée: {error_text}')
                            connected = False
                        else:
                            print("   ⚠️ Toujours sur page de connexion")
                            connected = False
                    else:
                        print(f"   ⚠️ URL après connexion: {page.url}")
                        connected = True
                else:
                    print("   ❌ Bouton submit non trouvé")
                    errors.append('Connexion: Bouton submit manquant')
                    connected = False
            else:
                print("   ❌ Formulaire de connexion non trouvé")
                errors.append('Connexion: Formulaire manquant')
                connected = False
            
            # Capture après connexion
            page.screenshot(path='logs/screenshots/00_after_login.png')
            
        except Exception as e:
            print(f"   ❌ ERREUR: {str(e)}")
            errors.append(f'Connexion: {str(e)}')
            connected = False
            page.screenshot(path='logs/screenshots/00_login_error.png')
    
    # ========================================================================
    # ÉTAPE 2: TEST PAGE UTILISATEURS
    # ========================================================================
    if connected:
        print("\n📋 ÉTAPE 2: TEST PAGE UTILISATEURS")
        print("-"*60)
        
        try:
            page.goto('http://localhost:5000/users/', wait_until='networkidle', timeout=10000)
            time.sleep(2)
            
            result = check_page_health(page, '01_users_list')
            
            # Vérifier tableau
            table = page.query_selector('table.data-table')
            if table:
                rows = page.query_selector_all('table.data-table tbody tr')
                result['warnings'].append(f'✅ Tableau avec {len(rows)} utilisateurs')
                print(f"   ✅ Tableau trouvé: {len(rows)} utilisateurs")
            else:
                result['warnings'].append('⚠️ Tableau vide')
                print("   ⚠️ Tableau vide")
            
            # Vérifier bouton Nouvel utilisateur
            create_btn = page.query_selector('a[href="/users/create"]')
            if create_btn:
                result['warnings'].append('✅ Bouton "Nouvel utilisateur" présent')
                print("   ✅ Bouton créer présent")
            else:
                result['errors'].append('❌ Bouton créer manquant')
                errors.append('users: Bouton créer manquant')
                print("   ❌ Bouton créer manquant")
            
            # Vérifier boutons d'action
            action_buttons = page.query_selector_all('td.actions button, td.actions a')
            if len(action_buttons) > 0:
                result['warnings'].append(f'✅ {len(action_buttons)} boutons d\'action')
                print(f"   ✅ {len(action_buttons)} boutons d'action")
            else:
                result['warnings'].append('⚠️ Aucun bouton d\'action')
                print("   ⚠️ Aucun bouton d'action")
            
            test_results.append(result)
            
        except Exception as e:
            print(f"   ❌ ERREUR: {str(e)}")
            errors.append(f'users: {str(e)}')
            test_results.append({'page': 'users_list', 'errors': [str(e)], 'warnings': []})
        
        # ========================================================================
        # ÉTAPE 3: TEST PAGE CRÉATION
        # ========================================================================
        print("\n➕ ÉTAPE 3: TEST PAGE CRÉATION")
        print("-"*60)
        
        try:
            page.goto('http://localhost:5000/users/create', wait_until='networkidle', timeout=10000)
            time.sleep(2)
            
            result = check_page_health(page, '02_users_create')
            
            # Vérifier champs
            fields_found = []
            fields_missing = []
            
            field_names = [
                ('username', 'Nom d\'utilisateur'),
                ('first_name', 'Prénom'),
                ('last_name', 'Nom'),
                ('password', 'Mot de passe'),
                ('email', 'Email'),
                ('department', 'Service'),
                ('title', 'Fonction'),
            ]
            
            for field_name, field_label in field_names:
                field_el = page.query_selector(f'input[name="{field_name}"]')
                if field_el:
                    fields_found.append(field_name)
                else:
                    fields_missing.append(field_name)
            
            # Select OU
            ou_select = page.query_selector('select[name="target_ou"]')
            if ou_select:
                fields_found.append('target_ou (select)')
            else:
                fields_missing.append('target_ou')
            
            result['warnings'].append(f'✅ Champs trouvés: {len(fields_found)}')
            if fields_missing:
                result['warnings'].append(f'⚠️ Champs manquants: {fields_missing}')
            
            print(f"   ✅ Champs: {len(fields_found)} trouvés")
            if fields_missing:
                print(f"   ⚠️ Manquants: {fields_missing}")
            
            # Vérifier bouton submit
            submit_btn = page.query_selector('button[type="submit"]')
            if submit_btn:
                result['warnings'].append('✅ Bouton submit présent')
                print("   ✅ Bouton submit présent")
            else:
                result['errors'].append('❌ Bouton submit manquant')
                errors.append('create: Bouton submit manquant')
                print("   ❌ Bouton submit manquant")
            
            # Vérifier bouton Annuler
            cancel_btn = page.query_selector('a[href="/users/"]')
            if cancel_btn:
                result['warnings'].append('✅ Bouton Annuler présent')
                print("   ✅ Bouton Annuler présent")
            
            test_results.append(result)
            
        except Exception as e:
            print(f"   ❌ ERREUR: {str(e)}")
            errors.append(f'create: {str(e)}')
            test_results.append({'page': 'users_create', 'errors': [str(e)], 'warnings': []})
        
        # ========================================================================
        # ÉTAPE 4: TEST TOGGLE (activer/désactiver)
        # ========================================================================
        print("\n🔄 ÉTAPE 4: TEST FORMULAIRES TOGGLE")
        print("-"*60)
        
        try:
            page.goto('http://localhost:5000/users/', wait_until='networkidle', timeout=10000)
            time.sleep(2)
            
            result = {'page': 'users_toggle', 'errors': [], 'warnings': []}
            
            # Vérifier formulaires toggle
            toggle_forms = page.query_selector_all('form[id*="toggle-form"]')
            
            if len(toggle_forms) > 0:
                result['warnings'].append(f'✅ {len(toggle_forms)} formulaires toggle')
                print(f"   ✅ {len(toggle_forms)} formulaires toggle trouvés")
                
                # Vérifier structure premier formulaire
                first_form = toggle_forms[0]
                has_csrf = first_form.query_selector('input[name="csrf_token"]') is not None
                has_action = first_form.query_selector('input[name="action"]') is not None
                
                if has_csrf:
                    result['warnings'].append('✅ Token CSRF présent')
                else:
                    result['errors'].append('❌ Token CSRF manquant')
                    errors.append('toggle: CSRF manquant')
                
                if has_action:
                    result['warnings'].append('✅ Champ action présent')
                else:
                    result['errors'].append('❌ Champ action manquant')
                    errors.append('toggle: Champ action manquant')
            else:
                result['warnings'].append('⚠️ Aucun formulaire toggle (tableau vide ?)')
                print("   ⚠️ Aucun formulaire toggle")
            
            test_results.append(result)
            print(f"   ✅ Toggle vérifié")
            
        except Exception as e:
            print(f"   ❌ ERREUR: {str(e)}")
            errors.append(f'toggle: {str(e)}')
            test_results.append({'page': 'users_toggle', 'errors': [str(e)], 'warnings': []})
        
        # ========================================================================
        # ÉTAPE 5: TEST MODAL DÉPLACEMENT
        # ========================================================================
        print("\n📍 ÉTAPE 5: TEST MODAL DÉPLACEMENT")
        print("-"*60)
        
        try:
            page.goto('http://localhost:5000/users/', wait_until='networkidle', timeout=10000)
            time.sleep(2)
            
            result = {'page': 'users_move', 'errors': [], 'warnings': []}
            
            # Vérifier boutons de déplacement
            move_buttons = page.query_selector_all('button[onclick*="showMoveModal"]')
            
            if len(move_buttons) > 0:
                result['warnings'].append(f'✅ {len(move_buttons)} boutons déplacer')
                print(f"   ✅ {len(move_buttons)} boutons déplacer")
            else:
                result['warnings'].append('⚠️ Aucun bouton déplacer')
                print("   ⚠️ Aucun bouton déplacer")
            
            # Vérifier modal dans le DOM
            move_modal = page.query_selector('#moveModal')
            if move_modal:
                result['warnings'].append('✅ Modal déplacement présent dans le DOM')
                print("   ✅ Modal présent dans le DOM")
                
                # Vérifier structure du modal
                modal_form = move_modal.query_selector('form')
                if modal_form:
                    result['warnings'].append('✅ Formulaire dans le modal')
                
                modal_select = move_modal.query_selector('select[name="new_ou"]')
                if modal_select:
                    result['warnings'].append('✅ Select OU dans le modal')
            else:
                result['warnings'].append('⚠️ Modal non trouvé')
                print("   ⚠️ Modal non trouvé")
            
            test_results.append(result)
            
        except Exception as e:
            print(f"   ❌ ERREUR: {str(e)}")
            errors.append(f'move: {str(e)}')
            test_results.append({'page': 'users_move', 'errors': [str(e)], 'warnings': []})
        
        # ========================================================================
        # ÉTAPE 6: TEST RESET PASSWORD
        # ========================================================================
        print("\n🔑 ÉTAPE 6: TEST LIENS RESET MDP")
        print("-"*60)
        
        try:
            page.goto('http://localhost:5000/users/', wait_until='networkidle', timeout=10000)
            time.sleep(2)
            
            result = {'page': 'users_reset', 'errors': [], 'warnings': []}
            
            # Vérifier liens reset password
            reset_links = page.query_selector_all('a[href*="/reset-password"]')
            
            if len(reset_links) > 0:
                result['warnings'].append(f'✅ {len(reset_links)} liens reset MDP')
                print(f"   ✅ {len(reset_links)} liens reset MDP")
            else:
                result['warnings'].append('⚠️ Aucun lien reset MDP')
                print("   ⚠️ Aucun lien reset MDP")
            
            test_results.append(result)
            
        except Exception as e:
            print(f"   ❌ ERREUR: {str(e)}")
            errors.append(f'reset: {str(e)}')
            test_results.append({'page': 'users_reset', 'errors': [str(e)], 'warnings': []})
        
        # ========================================================================
        # ÉTAPE 7: TEST SUPPRESSION
        # ========================================================================
        print("\n🗑️ ÉTAPE 7: TEST FORMULAIRES SUPPRESSION")
        print("-"*60)
        
        try:
            page.goto('http://localhost:5000/users/', wait_until='networkidle', timeout=10000)
            time.sleep(2)
            
            result = {'page': 'users_delete', 'errors': [], 'warnings': []}
            
            # Vérifier formulaires de suppression
            delete_forms = page.query_selector_all('form[action*="/delete"]')
            
            if len(delete_forms) > 0:
                result['warnings'].append(f'✅ {len(delete_forms)} formulaires suppression')
                print(f"   ✅ {len(delete_forms)} formulaires suppression")
                
                # Vérifier CSRF
                first_form = delete_forms[0]
                has_csrf = first_form.query_selector('input[name="csrf_token"]') is not None
                
                if has_csrf:
                    result['warnings'].append('✅ Token CSRF présent')
                else:
                    result['errors'].append('❌ Token CSRF manquant')
                    errors.append('delete: CSRF manquant')
            else:
                result['warnings'].append('⚠️ Aucun formulaire suppression')
                print("   ⚠️ Aucun formulaire suppression")
            
            test_results.append(result)
            
        except Exception as e:
            print(f"   ❌ ERREUR: {str(e)}")
            errors.append(f'delete: {str(e)}')
            test_results.append({'page': 'users_delete', 'errors': [str(e)], 'warnings': []})
        
        # ========================================================================
        # ÉTAPE 8: TEST RECHERCHE
        # ========================================================================
        print("\n🔍 ÉTAPE 8: TEST RECHERCHE UTILISATEURS")
        print("-"*60)
        
        try:
            page.goto('http://localhost:5000/users/', wait_until='networkidle', timeout=10000)
            time.sleep(2)
            
            result = check_page_health(page, '03_users_search')
            
            # Vérifier champ recherche
            search_input = page.query_selector('input[name="search"]')
            if search_input:
                result['warnings'].append('✅ Champ recherche présent')
                print("   ✅ Champ recherche présent")
                
                # Tester recherche
                search_input.fill('admin')
                time.sleep(1)
                
                # Soumettre (le champ devrait auto-soumettre après 500ms)
                search_input.press('Enter')
                time.sleep(2)
                
                result['warnings'].append('✅ Recherche testée')
                print("   ✅ Recherche testée")
            else:
                result['warnings'].append('⚠️ Champ recherche non trouvé')
                print("   ⚠️ Champ recherche non trouvé")
            
            test_results.append(result)
            
        except Exception as e:
            print(f"   ❌ ERREUR: {str(e)}")
            errors.append(f'search: {str(e)}')
            test_results.append({'page': 'users_search', 'errors': [str(e)], 'warnings': []})
    
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
    else:
        print("\n✅ AUCUNE ERREUR DÉTECTÉE !")
    
    # Sauvegarder rapport JSON
    report = {
        'timestamp': datetime.now().isoformat(),
        'connected': connected,
        'total_pages': len(test_results),
        'total_errors': total_errors,
        'total_warnings': total_warnings,
        'results': test_results,
        'errors': errors,
        'screenshots': screenshots
    }
    
    report_path = f'logs/test_results/users_connected_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
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
