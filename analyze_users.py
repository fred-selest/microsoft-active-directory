#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script d'analyse et de correction automatique de routes/users.py
"""
import re
import sys

def analyze_users_py():
    """Analyser users.py et corriger les erreurs courantes."""
    
    with open('routes/users.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    errors_found = []
    corrections = []
    
    # 1. Vérifier les attributs LDAP ['*']
    if "attributes=['*']" in content:
        errors_found.append("❌ attributes=['*'] - Peut causer des erreurs LDAP")
        corrections.append("✅ Remplacer par des attributs spécifiques")
    
    # 2. Vérifier les conn.search sans gestion d'erreur
    search_count = content.count('conn.search(')
    try_count = content.count('try:')
    if search_count > try_count:
        errors_found.append(f"❌ {search_count} search() mais seulement {try_count} try:")
        corrections.append("✅ Ajouter des try/except autour des search()")
    
    # 3. Vérifier les conn.unbind() manquants dans except
    except_count = content.count('except')
    unbind_in_except = content.count('except Exception as e:')
    
    # 4. Vérifier les flash() sans message d'erreur précis
    flash_errors = re.findall(r"flash\(f'Erreur: {str\(e\)}'\)", content)
    if flash_errors:
        errors_found.append(f"❌ {len(flash_errors)} messages d'erreur génériques")
        corrections.append("✅ Messages d'erreur plus précis")
    
    # 5. Vérifier les decode_ldap_value non protégés
    decode_calls = re.findall(r'decode_ldap_value\(entry\.(\w+)\)', content)
    if decode_calls:
        errors_found.append(f"⚠️ decode_ldap_value utilisé {len(decode_calls)} fois sans vérification")
        corrections.append("✅ Vérifier hasattr avant decode_ldap_value")
    
    # 6. Vérifier les conn.result sans .get()
    result_direct = re.findall(r"conn\.result\['(\w+)'\]", content)
    if result_direct:
        errors_found.append(f"⚠️ {len(result_direct)} accès direct à conn.result")
        corrections.append("✅ Utiliser conn.result.get() pour éviter KeyError")
    
    # Affichage des résultats
    print("=" * 70)
    print("📊 ANALYSE DE routes/users.py")
    print("=" * 70)
    print()
    
    if errors_found:
        print("🔴 ERREURS TROUVÉES:")
        for i, error in enumerate(errors_found, 1):
            print(f"  {i}. {error}")
        print()
        
        if corrections:
            print("🟢 CORRECTIONS RECOMMANDÉES:")
            for i, correction in enumerate(corrections, 1):
                print(f"  {i}. {correction}")
        print()
    else:
        print("✅ Aucune erreur critique trouvée")
        print()
    
    # Statistiques
    print("📈 STATISTIQUES:")
    print(f"  - Lignes: {len(content.splitlines())}")
    print(f"  - Fonctions: {content.count('def ')}")
    print(f"  - conn.search(): {search_count}")
    print(f"  - conn.modify(): {content.count('conn.modify(')}")
    print(f"  - conn.delete(): {content.count('conn.delete(')}")
    print(f"  - try/except: {try_count}")
    print(f"  - logger: {content.count('logger.')}")
    print()
    
    # Fonctions à risque
    print("🔍 FONCTIONS À VÉRIFIER:")
    functions = re.findall(r'def (\w+)\([^)]*\):', content)
    risky_functions = ['delete_user', 'reset_password', 'toggle_user', 'create_user', 'move_user']
    for func in risky_functions:
        if func in functions:
            print(f"  ✓ {func}")
    print()
    
    return len(errors_found) == 0


if __name__ == '__main__':
    success = analyze_users_py()
    sys.exit(0 if success else 1)
