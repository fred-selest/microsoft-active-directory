# -*- coding: utf-8 -*-
"""
Test des connexions avec les différents modules
"""
import sys
import os

# Ajouter le répertoire parent au path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_import(module_name, import_path):
    """Tester l'import d'un module."""
    try:
        exec(f"import {import_path}")
        print(f"✓ {module_name}: OK")
        return True
    except Exception as e:
        print(f"✗ {module_name}: ÉCHEC - {e}")
        return False


def test_function(module_path, function_name):
    """Tester l'existence d'une fonction."""
    try:
        exec(f"from {module_path} import {function_name}")
        print(f"✓ {module_path}.{function_name}: OK")
        return True
    except Exception as e:
        print(f"✗ {module_path}.{function_name}: ÉCHEC - {e}")
        return False


def main():
    print("=" * 60)
    print("TEST DES CONNEXIONS MODULES")
    print("=" * 60)
    print()
    
    results = []
    
    # 1. Modules principaux
    print("1. MODULES PRINCIPAUX:")
    results.append(test_import("config", "config"))
    results.append(test_import("app", "app"))
    results.append(test_import("audit", "audit"))
    results.append(test_import("security", "security"))
    results.append(test_import("session_crypto", "session_crypto"))
    results.append(test_import("backup", "backup"))
    results.append(test_import("alerts", "alerts"))
    results.append(test_import("ad_detect", "ad_detect"))
    results.append(test_import("diagnostic", "diagnostic"))
    results.append(test_import("translations", "translations"))
    print()
    
    # 2. Package password_audit
    print("2. PACKAGE PASSWORD_AUDIT:")
    results.append(test_import("password_audit", "password_audit"))
    results.append(test_function("password_audit", "run_password_audit"))
    results.append(test_function("password_audit", "check_weak_passwords"))
    results.append(test_function("password_audit", "check_admin_weak_passwords"))
    results.append(test_function("password_audit", "check_service_accounts"))
    results.append(test_function("password_audit", "generate_auditor_issues"))
    results.append(test_function("password_audit", "export_audit_to_csv"))
    results.append(test_function("password_audit", "export_audit_to_json"))
    results.append(test_function("password_audit.analyzer", "get_password_policy"))
    results.append(test_function("password_audit.checks", "check_password_age"))
    results.append(test_function("password_audit.protocol", "check_legacy_protocols"))
    results.append(test_function("password_audit.admin", "check_admin_weak_passwords"))
    results.append(test_function("password_audit.report", "generate_auditor_issues"))
    results.append(test_function("password_audit.runner", "run_password_audit"))
    results.append(test_function("password_audit.export", "export_audit_to_csv"))
    print()
    
    # 3. Routes
    print("3. ROUTES:")
    results.append(test_import("routes.core", "routes.core"))
    results.append(test_import("routes.users", "routes.users"))
    results.append(test_import("routes.groups", "routes.groups"))
    results.append(test_import("routes.computers", "routes.computers"))
    results.append(test_import("routes.ous", "routes.ous"))
    results.append(test_import("routes.admin", "routes.admin"))
    results.append(test_import("routes.tools", "routes.tools"))
    results.append(test_import("routes.tools.password", "routes.tools.password"))
    results.append(test_import("routes.tools.laps", "routes.tools.laps"))
    results.append(test_import("routes.tools.accounts", "routes.tools.accounts"))
    print()
    
    # 4. Blueprints
    print("4. BLUEPRINTS:")
    results.append(test_function("routes.core", "core_bp"))
    results.append(test_function("routes.users", "users_bp"))
    results.append(test_function("routes.groups", "groups_bp"))
    results.append(test_function("routes.computers", "computers_bp"))
    results.append(test_function("routes.ous", "ous_bp"))
    results.append(test_function("routes.admin", "admin_bp"))
    results.append(test_function("routes.tools", "tools_bp"))
    print()
    
    # 5. Fonctions de sécurité
    print("5. SÉCURITÉ:")
    results.append(test_function("security", "escape_ldap_filter"))
    results.append(test_function("security", "generate_csrf_token"))
    results.append(test_function("security", "validate_csrf_token"))
    results.append(test_function("security", "rate_limit"))
    results.append(test_function("session_crypto", "encrypt_password"))
    results.append(test_function("session_crypto", "decrypt_password"))
    print()
    
    # 6. Audit
    print("6. AUDIT:")
    results.append(test_function("audit", "log_action"))
    results.append(test_function("audit", "get_audit_logs"))
    results.append(test_function("audit_history", "save_audit"))
    results.append(test_function("audit_history", "get_audit_history"))
    results.append(test_function("audit_history", "get_history_stats"))
    print()
    
    # Résumé
    print("=" * 60)
    print(f"RÉSULTATS: {sum(results)}/{len(results)} tests réussis")
    print("=" * 60)
    
    if all(results):
        print("✅ TOUS LES TESTS ONT RÉUSSI")
        return 0
    else:
        print("❌ CERTAINS TESTS ONT ÉCHOUÉ")
        return 1


if __name__ == "__main__":
    sys.exit(main())
