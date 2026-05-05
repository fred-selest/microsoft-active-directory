import sys
sys.path.insert(0, r'C:\AD-WebInterface')

try:
    from password_audit.runner import run_password_audit
    from password_audit.checks import check_weak_passwords
    from password_audit.admin import check_admin_weak_passwords
    print("✅ Tous les imports fonctionnent")
except ImportError as e:
    print(f"❌ ImportError: {e}")
    import traceback
    traceback.print_exc()
except Exception as e:
    print(f"❌ Erreur: {e}")
    import traceback
    traceback.print_exc()
