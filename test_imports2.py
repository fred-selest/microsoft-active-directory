import sys
sys.path.insert(0, r'C:\AD-WebInterface')

print("Test 1: from password_audit.runner import run_password_audit")
try:
    from password_audit.runner import run_password_audit
    print("  ✅ OK")
except Exception as e:
    print(f"  ❌ Erreur: {e}")

print("Test 2: from password_audit.checks import check_weak_passwords_ad")
try:
    from password_audit.checks import check_weak_passwords_ad
    print("  ✅ OK")
except Exception as e:
    print(f"  ❌ Erreur: {e}")

print("Test 3: from password_audit.admin import check_admin_weak_passwords")
try:
    from password_audit.admin import check_admin_weak_passwords
    print("  ✅ OK")
except Exception as e:
    print(f"  ❌ Erreur: {e}")

print("Test 4: from password_audit import check_weak_passwords")
try:
    from password_audit import check_weak_passwords
    print("  ✅ OK")
except Exception as e:
    print(f"  ❌ Erreur: {e}")

print("Test 5: from password_audit.runner import check_password_age")
try:
    from password_audit.runner import check_password_age
    print("  ✅ OK")
except Exception as e:
    print(f"  ❌ Erreur: {e}")

print("\n--- Import routes/api.py ---")
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("api", r"C:\AD-WebInterface\routes\api.py")
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    print("  ✅ api.py chargée sans erreur")
except Exception as e:
    print(f"  ❌ api.py: {e}")

print("\n--- Import routes/tools/password.py ---")
try:
    spec = importlib.util.spec_from_file_location("password", r"C:\AD-WebInterface\routes\tools\password.py")
    password = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(password)
    print("  ✅ password.py chargée sans erreur")
except Exception as e:
    print(f"  ❌ password.py: {e}")
