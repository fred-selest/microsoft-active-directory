"""
Package password_audit — Audit de sécurité des mots de passe Active Directory.

API publique (rétrocompatible avec l'ancien fichier password_audit.py) :
    run_password_audit, export_audit_to_csv, export_audit_to_json,
    analyze_password_strength, get_password_policy
"""
import os
from .analyzer import analyze_password_strength, get_password_policy, check_fine_grained_policies, generate_password_recommendations
from .checks import (check_weak_passwords_ad, check_password_age,
                     check_password_spray_vulnerability, check_tiering_violations,
                     check_delegations, check_protected_users,
                     check_privileged_group_memberships, check_siem_logging)
# Alias pour rétrocompatibilité
check_weak_passwords = check_weak_passwords_ad
from .protocol import (check_legacy_protocols, check_smbv1_status, check_ntlm_level,
                       get_ntlm_level_name, check_ldap_signing, check_channel_binding)
from .runner import run_password_audit
from .export import export_audit_to_csv, export_audit_to_json
from .report import generate_auditor_issues
from .admin import check_admin_weak_passwords, check_service_accounts

__all__ = [
    'analyze_password_strength', 'get_password_policy', 'check_fine_grained_policies',
    'generate_password_recommendations', 'check_weak_passwords_ad', 'check_password_age',
    'check_password_spray_vulnerability', 'check_tiering_violations', 'check_delegations',
    'check_protected_users', 'check_privileged_group_memberships', 'check_siem_logging',
    'check_legacy_protocols', 'check_smbv1_status', 'check_ntlm_level', 'get_ntlm_level_name',
    'check_ldap_signing', 'check_channel_binding', 'run_password_audit',
    'export_audit_to_csv', 'export_audit_to_json', 'generate_auditor_issues',
    'check_admin_weak_passwords', 'check_service_accounts',
]
