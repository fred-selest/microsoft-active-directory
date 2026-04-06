"""Point d'entrée de l'audit complet (run_password_audit)."""
from datetime import datetime

from .analyzer import get_password_policy, check_fine_grained_policies, generate_password_recommendations
from .checks import (check_weak_passwords_ad, check_password_age,
                     check_password_spray_vulnerability, check_tiering_violations,
                     check_delegations, check_protected_users,
                     check_privileged_group_memberships, check_siem_logging)
from .protocol import check_legacy_protocols
from .admin import check_admin_weak_passwords, check_service_accounts


def run_password_audit(conn, base_dn, max_age_days=90):
    """Exécuter un audit complet des mots de passe et de la sécurité AD."""
    policy = get_password_policy(conn, base_dn)
    weak_accounts = check_weak_passwords_ad(conn, base_dn)
    old_passwords = check_password_age(conn, base_dn, max_age_days)
    fgpps = check_fine_grained_policies(conn, base_dn)
    spray_vulns = check_password_spray_vulnerability(conn, base_dn)
    tiering_violations = check_tiering_violations(conn, base_dn)
    legacy_protocols = check_legacy_protocols(conn, base_dn)
    delegations = check_delegations(conn, base_dn)
    protected_users = check_protected_users(conn, base_dn)
    privileged_groups = check_privileged_group_memberships(conn, base_dn)
    siem_logging = check_siem_logging(conn, base_dn)
    
    # NOUVEAU: Comptes admin et service
    admin_weak_accounts = check_admin_weak_passwords(conn, base_dn)
    service_accounts = check_service_accounts(conn, base_dn)

    recommendations = generate_password_recommendations(policy, weak_accounts, old_passwords, fgpps)
    security_recommendations = []

    _cat_map = {
        'protocol': ('🔒 Protocoles', legacy_protocols, {'issue', 'recommendation', 'reference', 'type', 'item'}),
        'tiering':  ('🏛️ Tiering',   tiering_violations[:3], {'issue', 'recommendation', 'reference', 'type', 'tier'}),
        'delegation': ('🔑 Délégations', delegations, {'issue', 'recommendation', 'reference', 'type', 'dn'}),
        'protected': ('🛡️ Protected Users', protected_users, {'issue', 'recommendation', 'reference', 'type'}),
        'privileged': ('👥 Privilèges', privileged_groups, {'issue', 'recommendation', 'reference', 'type'}),
        'siem': ('📊 SIEM & Logs', siem_logging, {'issue', 'recommendation', 'reference', 'type'}),
    }

    _categories = [
        ('🔒 Protocoles', legacy_protocols, 'high'),
        ('🏛️ Tiering', tiering_violations[:3], 'high'),
        ('🔑 Délégations', delegations, 'high'),
        ('🛡️ Protected Users', protected_users, 'high'),
        ('👥 Privilèges', privileged_groups, 'warning'),
        ('📊 SIEM & Logs', siem_logging, 'high'),
    ]

    for category, items, default_priority in _categories:
        for item in items:
            if 'error' in item:
                continue
            entry = {'priority': item.get('severity', default_priority), 'category': category}
            for k in ('issue', 'recommendation', 'reference', 'type', 'item', 'tier', 'dn'):
                if k in item:
                    entry[k] = item[k]
            security_recommendations.append(entry)

    # Score global
    critical_issues = (
        sum(1 for a in weak_accounts if a.get('severity') == 'critical')
        + sum(1 for p in old_passwords if p.get('severity') == 'critical')
        + (1 if policy.get('reversible_encryption', False) else 0)
        + sum(1 for d in delegations if d.get('severity') == 'critical')
    )
    base_score = (100
        - critical_issues * 15
        - sum(1 for a in weak_accounts if a.get('severity') == 'warning') * 5
        - sum(1 for p in old_passwords if p.get('severity') == 'warning') * 3
        - (10 if not policy.get('complexity_enabled', False) else 0)
        - (5 if policy.get('minPasswordLength', 0) < 12 else 0)
        - len(legacy_protocols) * 5
        - len([d for d in delegations if d.get('severity') == 'critical']) * 10
    )
    global_score = max(0, min(100, base_score))

    if global_score >= 80:
        score_label, score_color = "Excellent", "success"
    elif global_score >= 60:
        score_label, score_color = "Acceptable", "info"
    elif global_score >= 40:
        score_label, score_color = "Mauvais", "warning"
    else:
        score_label, score_color = "Critique", "danger"

    return {
        'timestamp': datetime.now().isoformat(),
        'policy': policy,
        'fgpps': fgpps,
        'weak_accounts': weak_accounts,
        'admin_weak_accounts': admin_weak_accounts,
        'service_accounts': service_accounts,
        'old_passwords': old_passwords,
        'spray_vulnerabilities': spray_vulns,
        'tiering_violations': tiering_violations,
        'legacy_protocols': legacy_protocols,
        'delegations': delegations,
        'protected_users': protected_users,
        'privileged_groups': privileged_groups,
        'siem_logging': siem_logging,
        'recommendations': recommendations + security_recommendations,
        'summary': {
            'total_issues': len(weak_accounts) + len(old_passwords) + len(admin_weak_accounts) + len(service_accounts),
            'critical_issues': critical_issues,
            'warning_issues': sum(1 for a in weak_accounts if a.get('severity') == 'warning'),
            'global_score': global_score,
            'score_label': score_label,
            'score_color': score_color,
            'accounts_audited': len(weak_accounts) + len(old_passwords) + len(admin_weak_accounts) + len(service_accounts),
            'policy_compliant': global_score >= 80,
            'tiering_issues': len(tiering_violations),
            'protocol_issues': len(legacy_protocols),
            'delegation_issues': len(delegations),
            'privileged_group_issues': len(privileged_groups),
            'siem_issues': len(siem_logging),
            'total_recommendations': len(recommendations) + len(security_recommendations),
        },
    }
