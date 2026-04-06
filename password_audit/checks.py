# -*- coding: utf-8 -*-
"""Vérifications de sécurité AD : comptes faibles, délégations, groupes privilégiés, SIEM."""
from datetime import datetime, timedelta
from ldap3 import SUBTREE

from security import escape_ldap_filter


def _clean_str(s):
    """Nettoyer une chaîne (UTF-8)."""
    if s is None:
        return ''
    s = str(s)
    # Décoder les séquences d'échappement Unicode (ex: \xe9 → é)
    try:
        return s.encode('latin-1').decode('unicode_escape').encode('latin-1').decode('utf-8', errors='replace')
    except:
        return s


def check_weak_passwords_ad(conn, base_dn):
    """Vérifier les utilisateurs avec des configurations de mot de passe risquées."""
    weak_accounts = []
    try:
        # Mots de passe n'expirant jamais
        conn.search(base_dn,
            '(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=64))',
            SUBTREE, attributes=['sAMAccountName', 'displayName', 'distinguishedName', 'userAccountControl', 'mail'])
        for entry in conn.entries:
            weak_accounts.append({
                'type': 'password_never_expires',
                'username': _clean_str(entry.sAMAccountName),
                'display_name': _clean_str(entry.displayName) if entry.displayName else '',
                'mail': _clean_str(entry.mail) if hasattr(entry, 'mail') and entry.mail else '',
                'dn': _clean_str(entry.distinguishedName),
                'issue': "Le mot de passe n'expire jamais",
                'severity': 'warning',
                'remediation': "Désactiver \"Le mot de passe n'expire jamais\" dans les propriétés du compte",
            })

        # Mot de passe non requis
        conn.search(base_dn,
            '(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=32))',
            SUBTREE, attributes=['sAMAccountName', 'displayName', 'distinguishedName', 'mail'])
        for entry in conn.entries:
            weak_accounts.append({
                'type': 'no_password_required',
                'username': _clean_str(entry.sAMAccountName),
                'display_name': _clean_str(entry.displayName) if entry.displayName else '',
                'mail': _clean_str(entry.mail) if hasattr(entry, 'mail') and entry.mail else '',
                'dn': _clean_str(entry.distinguishedName),
                'issue': 'Mot de passe non requis',
                'severity': 'critical',
                'remediation': 'Exiger un mot de passe pour ce compte',
            })

        # Admins avec mot de passe n'expirant jamais
        conn.search(base_dn,
            '(&(objectClass=user)(objectCategory=person)(adminCount=1))',
            SUBTREE, attributes=['sAMAccountName', 'displayName', 'distinguishedName', 'mail', 'userAccountControl'])
        for entry in conn.entries:
            uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 0
            if uac & 64:
                weak_accounts.append({
                    'type': 'admin_password_never_expires',
                    'username': _clean_str(entry.sAMAccountName),
                    'display_name': _clean_str(entry.displayName) if entry.displayName else '',
                    'mail': _clean_str(entry.mail) if hasattr(entry, 'mail') and entry.mail else '',
                    'dn': _clean_str(entry.distinguishedName),
                    'issue': "Compte administrateur avec mot de passe n'expirant jamais",
                    'severity': 'critical',
                    'remediation': "Activer l'expiration du mot de passe pour les comptes privilégiés",
                })
    except Exception as ex:
        weak_accounts.append({'type': 'error', 'issue': f'Erreur de recherche: {ex}', 'severity': 'error'})
    return weak_accounts


def check_password_age(conn, base_dn, max_age_days=90):
    """Vérifier l'ancienneté des mots de passe."""
    old_passwords = []
    threshold_date = datetime.now() - timedelta(days=max_age_days)
    try:
        conn.search(base_dn,
            '(&(objectClass=user)(objectCategory=person)(pwdLastSet=*))',
            SUBTREE, attributes=['sAMAccountName', 'displayName', 'pwdLastSet', 'distinguishedName', 'mail'])
        for entry in conn.entries:
            pwd_last_set = entry.pwdLastSet.value
            if pwd_last_set:
                if isinstance(pwd_last_set, datetime):
                    last_change = pwd_last_set
                else:
                    last_change = datetime(1601, 1, 1) + timedelta(microseconds=pwd_last_set // 10)
                if last_change < threshold_date:
                    days_old = (datetime.now() - last_change).days
                    old_passwords.append({
                        'username': _clean_str(entry.sAMAccountName),
                        'display_name': _clean_str(entry.displayName) if entry.displayName else '',
                        'mail': _clean_str(entry.mail) if hasattr(entry, 'mail') and entry.mail else '',
                        'dn': _clean_str(entry.distinguishedName),
                        'pwdLastSet': last_change.strftime('%Y-%m-%d'),
                        'days_old': days_old,
                        'severity': 'critical' if days_old > max_age_days * 2 else 'warning',
                        'remediation': 'Forcer le changement de mot de passe',
                    })
    except Exception as ex:
        old_passwords.append({'type': 'error', 'issue': f'Erreur: {ex}', 'severity': 'error'})
    return old_passwords


def check_password_spray_vulnerability(conn, base_dn):
    """Détecter les comptes vulnérables aux attaques par spray de mot de passe."""
    vulnerable = []
    try:
        conn.search(base_dn, '(&(objectClass=user)(objectCategory=person))', SUBTREE,
                    attributes=['sAMAccountName', 'displayName', 'distinguishedName', 'mail'])
        for entry in conn.entries:
            vulnerable.append({
                'username': _clean_str(entry.sAMAccountName),
                'display_name': _clean_str(entry.displayName) if entry.displayName else '',
                'mail': _clean_str(entry.mail) if hasattr(entry, 'mail') and entry.mail else '',
                'dn': _clean_str(entry.distinguishedName),
                'issue': 'Vulnérable au spray de mot de passe (verrouillage non configuré)',
                'severity': 'medium',
            })
    except Exception as ex:
        vulnerable.append({'error': str(ex)})
    return vulnerable


def check_tiering_violations(conn, base_dn):
    """Vérifier les violations du modèle de tiering (Tier 0, 1, 2)."""
    violations = []
    try:
        conn.search(base_dn, '(&(objectClass=user)(objectCategory=person)(adminCount=1))', SUBTREE,
                    attributes=['sAMAccountName', 'distinguishedName', 'lastLogon'])
        for entry in conn.entries:
            violations.append({
                'type': 'tiering',
                'item': str(entry.sAMAccountName),
                'issue': "Compte privilégié - Vérifier qu'il n'est utilisé que sur des PAW (Tier 0)",
                'recommendation': "Utiliser exclusivement des Postes d'Administration Sécurisés (PAW)",
                'severity': 'high',
                'tier': 'Tier 0',
                'reference': 'ANSSI: Modèle de tiering',
            })
    except Exception as ex:
        violations.append({'error': str(ex)})
    return violations


def check_delegations(conn, base_dn):
    """Vérifier les délégations de privilèges (constrained/unconstrained)."""
    issues = []
    try:
        conn.search(base_dn,
            '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
            SUBTREE, attributes=['sAMAccountName', 'distinguishedName'])
        for entry in conn.entries:
            issues.append({
                'type': 'delegation',
                'item': str(entry.sAMAccountName),
                'issue': 'Délégation sans contrainte activée (TRUSTED_FOR_DELEGATION)',
                'recommendation': 'Désactiver ou remplacer par délégation contrainte (KCD)',
                'severity': 'critical',
                'reference': 'ANSSI: Gestion des délégations de privilèges',
                'dn': _clean_str(entry.distinguishedName),
            })

        conn.search(base_dn, '(&(objectClass=user)(msDS-AllowedToDelegateTo=*))', SUBTREE,
                    attributes=['sAMAccountName', 'distinguishedName', 'msDS-AllowedToDelegateTo'])
        for entry in conn.entries:
            delegated = getattr(entry, 'msDS-AllowedToDelegateTo', None)
            count = len(delegated.values) if delegated else 0
            issues.append({
                'type': 'delegation_constrained',
                'item': str(entry.sAMAccountName),
                'issue': f'Délégation contrainte vers {count} service(s)',
                'recommendation': 'Vérifier que la délégation est nécessaire et documentée',
                'severity': 'medium',
                'dn': _clean_str(entry.distinguishedName),
            })
    except Exception as ex:
        issues.append({'error': str(ex)})
    return issues


def check_protected_users(conn, base_dn):
    """Vérifier le groupe Protected Users."""
    issues = []
    try:
        conn.search(base_dn, '(&(objectClass=group)(cn=Protected Users))', SUBTREE,
                    attributes=['member', 'distinguishedName'])
        if conn.entries:
            members = conn.entries[0].member.values if hasattr(conn.entries[0], 'member') else []
            count = len(members) if members else 0
            if count == 0:
                issues.append({'type': 'protected_users', 'item': 'Protected Users',
                    'issue': 'Groupe Protected Users vide',
                    'recommendation': 'Ajouter les comptes administrateurs et comptes sensibles',
                    'severity': 'high', 'reference': 'Microsoft: Protected Users Security Group'})
            else:
                issues.append({'type': 'protected_users', 'item': 'Protected Users',
                    'issue': f'{count} membre(s) dans Protected Users',
                    'recommendation': 'Vérifier que tous les comptes privilégiés y sont',
                    'severity': 'info'})
        else:
            issues.append({'type': 'protected_users', 'item': 'Protected Users',
                'issue': 'Groupe Protected Users introuvable (nécessite Windows Server 2012 R2+)',
                'recommendation': 'Créer le groupe et y ajouter les comptes sensibles',
                'severity': 'high'})
    except Exception as ex:
        issues.append({'error': str(ex)})
    return issues


def check_privileged_group_memberships(conn, base_dn):
    """Vérifier les appartenances permanentes aux groupes privilégiés."""
    issues = []
    privileged_groups = [
        'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators',
    ]
    try:
        for group_name in privileged_groups:
            conn.search(base_dn, f'(&(objectClass=group)(cn={escape_ldap_filter(group_name)}))',
                        SUBTREE, attributes=['member', 'distinguishedName'])
            if conn.entries:
                members = conn.entries[0].member.values if hasattr(conn.entries[0], 'member') else []
                count = len(members) if members else 0
                if count > 0:
                    issues.append({'type': 'privileged_group', 'item': group_name,
                        'issue': f'{count} membre(s) permanent(s)',
                        'recommendation': 'Mettre en place un accès JIT (Just-In-Time) ou PAM',
                        'severity': 'warning', 'reference': 'ANSSI: Gestion des privilèges'})
    except Exception as ex:
        issues.append({'error': str(ex)})
    return issues


def check_siem_logging(conn, base_dn):
    """Vérifier la configuration des logs et du SIEM."""
    return [
        {'type': 'siem', 'item': 'Audit Policy',
         'issue': 'Vérifier que les audits avancés sont activés',
         'recommendation': 'GPO: Advanced Audit Policy → Activer tous les audits de sécurité critiques',
         'severity': 'high', 'reference': 'ANSSI: Recommandations de journalisation'},
        {'type': 'siem', 'item': 'SIEM Integration',
         'issue': 'Centraliser les logs AD dans un SIEM',
         'recommendation': 'Configurer la forwarding des événements 4624, 4625, 4672, 4720, 4732, etc.',
         'severity': 'high', 'reference': 'ANSSI: Détection et réponse'},
        {'type': 'siem', 'item': 'Sensitive Objects',
         'issue': 'Surveiller les modifications des objets sensibles',
         'recommendation': 'Activer SACL sur les groupes privilégiés et comptes admins',
         'severity': 'high', 'reference': 'Microsoft: Audit AD DS'},
    ]
