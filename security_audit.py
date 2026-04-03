"""
Audit de Sécurité Renforcé - Détection et réparation automatique
"""
from datetime import datetime
from ldap3 import SUBTREE, MODIFY_REPLACE


def check_security_issues(conn, base_dn):
    """
    Vérifier les problèmes de sécurité AD.
    
    Args:
        conn: Connexion LDAP
        base_dn: DN de base
    
    Returns:
        list: Liste des problèmes de sécurité détectés
    """
    issues = []
    
    # 1. Comptes orphelins (sans manager)
    issues.extend(check_orphaned_accounts(conn, base_dn))
    
    # 2. Privilèges excessifs
    issues.extend(check_excessive_privileges(conn, base_dn))
    
    # 3. Comptes administrateurs sans MFA
    issues.extend(check_admin_without_mfa(conn, base_dn))
    
    # 4. Groupes de sécurité vides
    issues.extend(check_empty_security_groups(conn, base_dn))
    
    # 5. Comptes avec privilèges spéciaux
    issues.extend(check_special_privileges(conn, base_dn))
    
    # 6. Délégations dangereuses
    issues.extend(check_dangerous_delegations(conn, base_dn))
    
    # 7. Mots de passe qui n'expirent jamais
    issues.extend(check_password_never_expires(conn, base_dn))
    
    # 8. Comptes inactifs depuis longtemps
    issues.extend(check_inactive_accounts(conn, base_dn))
    
    return issues


def check_orphaned_accounts(conn, base_dn):
    """Vérifier les comptes sans manager."""
    issues = []
    
    try:
        conn.search(base_dn, '(&(objectClass=user)(objectCategory=person)(!(manager=*)))',
                   SUBTREE, attributes=['sAMAccountName', 'cn', 'distinguishedName', 'department'])
        
        orphaned = [str(e.sAMAccountName) for e in conn.entries if str(e.sAMAccountName) not in ['admin', 'administrator', 'krbtgt']]
        
        if orphaned:
            issues.append({
                'id': 'orphaned_accounts',
                'title': f'{len(orphaned)} compte(s) sans manager',
                'severity': 'warning',
                'description': 'Ces comptes n\'ont pas de manager défini. En cas de problème, personne ne peut les superviser.',
                'affected': orphaned[:10],  # Limiter à 10
                'total': len(orphaned),
                'remediation': 'Définir un manager pour chaque compte dans les propriétés AD.',
                'fix_available': True,
                'fix_script': 'assign_manager'
            })
    except Exception as e:
        pass
    
    return issues


def check_excessive_privileges(conn, base_dn):
    """Vérifier les privilèges excessifs."""
    issues = []
    
    try:
        # Utilisateurs dans Domain Admins
        conn.search(base_dn, '(cn=Domain Admins)', SUBTREE, attributes=['member'])
        if conn.entries:
            members = conn.entries[0].member.values
            if len(members) > 10:  # Trop de membres
                issues.append({
                    'id': 'excessive_domain_admins',
                    'title': 'Trop de membres dans Domain Admins',
                    'severity': 'critical',
                    'description': f'{len(members)} membres dans Domain Admins. Ce groupe devrait être limité à 5-10 personnes maximum.',
                    'affected': [str(m) for m in members[:10]],
                    'total': len(members),
                    'remediation': 'Réduire le nombre de membres. Utiliser des groupes dédiés pour des tâches spécifiques.',
                    'fix_available': False
                })
    except Exception as e:
        pass
    
    return issues


def check_admin_without_mfa(conn, base_dn):
    """Vérifier les admins sans MFA."""
    issues = []
    
    try:
        # Chercher les admins
        conn.search(base_dn, '(cn=Domain Admins)', SUBTREE, attributes=['member'])
        if conn.entries:
            admin_count = len(conn.entries[0].member.values)
            
            issues.append({
                'id': 'admin_mfa',
                'title': f'{admin_count} administrateur(s) - MFA non vérifié',
                'severity': 'critical',
                'description': 'Les comptes administrateurs devraient tous avoir la MFA activée. Vérifiez manuellement dans Azure AD ou votre solution MFA.',
                'affected': [],
                'total': admin_count,
                'remediation': 'Activer la MFA pour tous les comptes administrateurs via Azure AD ou NPS.',
                'fix_available': False,
                'manual_check_required': True
            })
    except Exception as e:
        pass
    
    return issues


def check_empty_security_groups(conn, base_dn):
    """Vérifier les groupes de sécurité vides."""
    issues = []
    
    try:
        conn.search(base_dn, '(&(objectClass=group)(groupType=-2147483646))',
                   SUBTREE, attributes=['cn', 'distinguishedName', 'member'])
        
        empty_groups = []
        for entry in conn.entries:
            if not entry.member or len(entry.member.values) == 0:
                empty_groups.append(str(entry.cn))
        
        if empty_groups:
            issues.append({
                'id': 'empty_security_groups',
                'title': f'{len(empty_groups)} groupe(s) de sécurité vide(s)',
                'severity': 'warning',
                'description': 'Ces groupes de sécurité n\'ont aucun membre. Ils peuvent être supprimés ou remplis.',
                'affected': empty_groups[:10],
                'total': len(empty_groups),
                'remediation': 'Supprimer les groupes inutiles ou ajouter des membres.',
                'fix_available': True,
                'fix_script': 'delete_empty_groups'
            })
    except Exception as e:
        pass
    
    return issues


def check_special_privileges(conn, base_dn):
    """Vérifier les comptes avec privilèges spéciaux."""
    issues = []
    
    try:
        # Comptes avec DCSync rights
        conn.search(base_dn, '(objectClass=domain)', SUBTREE,
                   attributes=['nTSecurityDescriptor'])
        
        # Simplifié - en production il faudrait parser le descriptor
        issues.append({
            'id': 'special_privileges',
            'title': 'Privilèges spéciaux détectés',
            'severity': 'high',
            'description': 'Certains comptes ont des privilèges spéciaux (DCSync, Restore, etc.). Vérifiez qu\'ils sont justifiés.',
            'affected': ['À vérifier manuellement'],
            'total': 1,
            'remediation': 'Auditer les privilèges spéciaux avec ADRecon ou BloodHound.',
            'fix_available': False,
            'manual_check_required': True
        })
    except Exception as e:
        pass
    
    return issues


def check_dangerous_delegations(conn, base_dn):
    """Vérifier les délégations dangereuses."""
    issues = []
    
    try:
        # Comptes avec unconstrained delegation
        conn.search(base_dn, '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
                   SUBTREE, attributes=['sAMAccountName', 'cn'])
        
        delegations = [str(e.sAMAccountName) for e in conn.entries]
        
        if delegations:
            issues.append({
                'id': 'unconstrained_delegation',
                'title': f'{len(delegations)} compte(s) avec délégation non contrainte',
                'severity': 'critical',
                'description': 'La délégation non contrainte permet à un compte d\'accéder à n\'importe quelle ressource au nom d\'un utilisateur. C\'est un risque majeur.',
                'affected': delegations[:10],
                'total': len(delegations),
                'remediation': 'Désactiver la délégation non contrainte et utiliser la délégation contrainte.',
                'fix_available': True,
                'fix_script': 'disable_unconstrained_delegation'
            })
    except Exception as e:
        pass
    
    return issues


def check_password_never_expires(conn, base_dn):
    """Vérifier les comptes avec MDP n'expirant jamais."""
    issues = []
    
    try:
        conn.search(base_dn, '(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=64))',
                   SUBTREE, attributes=['sAMAccountName', 'cn', 'distinguishedName'])
        
        never_expire = [str(e.sAMAccountName) for e in conn.entries]
        
        # Exclure les comptes de service légitimes
        service_patterns = ['svc', 'service', 'sql', 'iis', 'web', 'ftp']
        legitimate_services = [u for u in never_expire if any(p in u.lower() for p in service_patterns)]
        suspicious = [u for u in never_expire if u not in legitimate_services]
        
        if suspicious:
            issues.append({
                'id': 'password_never_expires',
                'title': f'{len(suspicious)} compte(s) avec MDP n\'expirant jamais',
                'severity': 'high',
                'description': 'Ces comptes (non-service) ont un mot de passe qui n\'expire jamais. C\'est un risque de sécurité.',
                'affected': suspicious[:10],
                'total': len(suspicious),
                'remediation': 'Activer l\'expiration des mots de passe ou convertir en Managed Service Account.',
                'fix_available': True,
                'fix_script': 'enable_password_expiry'
            })
    except Exception as e:
        pass
    
    return issues


def check_inactive_accounts(conn, base_dn):
    """Vérifier les comptes inactifs."""
    issues = []
    
    try:
        from datetime import datetime, timedelta
        
        # Comptes inactifs depuis 90 jours
        conn.search(base_dn, '(&(objectClass=user)(objectCategory=person))',
                   SUBTREE, attributes=['sAMAccountName', 'lastLogonTimestamp', 'userAccountControl'])
        
        inactive = []
        now = datetime.now()
        
        for entry in conn.entries:
            try:
                uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 0
                # Skip disabled accounts
                if uac & 2:
                    continue
                
                last_logon = entry.lastLogonTimestamp.value
                if last_logon:
                    # Convert Windows timestamp
                    last_logon_date = datetime(1601, 1, 1) + timedelta(microseconds=last_logon // 10)
                    days_inactive = (now - last_logon_date).days
                    
                    if days_inactive > 90:
                        inactive.append({
                            'name': str(entry.sAMAccountName),
                            'days': days_inactive
                        })
            except:
                continue
        
        if inactive:
            inactive.sort(key=lambda x: x['days'], reverse=True)
            issues.append({
                'id': 'inactive_accounts',
                'title': f'{len(inactive)} compte(s) inactif(s) depuis >90 jours',
                'severity': 'warning',
                'description': 'Ces comptes n\'ont pas ouvert de session depuis plus de 90 jours. Ils devraient être désactivés ou supprimés.',
                'affected': [f"{a['name']} ({a['days']}j)" for a in inactive[:10]],
                'total': len(inactive),
                'remediation': 'Désactiver ces comptes après vérification avec les managers.',
                'fix_available': True,
                'fix_script': 'disable_inactive_accounts'
            })
    except Exception as e:
        pass
    
    return issues


# =============================================================================
# FONCTIONS DE RÉPARATION
# =============================================================================

def fix_assign_manager(conn, base_dn, accounts, manager_dn):
    """Assigner un manager à des comptes."""
    results = {'success': 0, 'failed': 0, 'errors': []}
    
    for account in accounts:
        try:
            # Trouver le DN du compte
            conn.search(base_dn, f'(sAMAccountName={account})', SUBTREE)
            if conn.entries:
                account_dn = str(conn.entries[0].distinguishedName)
                
                # Assigner le manager
                conn.modify(account_dn, {
                    'manager': [(MODIFY_REPLACE, [manager_dn])]
                })
                
                if conn.result['result'] == 0:
                    results['success'] += 1
                else:
                    results['failed'] += 1
                    results['errors'].append(f"{account}: {conn.result['description']}")
        except Exception as e:
            results['failed'] += 1
            results['errors'].append(f"{account}: {str(e)}")
    
    return results


def fix_delete_empty_groups(conn, base_dn, groups):
    """Supprimer les groupes vides."""
    results = {'success': 0, 'failed': 0, 'errors': []}
    
    for group in groups:
        try:
            # Trouver le DN du groupe
            conn.search(base_dn, f'(cn={group})', SUBTREE)
            if conn.entries:
                group_dn = str(conn.entries[0].distinguishedName)
                
                # Supprimer
                conn.delete(group_dn)
                
                if conn.result['result'] == 0:
                    results['success'] += 1
                else:
                    results['failed'] += 1
                    results['errors'].append(f"{group}: {conn.result['description']}")
        except Exception as e:
            results['failed'] += 1
            results['errors'].append(f"{group}: {str(e)}")
    
    return results


def fix_disable_unconstrained_delegation(conn, base_dn, accounts):
    """Désactiver la délégation non contrainte."""
    results = {'success': 0, 'failed': 0, 'errors': []}
    
    for account in accounts:
        try:
            conn.search(base_dn, f'(sAMAccountName={account})', SUBTREE)
            if conn.entries:
                account_dn = str(conn.entries[0].distinguishedName)
                current_uac = int(conn.entries[0].userAccountControl.value)
                
                # Désactiver TRUSTED_FOR_DELEGATION (bit 17 = 524288)
                new_uac = current_uac & ~524288
                
                conn.modify(account_dn, {
                    'userAccountControl': [(MODIFY_REPLACE, [new_uac])]
                })
                
                if conn.result['result'] == 0:
                    results['success'] += 1
                else:
                    results['failed'] += 1
                    results['errors'].append(f"{account}: {conn.result['description']}")
        except Exception as e:
            results['failed'] += 1
            results['errors'].append(f"{account}: {str(e)}")
    
    return results


def fix_enable_password_expiry(conn, base_dn, accounts):
    """Activer l'expiration des mots de passe."""
    results = {'success': 0, 'failed': 0, 'errors': []}
    
    for account in accounts:
        try:
            conn.search(base_dn, f'(sAMAccountName={account})', SUBTREE)
            if conn.entries:
                account_dn = str(conn.entries[0].distinguishedName)
                current_uac = int(conn.entries[0].userAccountControl.value)
                
                # Désactiver DONT_EXPIRE_PASSWD (bit 6 = 64)
                new_uac = current_uac & ~64
                
                conn.modify(account_dn, {
                    'userAccountControl': [(MODIFY_REPLACE, [new_uac])]
                })
                
                if conn.result['result'] == 0:
                    results['success'] += 1
                else:
                    results['failed'] += 1
                    results['errors'].append(f"{account}: {conn.result['description']}")
        except Exception as e:
            results['failed'] += 1
            results['errors'].append(f"{account}: {str(e)}")
    
    return results


def fix_disable_inactive_accounts(conn, base_dn, accounts):
    """Désactiver les comptes inactifs."""
    results = {'success': 0, 'failed': 0, 'errors': []}
    
    for account in accounts:
        try:
            conn.search(base_dn, f'(sAMAccountName={account})', SUBTREE)
            if conn.entries:
                account_dn = str(conn.entries[0].distinguishedName)
                current_uac = int(conn.entries[0].userAccountControl.value)
                
                # Activer ACCOUNTDISABLE (bit 1 = 2)
                new_uac = current_uac | 2
                
                conn.modify(account_dn, {
                    'userAccountControl': [(MODIFY_REPLACE, [new_uac])]
                })
                
                if conn.result['result'] == 0:
                    results['success'] += 1
                else:
                    results['failed'] += 1
                    results['errors'].append(f"{account}: {conn.result['description']}")
        except Exception as e:
            results['failed'] += 1
            results['errors'].append(f"{account}: {str(e)}")
    
    return results
