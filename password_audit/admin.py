# -*- coding: utf-8 -*-
"""Vérifications des comptes administrateurs et de service."""
from datetime import datetime
from ldap3 import SUBTREE


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


def check_admin_weak_passwords(conn, base_dn):
    """
    Vérifier les comptes administrateurs avec des configurations de mot de passe faibles.
    """
    admin_weak_accounts = []

    try:
        # Rechercher tous les comptes avec adminCount=1 (comptes privilégiés)
        conn.search(
            base_dn,
            '(&(objectClass=user)(objectCategory=person)(adminCount=1))',
            SUBTREE,
            attributes=[
                'sAMAccountName',
                'displayName',
                'distinguishedName',
                'mail',
                'userAccountControl',
                'pwdLastSet',
                'whenCreated'
            ]
        )

        now = datetime.now()

        for entry in conn.entries:
            uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 0
            username = _clean_str(entry.sAMAccountName)
            display_name = _clean_str(entry.displayName) if entry.displayName else ''
            dn = _clean_str(entry.distinguishedName)
            mail = _clean_str(entry.mail) if hasattr(entry, 'mail') and entry.mail else ''

            # 1. MDP n'expire jamais
            if uac & 64:  # DONT_EXPIRE_PASSWD
                admin_weak_accounts.append({
                    'type': 'admin_password_never_expires',
                    'username': username,
                    'display_name': display_name,
                    'mail': mail,
                    'dn': dn,
                    'issue': 'Compte administrateur avec mot de passe n\'expirant jamais',
                    'severity': 'critical',
                    'remediation': 'Activer l\'expiration du mot de passe pour les comptes privilégiés'
                })

            # 2. MDP jamais changé (depuis la création du compte)
            try:
                pwd_last_set = entry.pwdLastSet.value if entry.pwdLastSet.value else None
                when_created = entry.whenCreated.value if entry.whenCreated.value else None

                if pwd_last_set and when_created:
                    if isinstance(pwd_last_set, datetime) and isinstance(when_created, datetime):
                        days_since_change = (now - pwd_last_set).days
                        days_since_creation = (now - when_created).days

                        if days_since_change > 365 and abs(days_since_change - days_since_creation) < 30:
                            admin_weak_accounts.append({
                                'type': 'admin_password_never_changed',
                                'username': username,
                                'display_name': display_name,
                                'mail': mail,
                                'dn': dn,
                                'issue': f'Compte administrateur avec mot de passe jamais changé ({days_since_change} jours)',
                                'severity': 'critical',
                                'remediation': 'Changer immédiatement le mot de passe et activer le renouvellement périodique'
                            })
            except Exception:
                pass

            # 3. Compte activé sans MDP requis
            if uac & 32:  # PASSWD_NOTREQD
                admin_weak_accounts.append({
                    'type': 'admin_no_password_required',
                    'username': username,
                    'display_name': display_name,
                    'mail': mail,
                    'dn': dn,
                    'issue': 'Compte administrateur sans mot de passe requis',
                    'severity': 'critical',
                    'remediation': 'Exiger immédiatement un mot de passe fort'
                })

        if len(admin_weak_accounts) == 0:
            admin_weak_accounts.append({
                'type': 'admin_ok',
                'issue': 'Aucun compte administrateur avec configuration faible détecté',
                'severity': 'success',
                'remediation': 'Continuer à surveiller régulièrement'
            })

    except Exception as e:
        admin_weak_accounts.append({
            'type': 'error',
            'issue': f'Erreur de recherche des comptes admins: {str(e)}',
            'severity': 'error'
        })

    return admin_weak_accounts


def check_service_accounts(conn, base_dn):
    """
    Vérifier les comptes de service avec des configurations de mot de passe faibles.
    """
    service_accounts = []

    try:
        service_patterns = ['svc', 'service', 'app', 'sql', 'iis', 'web', 'ftp', 'smtp', 'pop', 'imap']
        now = datetime.now()

        for pattern in service_patterns:
            conn.search(
                base_dn,
                f'(&(objectClass=user)(objectCategory=person)(sAMAccountName=*{pattern}*))',
                SUBTREE,
                attributes=[
                    'sAMAccountName',
                    'displayName',
                    'distinguishedName',
                    'mail',
                    'userAccountControl',
                    'pwdLastSet',
                    'whenCreated',
                    'servicePrincipalName',
                    'description'
                ]
            )

            for entry in conn.entries:
                uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 0
                username = _clean_str(entry.sAMAccountName)
                display_name = _clean_str(entry.displayName) if entry.displayName else ''
                dn = _clean_str(entry.distinguishedName)
                mail = _clean_str(entry.mail) if hasattr(entry, 'mail') and entry.mail else ''
                description = _clean_str(entry.description) if hasattr(entry, 'description') and entry.description else ''
                spn = _clean_str(entry.servicePrincipalName) if hasattr(entry, 'servicePrincipalName') and entry.servicePrincipalName else ''

                # Vérifier si c'est un compte de service
                is_service = False
                if spn and spn != '[]':
                    is_service = True
                for p in service_patterns:
                    if p in username.lower():
                        is_service = True
                        break

                if not is_service:
                    continue

                # 1. MDP n'expire jamais
                if uac & 64:
                    service_accounts.append({
                        'type': 'service_password_never_expires',
                        'username': username,
                        'display_name': display_name,
                        'mail': mail,
                        'dn': dn,
                        'description': description,
                        'spn': spn,
                        'issue': 'Compte de service avec mot de passe n\'expirant jamais',
                        'severity': 'critical',
                        'remediation': 'Utiliser un Managed Service Account (MSA) ou renouveler le MDP périodiquement'
                    })

                # 2. MDP jamais changé
                try:
                    pwd_last_set = entry.pwdLastSet.value if entry.pwdLastSet.value else None
                    if pwd_last_set and isinstance(pwd_last_set, datetime):
                        days_since_change = (now - pwd_last_set).days
                        if days_since_change > 365:
                            service_accounts.append({
                                'type': 'service_password_never_changed',
                                'username': username,
                                'display_name': display_name,
                                'mail': mail,
                                'dn': dn,
                                'description': description,
                                'spn': spn,
                                'issue': f'Compte de service avec mot de passe jamais changé ({days_since_change} jours)',
                                'severity': 'critical',
                                'remediation': 'Changer immédiatement le mot de passe et planifier un renouvellement'
                            })
                except Exception:
                    pass

                # 3. Compte activé sans MDP requis
                if uac & 32:
                    service_accounts.append({
                        'type': 'service_no_password_required',
                        'username': username,
                        'display_name': display_name,
                        'mail': mail,
                        'dn': dn,
                        'description': description,
                        'spn': spn,
                        'issue': 'Compte de service sans mot de passe requis',
                        'severity': 'critical',
                        'remediation': 'Exiger immédiatement un mot de passe fort'
                    })

        if len(service_accounts) == 0:
            service_accounts.append({
                'type': 'service_ok',
                'issue': 'Aucun compte de service à risque détecté',
                'severity': 'success',
                'remediation': 'Continuer à surveiller régulièrement'
            })

    except Exception as e:
        service_accounts.append({
            'type': 'error',
            'issue': f'Erreur de recherche des comptes de service: {str(e)}',
            'severity': 'error'
        })

    return service_accounts
