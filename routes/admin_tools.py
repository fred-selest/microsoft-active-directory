# -*- coding: utf-8 -*-
"""
Blueprint pour les routes d'administration et outils.
Contient: update, diagnostic, alerts, errors, security-audit, permissions
"""
from flask import Blueprint, render_template, session, flash
from .core import require_connection, require_permission, get_ad_connection

admin_tools_bp = Blueprint('admin_tools', __name__, url_prefix='/')


@admin_tools_bp.route('/update')
def update_page():
    """Page de mise à jour."""
    try:
        from core.updater import check_for_updates_fast
        update_info = check_for_updates_fast()
    except Exception as e:
        update_info = {
            'update_available': False,
            'current_version': 'Erreur',
            'latest_version': None,
            'error': str(e)
        }
    return render_template('update.html', update_info=update_info, connected=False)


@admin_tools_bp.route('/diagnostic')
@require_connection
def diagnostic_page():
    """Page de diagnostic et dépannage."""
    return render_template('diagnostic.html', connected=True)


@admin_tools_bp.route('/alerts')
@require_connection
def alerts_page():
    """Page des alertes enrichie."""
    from ldap3 import SUBTREE
    from datetime import datetime, timedelta
    from .core import decode_ldap_value

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return render_template('alerts.html', alert_data={}, alerts=[], connected=True)

    base_dn = session.get('ad_base_dn', '')

    # Statistiques d'alertes enrichies
    alert_data = {
        'expiring_accounts': 0,
        'password_expiring': 0,
        'inactive_accounts': 0,
        'locked_accounts': 0,
        'empty_groups': 0,
        'disabled_accounts': 0,
        'inactive_computers': 0,
        'admin_accounts': 0,
        'service_accounts': 0,
    }

    alerts = []
    now = datetime.now()

    try:
        # === COMPTES VERROUILLES ===
        conn.search(base_dn, '(&(objectClass=user)(lockoutTime>=1))', SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'lockoutTime'])
        alert_data['locked_accounts'] = len(conn.entries)

        if alert_data['locked_accounts'] > 0:
            alerts.append({
                'title': f'{alert_data["locked_accounts"]} compte(s) verrouillé(s)',
                'message': 'Des comptes sont actuellement verrouillés suite à tentatives de connexion échouées.',
                'severity': 'warning',
                'date': now.strftime('%d/%m/%Y %H:%M'),
                'link': 'tools.locked_accounts'
            })

        # === COMPTES DESACTIVES ===
        conn.search(base_dn, '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))', SUBTREE,
                   attributes=['cn', 'sAMAccountName'])
        alert_data['disabled_accounts'] = len(conn.entries)

        if alert_data['disabled_accounts'] > 5:
            alerts.append({
                'title': f'{alert_data["disabled_accounts"]} compte(s) désactivé(s)',
                'message': 'Des comptes utilisateurs sont désactivés. Vérifiez s\'ils doivent être supprimés.',
                'severity': 'info',
                'date': now.strftime('%d/%m/%Y %H:%M'),
                'link': 'users.list_users'
            })

        # === COMPTES INACTIFS (lastLogon > 90 jours) ===
        inactive_users_list = []
        conn.search(base_dn, '(objectClass=user)', SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'lastLogon'])
        for entry in conn.entries:
            last_logon_attr = getattr(entry, 'lastLogon', None)
            if last_logon_attr and last_logon_attr.value:
                try:
                    last_logon_val = int(str(last_logon_attr.value))
                    if last_logon_val == 0:
                        alert_data['inactive_accounts'] += 1
                    else:
                        last_logon_date = datetime.fromtimestamp(last_logon_val / 10000000 - 11644473600)
                        days_since_logon = (now - last_logon_date).days
                        if days_since_logon > 90:
                            alert_data['inactive_accounts'] += 1
                            inactive_users_list.append(str(entry.cn))
                except (ValueError, TypeError):
                    pass
            else:
                alert_data['inactive_accounts'] += 1

        if alert_data['inactive_accounts'] > 10:
            alerts.append({
                'title': f'{alert_data["inactive_accounts"]} compte(s) inactif(s)',
                'message': f'Ces comptes n\'ont pas été utilisés depuis plus de 90 jours.',
                'severity': 'info',
                'date': now.strftime('%d/%m/%Y %H:%M'),
                'link': 'tools.inactive_accounts'
            })

        # === MOTS DE PASSE EXPIRANT (dans 14 jours) ===
        conn.search(base_dn, '(objectClass=user)', SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'pwdLastSet', 'userAccountControl'])
        for entry in conn.entries:
            pwd_last_set_attr = getattr(entry, 'pwdLastSet', None)
            uac_attr = getattr(entry, 'userAccountControl', None)
            
            # Skip if password doesn't expire (DONT_EXPIRE_PASSWORD flag = 65536)
            if uac_attr and uac_attr.value:
                try:
                    uac = int(str(uac_attr.value))
                    if uac & 65536:  # DONT_EXPIRE_PASSWORD
                        continue
                except:
                    pass
            
            if pwd_last_set_attr and pwd_last_set_attr.value:
                try:
                    pwd_val = int(str(pwd_last_set_attr.value))
                    if pwd_val > 0:
                        pwd_date = datetime.fromtimestamp(pwd_val / 10000000 - 11644473600)
                        # Default AD password age is 42 days
                        days_since_change = (now - pwd_date).days
                        if days_since_change > 28 and days_since_change < 42:  # Expires in 14 days
                            alert_data['password_expiring'] += 1
                except:
                    pass

        if alert_data['password_expiring'] > 0:
            alerts.append({
                'title': f'{alert_data["password_expiring"]} mot(s) de passe expirant',
                'message': 'Des mots de passe expirent dans moins de 14 jours. Notifiez les utilisateurs.',
                'severity': 'warning',
                'date': now.strftime('%d/%m/%Y %H:%M'),
                'link': 'tools.password_policy'
            })

        # === COMPTES ADMIN (memberof Domain Admins) ===
        conn.search(base_dn, '(&(objectClass=user)(memberof=CN=Domain Admins,CN=Users,' + base_dn + '))', SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'lastLogon'])
        alert_data['admin_accounts'] = len(conn.entries)

        if alert_data['admin_accounts'] > 3:
            alerts.append({
                'title': f'{alert_data["admin_accounts"]} compte(s) admin',
                'message': f'Multiple comptes Domain Admins détectés. Limitez les accès administrateurs.',
                'severity': 'critical',
                'date': now.strftime('%d/%m/%Y %H:%M'),
                'link': 'groups.view_group'
            })

        # Vérifier les comptes inactifs (pas de connexion depuis 90 jours)
        for entry in conn.entries:
            last_logon = getattr(entry, 'lastLogon', None)
            if last_logon and last_logon.value:
                try:
                    last_val = int(str(last_logon.value))
                    if last_val > 0:
                        last_date = datetime.fromtimestamp(last_val / 10000000 - 11644473600)
                        if (now - last_date).days > 90:
                            alert_data['inactive_accounts'] += 1
                except:
                    # Si impossible à parser, considérer comme inactif
                    alert_data['inactive_accounts'] += 1
            else:
                # Pas de lastLogon = jamais connecté
                alert_data['inactive_accounts'] += 1
        
        if alert_data['inactive_accounts'] > 10:
            alerts.append({
                'title': f'{alert_data["inactive_accounts"]} compte(s) inactif(s)',
                'message': 'Des comptes n\'ont pas été utilisés récemment. Considérez une revue.',
                'severity': 'info',
                'date': now.strftime('%d/%m/%Y %H:%M')
            })
        
        # Groupes vides (exclure les groupes système Windows)
        # Ces groupes ont member.Count=0 mais sont des groupes "primaires" 
        # ou groupes BUILTIN qui ont des membres via primaryGroupID
        SYSTEM_GROUP_TOKENS = [
            513, 514, 515, 516, 498, 521, 522, 525, 526, 527,  # Domain groups
            548, 549, 550, 551, 552, 553, 556, 557, 558, 559,  # BUILTIN groups
            560, 562, 569, 571, 573, 579, 580, 582, 568,  # More BUILTIN + RODC
            1102, 1103, 1104, 1114, 1118, 1121, 1124, 1125, 1126, 1129,  # App groups + VPN
            1153, 1154,  # DHCP groups
        ]
        
        conn.search(base_dn, '(objectClass=group)', SUBTREE,
                   attributes=['cn', 'member', 'primaryGroupToken', 'groupType'])
        for entry in conn.entries:
            # Vérifier si c'est un groupe système
            is_system_group = False
            if hasattr(entry, 'primaryGroupToken') and entry.primaryGroupToken.value:
                try:
                    token = int(str(entry.primaryGroupToken.value))
                    if token in SYSTEM_GROUP_TOKENS:
                        is_system_group = True
                except (ValueError, TypeError):
                    pass
            
            # Vérifier si le groupe a des membres (attribut member)
            has_members = False
            if hasattr(entry, 'member'):
                member_attr = entry.member
                if member_attr and member_attr.value:
                    if isinstance(member_attr.value, list):
                        has_members = len(member_attr.value) > 0
                    elif isinstance(member_attr.value, str):
                        has_members = len(member_attr.value) > 0
                    else:
                        has_members = bool(member_attr.value)
            
            # Compter seulement les groupes non-système sans membres
            if not is_system_group and not has_members:
                alert_data['empty_groups'] += 1
        
        if alert_data['empty_groups'] > 5:
            alerts.append({
                'title': f'{alert_data["empty_groups"]} groupe(s) vide(s)',
                'message': 'Certains groupes n\'ont aucun membre. Vérifiez leur pertinence.',
                'severity': 'info',
                'date': now.strftime('%d/%m/%Y %H:%M')
            })
        
        conn.unbind()
        
    except Exception as e:
        flash(f'Erreur lors de la récupération des alertes: {str(e)}', 'error')
    
    return render_template('alerts.html', alert_data=alert_data, alerts=alerts, connected=True)


@admin_tools_bp.route('/errors')
@require_connection
def error_logs():
    """Page des logs d'erreurs."""
    import os
    from pathlib import Path

    error_log_path = Path('logs/server.log')
    errors = []

    if error_log_path.exists():
        try:
            with open(error_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                errors = [line.strip() for line in lines if 'ERROR' in line or 'Exception' in line]
                errors = errors[-50:]
        except:
            errors = ['Impossible de lire les logs']

    return render_template('errors.html', errors=errors, connected=True)


@admin_tools_bp.route('/security-audit')
@require_connection
@require_permission('admin')
def security_audit():
    """Audit de sécurité."""
    from core.security_audit import check_security_issues

    conn, error = get_ad_connection()
    if not conn:
        from flask import flash
        flash(f'Erreur: {error}', 'error')
        return render_template('security_audit.html', issues=[], stats={'critical': 0, 'high': 0, 'warning': 0, 'fixable': 0}, connected=True)

    try:
        issues = check_security_issues(conn, session.get('ad_base_dn', ''))
        conn.unbind()

        # Calculer les statistiques
        stats = {
            'critical': len([i for i in issues if i.get('severity') == 'critical']),
            'high': len([i for i in issues if i.get('severity') == 'high']),
            'warning': len([i for i in issues if i.get('severity') == 'warning']),
            'fixable': len([i for i in issues if i.get('fixable', False)])
        }

        return render_template('security_audit.html', issues=issues, stats=stats, connected=True)
    except Exception as e:
        from flask import flash
        flash(f'Erreur: {str(e)}', 'error')
        return render_template('security_audit.html', issues=[], stats={'critical': 0, 'high': 0, 'warning': 0, 'fixable': 0}, connected=True)


@admin_tools_bp.route('/permissions')
@require_connection
@require_permission('admin')
def permissions_page():
    """Page de gestion des permissions."""
    from core.granular_permissions import get_all_groups_with_permissions, get_available_permissions, get_permission_categories

    groups = get_all_groups_with_permissions()
    all_permissions = get_available_permissions()
    categories = get_permission_categories()

    return render_template('admin.html',
                         groups=groups,
                         permissions=all_permissions,
                         categories=categories,
                         connected=True)
