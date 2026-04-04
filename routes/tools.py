"""
Blueprint pour les outils (LAPS, BitLocker, Corbeille, etc.).
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE
from ldap3.core.exceptions import LDAPException

from .core import (get_ad_connection, decode_ldap_value, is_connected,
                   require_connection, require_permission, config)
from security import escape_ldap_filter, rate_limit_sensitive, record_attempt

tools_bp = Blueprint('tools', __name__)


# === LAPS ===
@tools_bp.route('/laps')
@require_connection
@require_permission('admin')
def laps_passwords():
    """Afficher les mots de passe LAPS."""
    from ldap3.core.exceptions import LDAPAttributeError
    
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')

    if search_query:
        safe_query = escape_ldap_filter(search_query)
        search_filter = f'(&(objectClass=computer)(cn=*{safe_query}*))'
    else:
        search_filter = '(objectClass=computer)'

    computers = []
    laps_available = True
    
    try:
        # Vérifier si les attributs LAPS existent dans le schéma
        conn.search(base_dn, '(objectClass=computer)', SUBTREE,
                   attributes=['objectClass'], 
                   get_operational_attributes=True)
        
        # Vérifier la présence des attributs LAPS dans le schéma
        schema_attrs = conn.server.schema.attribute_types if conn.server.schema else []
        has_legacy_laps = 'ms-Mcs-AdmPwd' in schema_attrs
        has_new_laps = 'msLAPS-Password' in schema_attrs
        
        if not has_legacy_laps and not has_new_laps:
            laps_available = False
            flash('LAPS n\'est pas installé sur ce domaine. Installez Windows LAPS ou Legacy LAPS pour afficher les mots de passe administrateur local.', 'warning')
        else:
            # Construire la liste des attributs à récupérer
            attrs = ['cn', 'distinguishedName', 'operatingSystem']
            if has_legacy_laps:
                attrs.extend(['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'])
            if has_new_laps:
                attrs.extend(['msLAPS-Password', 'msLAPS-PasswordExpirationTime'])
            
            conn.search(base_dn, search_filter, SUBTREE, attributes=attrs)

            for entry in conn.entries:
                pwd = None
                exp = None
                laps_type = 'Aucun'

                # Ancien LAPS
                if has_legacy_laps and hasattr(entry, 'ms-Mcs-AdmPwd'):
                    pwd_val = getattr(entry, 'ms-Mcs-AdmPwd', None)
                    if pwd_val and pwd_val.value:
                        pwd = decode_ldap_value(pwd_val)
                        laps_type = 'LAPS (Legacy)'
                        exp_val = getattr(entry, 'ms-Mcs-AdmPwdExpirationTime', None)
                        exp = decode_ldap_value(exp_val) if exp_val else None

                # Nouveau LAPS (Windows LAPS)
                if not pwd and has_new_laps and hasattr(entry, 'msLAPS-Password'):
                    pwd_val = getattr(entry, 'msLAPS-Password', None)
                    if pwd_val and pwd_val.value:
                        pwd = decode_ldap_value(pwd_val)
                        laps_type = 'Windows LAPS'
                        exp_val = getattr(entry, 'msLAPS-PasswordExpirationTime', None)
                        exp = decode_ldap_value(exp_val) if exp_val else None

                if pwd:
                    computers.append({
                        'cn': decode_ldap_value(entry.cn),
                        'os': decode_ldap_value(getattr(entry, 'operatingSystem', None)) or 'Inconnu',
                        'dn': decode_ldap_value(entry.distinguishedName),
                        'laps_type': laps_type,
                        'laps_password': pwd,
                        'laps_expiration': exp or 'Inconnue'
                    })
                    
    except LDAPAttributeError as e:
        laps_available = False
        flash(f'LAPS n\'est pas installé: {str(e)}', 'warning')
    except Exception as e:
        flash(f'Erreur LAPS: {str(e)}', 'error')
    finally:
        conn.unbind()

    return render_template('laps.html', computers=computers, search=search_query,
                         connected=is_connected(), laps_available=laps_available)


# === BITLOCKER ===
@tools_bp.route('/bitlocker')
@require_connection
@require_permission('admin')
def bitlocker_keys():
    """Afficher les clés de récupération BitLocker."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    search_query = request.args.get('search', '')
    keys = []

    try:
        # Chercher les objets BitLocker
        if search_query:
            safe_query = escape_ldap_filter(search_query)
            search_filter = f'(&(objectClass=msFVE-RecoveryInformation)(cn=*{safe_query}*))'
        else:
            search_filter = '(objectClass=msFVE-RecoveryInformation)'

        conn.search(base_dn, search_filter, SUBTREE,
                   attributes=['cn', 'distinguishedName', 'msFVE-RecoveryPassword',
                              'msFVE-VolumeGuid', 'whenCreated'])

        for entry in conn.entries:
            # Extraire le nom de l'ordinateur du DN
            dn = decode_ldap_value(entry.distinguishedName)
            computer_name = ''
            parts = dn.split(',')
            for p in parts:
                if p.upper().startswith('CN=') and not p.startswith('CN={'):
                    computer_name = p[3:]
                    break

            keys.append({
                'computer': computer_name,
                'dn': dn,
                'recovery_password': decode_ldap_value(getattr(entry, 'msFVE-RecoveryPassword', '')),
                'volume_guid': decode_ldap_value(getattr(entry, 'msFVE-VolumeGuid', '')),
                'created': decode_ldap_value(entry.whenCreated)
            })
        conn.unbind()
    except Exception as e:
        flash(f'Erreur BitLocker: {str(e)}', 'error')

    return render_template('bitlocker.html', keys=keys, search=search_query,
                         connected=is_connected())


# === CORBEILLE AD ===
@tools_bp.route('/recycle-bin')
@require_connection
@require_permission('admin')
def recycle_bin():
    """Afficher la corbeille AD."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    deleted_objects = []
    try:
        # Chercher dans le conteneur Deleted Objects
        base_dn = session.get('ad_base_dn', '')
        deleted_dn = f'CN=Deleted Objects,{base_dn}'

        conn.search(deleted_dn, '(isDeleted=TRUE)', SUBTREE,
                   attributes=['cn', 'distinguishedName', 'whenChanged', 'objectClass'],
                   controls=[('1.2.840.113556.1.4.417', True, None)])  # Show deleted

        for entry in conn.entries:
            deleted_objects.append({
                'cn': decode_ldap_value(entry.cn),
                'dn': decode_ldap_value(entry.distinguishedName),
                'deleted': decode_ldap_value(entry.whenChanged),
                'type': 'user' if 'user' in (entry.objectClass.values or []) else 'other'
            })
        conn.unbind()
    except Exception as e:
        flash(f'Corbeille AD non disponible: {str(e)}', 'warning')

    return render_template('recycle_bin.html', objects=deleted_objects,
                         connected=is_connected())


# === RESTAURER OBJET SUPPRIME ===
@tools_bp.route('/recycle-bin/<path:dn>/restore', methods=['POST'])
@require_connection
@require_permission('admin')
@rate_limit_sensitive(max_attempts=10, window_seconds=300)
def restore_deleted_object(dn):
    """
    Restaurer un objet supprimé de la corbeille AD.
    Note: Cette fonctionnalité nécessite que la corbeille AD soit activée.

    Pour restaurer un objet supprimé:
    1. L'objet doit être dans la corbeille AD (isDeleted=TRUE)
    2. Il faut modifier le distinguishedName pour lui redonner un chemin valide
    3. Positionner isDeleted à FALSE
    """
    from ldap3.core.exceptions import LDAPException

    ip = request.remote_addr
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.recycle_bin'))

    try:
        # Décoder le DN (url-encoded)
        from urllib.parse import unquote
        deleted_dn = unquote(dn)
        
        # Récupérer le nouveau DN depuis le form
        new_parent_dn = request.form.get('new_parent_dn', '')
        
        if not new_parent_dn:
            # Utiliser le parent d'origine de l'objet supprimé
            # Extraire le RDN (CN=...) et le parent DN
            parts = deleted_dn.split(',', 1)
            if len(parts) != 2:
                flash('DN invalide ou parent DN manquant.', 'error')
                return redirect(url_for('tools.recycle_bin'))
            
            rdn = parts[0]  # ex: CN=John Doe
            # Le parent est déjà dans le DN original (après suppression de CN=...)
            # Pour un objet supprimé, le DN est comme: CN=John Doe\0ADEL:...
            new_parent_dn = parts[1]
        
        # Construire le nouveau DN
        # Pour un objet supprimé, le DN contient \0ADEL:guid
        # Il faut le retirer
        rdn_parts = deleted_dn.split(',', 1)[0].split('=')
        if len(rdn_parts) >= 2:
            rdn_clean = f"{rdn_parts[0]}={rdn_parts[1]}"  # Garde seulement CN=Value sans \0ADEL
        else:
            rdn_clean = rdn_parts[0]
        
        new_dn = f"{rdn_clean},{new_parent_dn}"
        
        logger.info(f"Restauration: {deleted_dn} -> {new_dn}")
        
        # Opération de restauration:
        # 1. Modifier le DN pour retirer \0ADEL:guid et replacer l'objet
        # 2. Set isDeleted à FALSE (implicite dans laopération de rename)
        conn.rename(deleted_dn, new_dn)
        
        if conn.result['result'] == 0:
            # Succès
            object_name = deleted_dn.split(',')[0].split('=')[1] if '=' in deleted_dn.split(',')[0] else deleted_dn
            flash(f'Objet "{object_name}" restauré avec succès.', 'success')
            record_attempt(ip, success=True, action='restore_object')
            log_action('RESTORE_OBJECT', session.get('ad_username'),
                      {'dn': deleted_dn, 'new_dn': new_dn}, True, request.remote_addr)
        else:
            # Erreur - enregistrer comme tentative échouée
            record_attempt(ip, success=False, action='restore_object')
            error_msg = conn.result['message']
            if 'insufficient access' in error_msg.lower() or 'unwilling' in error_msg.lower():
                flash('Erreur: Permissions insuffisantes ou corbeille AD non activée. '
                      'Vérifiez que la corbeille AD est activée et que vous avez les droits.', 'error')
            else:
                flash(f'Erreur lors de la restauration: {error_msg}', 'error')
                
    except LDAPException as e:
        error_msg = str(e)
        if 'isDeleted' in error_msg or 'naming' in error_msg.lower():
            flash('Erreur: La corbeille AD n\'est probablement pas activée sur ce domaine. '
                  'Activez-la avec: Enable-ADOptionalFeature -Identity "Recycle Bin Feature"', 'error')
        else:
            flash(f'Erreur LDAP: {error_msg}', 'error')
        logger.error(f"Erreur restauration: {error_msg}", exc_info=True)
    except Exception as e:
        flash(f'Erreur lors de la restauration: {str(e)}', 'error')
        logger.error(f"Erreur restauration: {str(e)}", exc_info=True)
    finally:
        conn.unbind()

    return redirect(url_for('tools.recycle_bin'))


# === COMPTES VERROUILLES ===
@tools_bp.route('/locked-accounts')
@require_connection
def locked_accounts():
    """Afficher les comptes verrouillés."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    locked = []

    try:
        # Chercher les comptes verrouillés (lockoutTime > 0)
        conn.search(base_dn, '(&(objectClass=user)(lockoutTime>=1))', SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'distinguishedName', 'lockoutTime'])

        for entry in conn.entries:
            locked.append({
                'cn': decode_ldap_value(entry.cn),
                'sAMAccountName': decode_ldap_value(entry.sAMAccountName),
                'dn': decode_ldap_value(entry.distinguishedName),
                'lockoutTime': decode_ldap_value(entry.lockoutTime)
            })
        conn.unbind()
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')

    return render_template('locked_accounts.html', accounts=locked,
                         connected=is_connected())


# === DEBLOQUER COMPTES ===
@tools_bp.route('/locked-accounts/unlock', methods=['POST'])
@require_connection
@require_permission('admin')
@rate_limit_sensitive(max_attempts=10, window_seconds=300)
def bulk_unlock_accounts():
    """
    Débloquer un ou plusieurs comptes utilisateurs.
    Utilise ldap3 pour réinitialiser l'attribut lockoutTime à 0.
    """
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.locked_accounts'))

    # Récupérer les comptes à débloquer
    selected_accounts = request.form.getlist('selected_accounts')
    unlock_all = request.form.get('unlock_all', 'false') == 'true'

    if not selected_accounts and not unlock_all:
        flash('Aucun compte sélectionné.', 'warning')
        return redirect(url_for('tools.locked_accounts'))

    ip = request.remote_addr

    unlocked_count = 0
    failed_count = 0
    unlocked_users = []

    try:
        # Si unlock_all, récupérer tous les comptes verrouillés
        if unlock_all:
            base_dn = session.get('ad_base_dn', '')
            conn.search(base_dn, '(&(objectClass=user)(lockoutTime>=1))', SUBTREE,
                       attributes=['distinguishedName', 'sAMAccountName'])
            selected_accounts = [decode_ldap_value(entry.distinguishedName) for entry in conn.entries]

        for dn in selected_accounts:
            try:
                # Débloquer le compte en réinitialisant lockoutTime à 0
                # Format: lockoutTime: INTEGER (0 = débloqué)
                result = conn.modify(dn, {'lockoutTime': 0})
                
                if result:
                    unlocked_count += 1
                    # Extraire le nom d'utilisateur pour le log
                    user_dn_parts = dn.split(',')
                    user_cn = user_dn_parts[0].split('=')[1] if '=' in user_dn_parts[0] else user_dn_parts[0]
                    unlocked_users.append(user_cn)
                    logger.info(f"Compte débloqué: {user_cn}")
                else:
                    failed_count += 1
                    logger.warning(f"Échec déblocage: {dn} - {conn.result.get('message', 'Unknown')}")
                    
            except Exception as e:
                failed_count += 1
                logger.error(f"Erreur déblocage {dn}: {str(e)}")

        # Messages de résultat
        if unlocked_count > 0:
            flash(f'{unlocked_count} compte(s) débloqué(s) avec succès.', 'success')
            record_attempt(ip, success=True, action='unlock_accounts')
            log_action('BULK_UNLOCK_ACCOUNTS', session.get('ad_username'),
                      {'unlocked': unlocked_count, 'failed': failed_count,
                       'users': unlocked_users[:10]},  # Limite à 10 pour le log
                      True, request.remote_addr)
        else:
            # Échec total - enregistrer comme tentative échouée
            record_attempt(ip, success=False, action='unlock_accounts')

        if failed_count > 0:
            flash(f'{failed_count} échec(s) lors du déblocage.', 'warning')

    except Exception as e:
        flash(f'Erreur lors du déblocage: {str(e)}', 'error')
        logger.error(f"Erreur déblocage massif: {str(e)}", exc_info=True)
    finally:
        conn.unbind()

    return redirect(url_for('tools.locked_accounts'))


# === EXPORT EXPIRING PDF ===
@tools_bp.route('/expiring/export-pdf')
@require_connection
@require_permission('admin')
def export_expiring_pdf():
    """
    Exporter les comptes expirants en PDF.
    Placeholder - fonctionnalité à implémenter.
    """
    flash('Export PDF non implémenté.', 'info')
    return redirect(url_for('tools.expiring_accounts'))


# === MODELES UTILISATEURS ===
@tools_bp.route('/templates')
@require_connection
def user_templates():
    """Gestion des modèles utilisateurs."""
    flash('Fonctionnalité modèles disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))


# === FAVORIS ===
@tools_bp.route('/favorites')
@require_connection
def favorites():
    """Gestion des favoris."""
    flash('Fonctionnalité favoris disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))


# === COMPTES EXPIRANT ===
@tools_bp.route('/expiring')
@require_connection
def expiring_accounts():
    """Comptes expirant bientôt."""
    from datetime import datetime, timedelta
    from ldap3 import SUBTREE
    
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    
    # Dates pour les calculs
    now = datetime.now()
    expiry_threshold = now + timedelta(days=30)
    password_threshold = now + timedelta(days=14)
    inactive_threshold = now - timedelta(days=90)
    
    expiring_accounts_list = []
    password_expiring_list = []
    inactive_accounts_list = []

    try:
        # Chercher les comptes avec une date d'expiration
        conn.search(base_dn, '(&(objectClass=user)(accountExpires>=1))', SUBTREE,
                   attributes=['cn', 'sAMAccountName', 'accountExpires', 'mail', 'distinguishedName', 
                              'pwdLastSet', 'lastLogon'])

        for entry in conn.entries:
            account_data = {
                'cn': decode_ldap_value(entry.cn),
                'sAMAccountName': decode_ldap_value(entry.sAMAccountName),
                'mail': decode_ldap_value(entry.mail) if hasattr(entry, 'mail') else None,
                'dn': decode_ldap_value(entry.distinguishedName),
            }
            
            # Date d'expiration du compte
            if hasattr(entry, 'accountExpires') and entry.accountExpires.value:
                try:
                    from ldap3.utils.conv import from_ad_timestamp
                    expiry_date = from_ad_timestamp(entry.accountExpires.value)
                    account_data['accountExpires'] = expiry_date.strftime('%Y-%m-%d') if expiry_date else 'Jamais'
                    
                    if expiry_date and expiry_date <= expiry_threshold:
                        expiring_accounts_list.append(account_data.copy())
                except:
                    account_data['accountExpires'] = 'Inconnue'
            
            # Date du dernier changement de mot de passe
            if hasattr(entry, 'pwdLastSet') and entry.pwdLastSet.value:
                try:
                    from ldap3.utils.conv import from_ad_timestamp
                    pwd_date = from_ad_timestamp(entry.pwdLastSet.value)
                    if pwd_date and pwd_date <= password_threshold:
                        account_data['pwdLastSet'] = pwd_date.strftime('%Y-%m-%d')
                        password_expiring_list.append(account_data.copy())
                except:
                    pass
            
            # Dernière connexion
            if hasattr(entry, 'lastLogon') and entry.lastLogon.value:
                try:
                    from ldap3.utils.conv import from_ad_timestamp
                    last_logon = from_ad_timestamp(entry.lastLogon.value)
                    account_data['lastLogon'] = last_logon.strftime('%Y-%m-%d') if last_logon else 'Jamais'
                    
                    if last_logon and last_logon <= inactive_threshold:
                        inactive_accounts_list.append(account_data.copy())
                except:
                    account_data['lastLogon'] = 'Inconnue'
            else:
                account_data['lastLogon'] = 'Jamais'
                inactive_accounts_list.append(account_data.copy())
                
        conn.unbind()
    except Exception as e:
        flash(f'Erreur: {str(e)}', 'error')

    return render_template('expiring_accounts.html', 
                         expiring_accounts=expiring_accounts_list,
                         password_expiring=password_expiring_list,
                         inactive_accounts=inactive_accounts_list,
                         connected=is_connected())


# === DOCUMENTATION API ===
@tools_bp.route('/api-docs')
@require_connection
@require_permission('admin')
def api_documentation():
    """Documentation de l'API."""
    flash('Documentation API disponible dans la version complète.', 'info')
    return redirect(url_for('dashboard'))


# === POLITIQUE DE MOTS DE PASSE ===
# Route déplacée vers routes/tools/password.py (éviter doublon)


# === AUDIT MOTS DE PASSE ===
@tools_bp.route('/password-audit')
@require_connection
@require_permission('admin')
def password_audit():
    """Page d'audit des mots de passe."""
    return render_template('password_audit.html', connected=is_connected())


# === BACKUPS ===
@tools_bp.route('/backups')
@require_connection
@require_permission('admin')
def backups():
    """Liste des backups d'objets AD."""
    from backup import get_backups
    backup_list = get_backups(limit=100)
    return render_template('backups.html', backups=backup_list, connected=is_connected())


@tools_bp.route('/backups/<filename>')
@require_connection
@require_permission('admin')
def view_backup(filename):
    """Voir le détail d'un backup."""
    from backup import get_backup_content
    backup = get_backup_content(filename)
    if not backup:
        flash('Backup introuvable.', 'error')
        return redirect(url_for('tools.backups'))
    return render_template('backup_detail.html', backup=backup, connected=is_connected())


# === EXPORT AUDIT MOTS DE PASSE ===
@tools_bp.route('/password-audit/export/csv')
@require_connection
@require_permission('admin')
def export_password_audit_csv():
    """Exporter l'audit des mots de passe en CSV."""
    from flask import Response
    from password_audit import run_password_audit, export_audit_to_csv
    
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.password_audit'))
    
    base_dn = session.get('ad_base_dn', '')
    audit_result = run_password_audit(conn, base_dn, max_age_days=90)
    conn.unbind()
    
    csv_data = export_audit_to_csv(audit_result)
    
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=password_audit.csv'}
    )


@tools_bp.route('/password-audit/export/json')
@require_connection
@require_permission('admin')
def export_password_audit_json():
    """Exporter l'audit des mots de passe en JSON."""
    from flask import Response
    from password_audit import run_password_audit, export_audit_to_json
    
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.password_audit'))
    
    base_dn = session.get('ad_base_dn', '')
    audit_result = run_password_audit(conn, base_dn, max_age_days=90)
    conn.unbind()
    
    json_data = export_audit_to_json(audit_result)
    
    return Response(
        json_data,
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=password_audit.json'}
    )
