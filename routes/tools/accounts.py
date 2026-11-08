"""Routes gestion des comptes : corbeille AD, comptes verrouillés, comptes expirant."""
from datetime import datetime, timedelta
from flask import render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.utils.dn import escape_rdn

from . import tools_bp
from ..core import get_ad_connection, decode_ldap_value, is_connected, require_connection, require_permission


# === CORBEILLE AD ===

# LDAP_SERVER_SHOW_DELETED_OID : rend visibles (et modifiables) les objets
# supprimés, qui sont sinon ignorés par le serveur.
_SHOW_DELETED = [('1.2.840.113556.1.4.417', True, None)]


def _original_name(cn):
    """
    Nom d'origine d'un objet supprimé. AD suffixe le CN d'un objet supprimé
    par un saut de ligne suivi de « DEL:<guid> » (« Dupont\\nDEL:1a2b… »),
    pour le rendre unique dans CN=Deleted Objects.
    """
    return str(cn or '').split('\nDEL:')[0].split('\\0ADEL:')[0]

@tools_bp.route('/recycle-bin')
@require_connection
@require_permission('tools:recycle_bin')
def recycle_bin():
    """Afficher la corbeille AD."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('main.connect'))

    deleted_objects = []
    try:
        base_dn = session.get('ad_base_dn', '')
        deleted_dn = f'CN=Deleted Objects,{base_dn}'
        conn.search(deleted_dn, '(isDeleted=TRUE)', SUBTREE,
                    attributes=['cn', 'distinguishedName', 'whenChanged', 'objectClass', 'lastKnownParent'],
                    controls=_SHOW_DELETED)

        for entry in conn.entries:
            # Determiner le type d'objet
            obj_classes = entry.objectClass.values if hasattr(entry, 'objectClass') and entry.objectClass else []
            # « computer » avant « user » : en AD, la classe computer hérite de
            # user, et les ordinateurs apparaissaient comme « Utilisateur ».
            if 'computer' in obj_classes:
                obj_type = 'Ordinateur'
            elif 'user' in obj_classes:
                obj_type = 'Utilisateur'
            elif 'group' in obj_classes:
                obj_type = 'Groupe'
            elif 'organizationalUnit' in obj_classes:
                obj_type = 'OU'
            else:
                obj_type = 'Autre'

            # Formater la date de suppression
            when_changed = decode_ldap_value(entry.whenChanged) if hasattr(entry, 'whenChanged') else ''

            # Emplacement d'origine
            last_parent = decode_ldap_value(entry.lastKnownParent) if hasattr(entry, 'lastKnownParent') else ''

            deleted_objects.append({
                'cn': _original_name(decode_ldap_value(entry.cn)),
                'dn': decode_ldap_value(entry.entry_dn),
                'whenChanged': when_changed,
                'lastKnownParent': last_parent,
                'type': obj_type,
            })
    except Exception as e:
        flash(f'Corbeille AD non disponible: {e}', 'warning')
    finally:
        conn.unbind()

    return render_template('recycle_bin.html', objects=deleted_objects, connected=is_connected())


@tools_bp.route('/recycle-bin/<path:dn>/restore', methods=['POST'])
@require_connection
@require_permission('tools:recycle_bin')
def restore_deleted_object(dn):
    """
    Restaurer un objet de la corbeille AD à son emplacement d'origine.

    Procédure documentée par Microsoft : une opération LDAP *modify* (et non
    un renommage) qui, avec le contrôle Show Deleted, retire l'attribut
    isDeleted et remplace distinguishedName par le DN de destination.
    L'ancienne implémentation tentait un modDN — refusé par AD sur un objet
    supprimé — avec un RDN sans « CN= » et encore suffixé de « DEL:<guid> » :
    aucune restauration ne pouvait aboutir.
    """
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.recycle_bin'))
    try:
        conn.search(dn, '(isDeleted=TRUE)', 'BASE',
                    attributes=['cn', 'lastKnownParent'], controls=_SHOW_DELETED)
        if not conn.entries:
            flash("Objet introuvable dans la corbeille.", 'error')
            return redirect(url_for('tools.recycle_bin'))

        entry = conn.entries[0]
        name = _original_name(decode_ldap_value(entry.cn))
        parent_dn = decode_ldap_value(entry.lastKnownParent) if 'lastKnownParent' in entry else ''
        if not name or not parent_dn:
            flash("Emplacement d'origine inconnu : restauration impossible.", 'error')
            return redirect(url_for('tools.recycle_bin'))

        target_dn = f'CN={escape_rdn(name)},{parent_dn}'
        conn.modify(dn, {
            'isDeleted': [(MODIFY_DELETE, [])],
            'distinguishedName': [(MODIFY_REPLACE, [target_dn])],
        }, controls=_SHOW_DELETED)
        if conn.result['result'] == 0:
            flash(f"Objet restauré : {target_dn}", 'success')
        else:
            flash("Erreur: %s" % (conn.result.get('message') or conn.result.get('description')
                                  or 'erreur inconnue'), 'error')
    except Exception as e:
        flash(f"Erreur lors de la restauration: {e}", 'error')
    finally:
        conn.unbind()
    return redirect(url_for('tools.recycle_bin'))


# === COMPTES VERROUILLÉS ===

@tools_bp.route('/locked-accounts')
@require_connection
def locked_accounts():
    """
    Afficher les comptes verrouillés.

    lockoutTime reste renseigné après la fin de la durée de verrouillage
    (AD ne le remet à 0 qu'à la connexion suivante) : on ne garde que les
    comptes encore réellement verrouillés au regard de lockoutDuration.
    """
    from core.ad_dates import ad_datetime, get_account_policy, is_locked_out, utcnow

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('main.connect'))

    base_dn = session.get('ad_base_dn', '')
    locked = []

    try:
        policy = get_account_policy(conn, base_dn)
        now = utcnow()
        conn.search(base_dn, '(&(objectClass=user)(objectCategory=person)(lockoutTime>=1))', SUBTREE,
                    attributes=['cn', 'sAMAccountName', 'mail', 'lockoutTime'])
        for entry in conn.entries:
            if not is_locked_out(entry.lockoutTime, policy['lockout_duration'], now):
                continue
            locked_at = ad_datetime(entry.lockoutTime)
            locked.append({
                'cn': decode_ldap_value(entry.cn),
                'sAMAccountName': decode_ldap_value(entry.sAMAccountName),
                'mail': decode_ldap_value(entry.mail) if 'mail' in entry else '',
                'dn': decode_ldap_value(entry.entry_dn),
                'lockoutTime': locked_at.strftime('%d/%m/%Y %H:%M') + ' UTC' if locked_at else '',
            })
    except Exception as e:
        flash(f'Erreur: {e}', 'error')
    finally:
        conn.unbind()

    return render_template('locked_accounts.html', accounts=locked, connected=is_connected())


def _unlock(conn, dn):
    """
    Déverrouiller un compte : lockoutTime = 0.

    ldap3 exige un dictionnaire {attribut: [(opération, [valeurs])]}. L'ancien
    appel passait une liste — ldap3 levait « changes must be a dictionary »
    avant tout envoi — et une valeur de 8 octets nuls, alors que lockoutTime
    (syntaxe Integer8) attend l'entier 0 : aucun compte ne pouvait être
    déverrouillé depuis l'interface.
    """
    conn.modify(dn, {'lockoutTime': [(MODIFY_REPLACE, [0])]})


@tools_bp.route('/locked-accounts/unlock', methods=['POST'])
@require_connection
@require_permission('tools:unlock_accounts')
def bulk_unlock_accounts():
    """Débloquer un ou plusieurs comptes utilisateurs."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.locked_accounts'))

    # « dns » : nom des cases à cocher de locked_accounts.html. L'ancien code
    # lisait « selected_accounts », que la page n'envoie pas : le déblocage
    # groupé répondait toujours « Aucun compte sélectionné ».
    selected = request.form.getlist('dns') or request.form.getlist('selected_accounts')
    if not selected:
        flash('Aucun compte sélectionné.', 'warning')
        return redirect(url_for('tools.locked_accounts'))

    unlocked = failed = 0
    try:
        for dn in selected:
            try:
                _unlock(conn, dn)
                if conn.result['result'] == 0:
                    unlocked += 1
                else:
                    failed += 1
            except Exception:
                failed += 1

        if unlocked:
            flash(f'{unlocked} compte(s) débloqué(s).', 'success')
        if failed:
            flash(f'{failed} échec(s) lors du déblocage.', 'warning')
    except Exception as e:
        flash(f'Erreur lors du déblocage: {e}', 'error')
    finally:
        conn.unbind()

    return redirect(url_for('tools.locked_accounts'))


@tools_bp.route('/locked-accounts/unlock/<path:dn>', methods=['POST'])
@require_connection
@require_permission('tools:unlock_accounts')
def unlock_account(dn):
    """Débloquer un compte utilisateur individuel."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.locked_accounts'))
    try:
        _unlock(conn, dn)
        if conn.result['result'] == 0:
            flash('Compte débloqué avec succès.', 'success')
        else:
            flash(f"Échec du déblocage: {conn.result.get('description', 'erreur inconnue')}", 'error')
    except Exception as e:
        flash(f'Erreur: {e}', 'error')
    finally:
        conn.unbind()
    return redirect(url_for('tools.locked_accounts'))


# === COMPTES EXPIRANT ===

def _collect_expiring(conn, base_dn):
    """
    Comptes expirant, mots de passe expirant et comptes inactifs.

    Les dates passent par core.ad_dates : avec le schéma chargé, ldap3 les
    renvoie déjà en datetime. Le mot de passe est jugé sur la durée maximale
    réelle du domaine (maxPwdAge), et la dernière connexion sur
    lastLogonTimestamp, répliqué entre les DC.
    """
    from core.account_stats import (ACCOUNT_WARNING_DAYS, INACTIVE_DAYS,
                                    PASSWORD_WARNING_DAYS, UF_ACCOUNTDISABLE)
    from core.ad_dates import ad_datetime, get_account_policy, last_logon, password_expiry, utcnow
    from ..core import paged_search

    now = utcnow()
    account_limit = now + timedelta(days=ACCOUNT_WARNING_DAYS)
    password_limit = now + timedelta(days=PASSWORD_WARNING_DAYS)
    inactive_limit = now - timedelta(days=INACTIVE_DAYS)
    policy = get_account_policy(conn, base_dn)

    expiring, passwords, inactive = [], [], []
    entries = paged_search(conn, base_dn, '(&(objectClass=user)(objectCategory=person))',
                           attributes=['cn', 'sAMAccountName', 'mail', 'accountExpires',
                                       'pwdLastSet', 'lastLogon', 'lastLogonTimestamp',
                                       'whenCreated', 'userAccountControl'])
    for entry in entries:
        sam = decode_ldap_value(entry.sAMAccountName)
        if sam.lower() in _EXCLUDED_ACCOUNTS or sam.endswith('$'):
            continue
        try:
            uac = int(entry.userAccountControl.value or 0)
        except (AttributeError, TypeError, ValueError):
            uac = 0
        if uac & UF_ACCOUNTDISABLE:
            continue  # un compte désactivé n'expire ni ne se connecte
        base = {
            'cn': decode_ldap_value(entry.cn),
            'sAMAccountName': sam,
            'mail': decode_ldap_value(entry.mail) if 'mail' in entry else None,
            'dn': decode_ldap_value(entry.entry_dn),
        }

        expires = ad_datetime(getattr(entry, 'accountExpires', None))
        if expires and expires <= account_limit:
            expiring.append(dict(base, date=expires, expired=expires < now))

        pwd_expires = password_expiry(getattr(entry, 'pwdLastSet', None),
                                      policy['max_pwd_age'], uac)
        if pwd_expires and pwd_expires <= password_limit:
            passwords.append(dict(base, date=pwd_expires, expired=pwd_expires < now))

        seen = last_logon(entry)
        if seen and seen < inactive_limit:
            inactive.append(dict(base, date=seen))
        elif not seen:
            created = ad_datetime(getattr(entry, 'whenCreated', None))
            if created and created < inactive_limit:
                inactive.append(dict(base, date=None))  # jamais connecté

    # Les plus urgents d'abord ; « jamais connecté » en tête des inactifs.
    expiring.sort(key=lambda a: a['date'])
    passwords.sort(key=lambda a: a['date'])
    inactive.sort(key=lambda a: (a['date'] is not None, a['date'] or now))
    return {'expiring_accounts': expiring, 'password_expiring': passwords,
            'inactive_accounts': inactive, 'policy': policy,
            'account_days': ACCOUNT_WARNING_DAYS, 'password_days': PASSWORD_WARNING_DAYS,
            'inactive_days': INACTIVE_DAYS}


_EXCLUDED_ACCOUNTS = {'krbtgt', 'guest', 'invité', 'defaultaccount', 'wdagutilityaccount'}


@tools_bp.route('/expiring')
@require_connection
def expiring_accounts():
    """Comptes expirant bientôt."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('main.connect'))

    data = {'expiring_accounts': [], 'password_expiring': [], 'inactive_accounts': [],
            'policy': {'max_pwd_age': None}, 'account_days': 30, 'password_days': 14,
            'inactive_days': 90}
    try:
        data = _collect_expiring(conn, session.get('ad_base_dn', ''))
    except Exception as e:
        flash(f'Erreur: {e}', 'error')
    finally:
        conn.unbind()

    return render_template('expiring_accounts.html', connected=is_connected(), **data)


@tools_bp.route('/expiring/export-pdf')
@require_connection
@require_permission('tools:expiring_pdf')
def export_expiring_pdf():
    """Export PDF des comptes expirants, mots de passe expirant et inactifs."""
    from io import BytesIO
    from flask import send_file
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.expiring_accounts'))
    try:
        data = _collect_expiring(conn, session.get('ad_base_dn', ''))
    except Exception as e:
        flash(f'Erreur: {e}', 'error')
        return redirect(url_for('tools.expiring_accounts'))
    finally:
        conn.unbind()

    styles = getSampleStyleSheet()
    cell = styles['BodyText']
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), title='Comptes expirants',
                            leftMargin=1.5 * cm, rightMargin=1.5 * cm,
                            topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    story = [Paragraph('Comptes expirants', styles['Title']),
             Paragraph(f"Généré le {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles['Normal']),
             Spacer(1, 0.5 * cm)]

    def fmt(row, never='Jamais'):
        if row['date'] is None:
            return never
        text = row['date'].strftime('%d/%m/%Y')
        return f'{text} (dépassé)' if row.get('expired') else text

    sections = [
        (f"Comptes expirant sous {data['account_days']} jours", 'Expiration',
         data['expiring_accounts']),
        (f"Mots de passe expirant sous {data['password_days']} jours", 'Expiration du mot de passe',
         data['password_expiring']),
        (f"Comptes inactifs depuis plus de {data['inactive_days']} jours", 'Dernière connexion',
         data['inactive_accounts']),
    ]
    for title, date_label, rows in sections:
        story.append(Paragraph(f'{escape(title)} ({len(rows)})', styles['Heading2']))
        if not rows:
            story.append(Paragraph('Aucun.', styles['Normal']))
            story.append(Spacer(1, 0.4 * cm))
            continue
        table_data = [['Nom', 'Identifiant', 'Email', date_label]]
        for row in rows:
            table_data.append([Paragraph(escape(str(row['cn'] or '')), cell),
                               Paragraph(escape(str(row['sAMAccountName'] or '')), cell),
                               Paragraph(escape(str(row['mail'] or '-')), cell),
                               fmt(row)])
        table = Table(table_data, colWidths=[7 * cm, 5 * cm, 8 * cm, 5 * cm], repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4e79')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f2f2f2')]),
        ]))
        story += [table, Spacer(1, 0.5 * cm)]

    doc.build(story)
    buffer.seek(0)
    filename = f"comptes_expirants_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    return send_file(buffer, mimetype='application/pdf', as_attachment=True,
                     download_name=filename)
