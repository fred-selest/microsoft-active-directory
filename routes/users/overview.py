# -*- coding: utf-8 -*-
"""
Fiche 360° d'une personne et départ d'un collaborateur.

La fiche réunit sur une page ce qui est dispersé ailleurs : état du compte,
messagerie, groupes, stratégies de groupe reçues, répertoires accessibles,
départs passés. Le départ est dans core/offboarding.py.
"""
import logging
from urllib.parse import unquote

from flask import flash, redirect, render_template, request, session, url_for

from . import users_bp
from ..core import (get_ad_connection, is_connected, require_connection,
                    require_permission)
from core import offboarding as ob
from core.audit import log_action

logger = logging.getLogger(__name__)


def _base():
    return session.get('ad_base_dn', '')


def _name(dn):
    return dn.split(',')[0].split('=', 1)[-1]


def _can(permission):
    from config import get_config
    from core.granular_permissions import has_permission
    if not get_config().RBAC_ENABLED:
        return True
    return has_permission(session.get('user_groups', []), permission,
                          username=session.get('ad_username'), user_dn=session.get('user_dn'))


def _overview(conn, dn):
    from ldap3 import BASE
    from core.ad_dates import (ad_datetime, get_account_policy, is_locked_out, last_logon,
                               password_expiry, utcnow)
    from core.onboarding import get_onboarding_settings
    base_dn = _base()
    conn.search(dn, '(&(objectClass=user)(objectCategory=person))', BASE,
                attributes=['cn', 'displayName', 'sAMAccountName', 'userPrincipalName', 'mail',
                            'proxyAddresses', 'otherMailbox', 'title', 'department', 'manager',
                            'telephoneNumber', 'description', 'userAccountControl', 'lastLogon',
                            'lastLogonTimestamp', 'pwdLastSet', 'accountExpires', 'lockoutTime',
                            'whenCreated', 'memberOf', 'homeDirectory', 'homeDrive', 'adminCount'])
    if not conn.entries:
        return None
    e = conn.entries[0]

    def val(attr, default=''):
        if attr in e:
            value = getattr(e, attr).value
            if isinstance(value, list):
                value = value[0] if value else default
            return default if value is None else value
        return default

    def values(attr):
        return [str(v) for v in getattr(e, attr).values] if attr in e else []

    uac = int(val('userAccountControl', 512) or 512)
    policy = get_account_policy(conn, base_dn)
    now = utcnow()
    expiry = password_expiry(getattr(e, 'pwdLastSet', None), policy['max_pwd_age'], uac)
    account_expires = ad_datetime(getattr(e, 'accountExpires', None))
    license_groups = {g.lower() for g in get_onboarding_settings()['license_groups']}
    groups = [{'dn': g, 'name': _name(g), 'license': _name(g).lower() in license_groups}
              for g in sorted(values('memberOf'), key=lambda g: _name(g).lower())]
    proxies = values('proxyAddresses')
    user = {
        'dn': e.entry_dn, 'sam': str(val('sAMAccountName')),
        'name': str(val('displayName') or val('cn')), 'title': str(val('title')),
        'department': str(val('department')), 'phone': str(val('telephoneNumber')),
        'description': str(val('description')), 'manager': _name(str(val('manager'))) if val('manager') else '',
        'ou': e.entry_dn.split(',', 1)[1] if ',' in e.entry_dn else '',
        'enabled': not uac & 0x2, 'locked': is_locked_out(getattr(e, 'lockoutTime', None),
                                                         policy['lockout_duration'], now),
        'admin': int(val('adminCount', 0) or 0) == 1,
        'pwd_never_expires': bool(uac & 0x10000),
        'pwd_expires': expiry, 'pwd_expired': bool(expiry and expiry < now),
        'pwd_must_change': ad_datetime(getattr(e, 'pwdLastSet', None)) is None and not uac & 0x10000,
        'account_expires': account_expires, 'account_expired': bool(account_expires and account_expires < now),
        'last_logon': last_logon(e), 'created': ad_datetime(getattr(e, 'whenCreated', None)),
        'upn': str(val('userPrincipalName')), 'mail': str(val('mail')),
        'aliases': [p[5:] for p in proxies if p.startswith('smtp:')],
        'personal_email': (values('otherMailbox') or [''])[0],
        'home': str(val('homeDirectory')), 'home_drive': str(val('homeDrive')),
        'groups': groups,
    }
    return user


@users_bp.route('/<path:dn>/overview')
@require_connection
@require_permission('users:read')
def overview(dn):
    """Fiche 360° d'une personne."""
    dn = unquote(dn)
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur : {error}', 'error')
        return redirect(url_for('users.list_users'))
    gpos, gpo_error = None, None
    try:
        if not dn.lower().endswith(_base().lower()):
            flash('Compte hors du domaine.', 'error')
            return redirect(url_for('users.list_users'))
        user = _overview(conn, dn)
        if not user:
            flash('Utilisateur introuvable.', 'error')
            return redirect(url_for('users.list_users'))
        if _can('gpo:read'):
            from core import gpo as gp
            try:
                gpos = gp.applied_gpos(conn, _base(), user['dn'])
            except Exception as e:                      # la fiche reste utile sans les stratégies
                gpo_error = str(e)
    finally:
        conn.unbind()
    return render_template('user_overview.html', user=user, gpos=gpos, gpo_error=gpo_error,
                           departures=ob.list_reports(user['sam'])[:5], connected=is_connected())


def _ous(conn):
    from routes.core import paged_search
    ous = [e.entry_dn for e in paged_search(conn, _base(), '(objectClass=organizationalUnit)',
                                            attributes=['name'])]
    return sorted(ous, key=str.lower)


@users_bp.route('/<path:dn>/offboard', methods=['GET', 'POST'])
@require_connection
@require_permission('users:offboard')
def offboard(dn):
    """Départ d'un collaborateur : aperçu (GET) puis exécution (POST)."""
    from core import exchange as ex
    from core.settings_manager import get_setting, set_setting
    dn = unquote(dn)
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur : {error}', 'error')
        return redirect(url_for('users.list_users'))
    try:
        info = ob.plan(conn, _base(), dn, session.get('ad_username', ''))
        if request.method == 'POST':
            steps = [s for s in ob.STEPS if request.form.get(f'step_{s}') == 'on']
            target = request.form.get('target_ou', '').strip()
            delegate = ''
            if 'mailbox' in steps and request.form.get('mailbox_delegate', '').strip():
                delegate = ex.user_address(conn, _base(), request.form.get('mailbox_delegate', ''))
            report = ob.execute(conn, _base(), dn, steps, session.get('ad_username', ''), target_ou=target,
                                can_set_password=bool(session.get('ad_use_ssl') or session.get('ad_starttls')),
                                mailbox_delegate=delegate)
            if 'move' in steps and target:
                set_setting('offboarding.ou', target)
            failed = [s['label'] for s in report['steps'] if not s['ok']]
            log_action('offboard_user', session.get('ad_username'),
                       {'dn': info['dn'], 'sam': info['sam'], 'steps': steps, 'failed': failed,
                        'report': report['id']}, not failed, request.remote_addr)
            flash(f'Départ de {info["name"]} traité'
                  + (f' — {len(failed)} étape(s) en échec.' if failed else '.'),
                  'warning' if failed else 'success')
            return redirect(url_for('users.offboard_report', report_id=report['id']))
        ous = _ous(conn)
    except (ob.OffboardingError, ex.ExchangeError) as e:
        flash(str(e), 'error')
        return redirect(url_for('users.overview', dn=dn))
    finally:
        conn.unbind()
    return render_template('offboard.html', info=info, steps=ob.STEPS, default_steps=ob.DEFAULT_STEPS,
                           ous=ous, default_ou=get_setting('offboarding.ou', '') or '',
                           m365=bool(ex.get_config()),
                           can_set_password=bool(session.get('ad_use_ssl') or session.get('ad_starttls')),
                           connected=is_connected())


@users_bp.route('/offboarding/<report_id>')
@require_connection
@require_permission('users:offboard')
def offboard_report(report_id):
    try:
        report = ob.load(report_id)
    except ob.OffboardingError as e:
        flash(str(e), 'error')
        return redirect(url_for('users.list_users'))
    return render_template('offboard_report.html', report=report, connected=is_connected())


@users_bp.route('/offboarding/<report_id>/undo', methods=['POST'])
@require_connection
@require_permission('users:offboard')
def offboard_undo(report_id):
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur : {error}', 'error')
        return redirect(url_for('users.list_users'))
    try:
        report = ob.undo(conn, _base(), report_id, session.get('ad_username', ''))
        failed = [r['label'] for r in report['undone']['results'] if not r['ok']]
        log_action('offboard_undo', session.get('ad_username'),
                   {'sam': report['sam'], 'report': report_id, 'failed': failed}, not failed,
                   request.remote_addr)
        flash(f'Départ de {report["name"]} annulé' + (' partiellement.' if failed else '.'),
              'warning' if failed else 'success')
    except ob.OffboardingError as e:
        flash(str(e), 'error')
    finally:
        conn.unbind()
    return redirect(url_for('users.offboard_report', report_id=report_id))
