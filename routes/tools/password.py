"""Routes politique de mots de passe et audit."""
from flask import render_template, redirect, url_for, flash, session, Response

from . import tools_bp
from ..core import get_ad_connection, is_connected, require_connection, require_permission


def _get_filetime_days(entry, attr):
    """Convertit un FILETIME AD en jours (None si non défini)."""
    val = getattr(entry, attr, None)
    if val is None or val.value is None:
        return None
    v = val.value
    if hasattr(v, 'days'):
        return abs(int(v.total_seconds() / 86400))
    return abs(int(v / -864000000000)) if v != 0 else None


def _get_filetime_minutes(entry, attr):
    """Convertit un FILETIME AD en minutes (None si non défini)."""
    val = getattr(entry, attr, None)
    if val is None or val.value is None:
        return None
    v = val.value
    if hasattr(v, 'days'):
        return abs(int(v.total_seconds() / 60))
    return abs(int(v / -600000000)) if v != 0 else None


def _format_duration(val, is_days=True):
    if not val:
        return "Non défini"
    if is_days:
        return f"{val} jours"
    if val < 60:
        return f"{val} minutes"
    if val < 1440:
        return f"{val // 60} heures"
    return f"{val // 1440} jours"


# === POLITIQUE DE MOTS DE PASSE ===

@tools_bp.route('/password-policy')
@require_connection
def password_policy():
    """Afficher la politique de mots de passe du domaine."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('connect'))

    base_dn = session.get('ad_base_dn', '')
    policy = None

    try:
        conn.search(base_dn, '(objectClass=domain)', 'BASE',
                    attributes=['minPwdLength', 'pwdHistoryLength', 'maxPwdAge',
                                'minPwdAge', 'lockoutThreshold', 'lockoutDuration',
                                'lockoutObservationWindow', 'pwdProperties', 'name'])

        if not conn.entries:
            flash('Aucune politique de domaine trouvée.', 'warning')
            return render_template('password_policy.html', policy=None, connected=is_connected())

        entry = conn.entries[0]

        def int_val(attr, default=0):
            v = getattr(entry, attr, None)
            if v is None or v.value is None:
                return default
            val = v.value
            return int(val.total_seconds()) if hasattr(val, 'days') else (int(val) if val is not None else default)

        policy = {
            'domain_name': str(entry.name) if hasattr(entry, 'name') else 'Domaine',
            'minPwdLength': int_val('minPwdLength'),
            'pwdHistoryLength': int_val('pwdHistoryLength'),
            'maxPwdAge': _get_filetime_days(entry, 'maxPwdAge'),
            'minPwdAge': _get_filetime_days(entry, 'minPwdAge'),
            'lockoutThreshold': int_val('lockoutThreshold'),
            'lockoutDuration': _get_filetime_minutes(entry, 'lockoutDuration'),
            'lockoutObservationWindow': _get_filetime_minutes(entry, 'lockoutObservationWindow'),
            'pwdProperties': int_val('pwdProperties'),
        }

        policy['maxPwdAge_display'] = _format_duration(policy['maxPwdAge'], is_days=True)
        policy['minPwdAge_display'] = _format_duration(policy['minPwdAge'], is_days=True)
        policy['lockoutDuration_display'] = _format_duration(policy['lockoutDuration'], is_days=False)
        policy['lockoutObservationWindow_display'] = _format_duration(policy['lockoutObservationWindow'], is_days=False)
        policy['complexity_enabled'] = bool(policy['pwdProperties'] & 1)
        policy['reversible_encryption'] = bool(policy['pwdProperties'] & 16)

        conn.unbind()
    except Exception as e:
        flash(f'Erreur lors de la récupération: {e}', 'error')

    return render_template('password_policy.html', policy=policy, connected=is_connected())


# === AUDIT DE MOTS DE PASSE ===

@tools_bp.route('/password-audit')
@require_connection
@require_permission('admin')
def password_audit():
    """Page d'audit des mots de passe."""
    return render_template('password_audit.html', connected=is_connected())


@tools_bp.route('/password-audit/export/csv')
@require_connection
@require_permission('admin')
def export_password_audit_csv():
    """Exporter l'audit des mots de passe en CSV."""
    from password_audit import run_password_audit, export_audit_to_csv
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.password_audit'))

    base_dn = session.get('ad_base_dn', '')
    audit_result = run_password_audit(conn, base_dn, max_age_days=90)
    conn.unbind()
    return Response(
        export_audit_to_csv(audit_result),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=password_audit.csv'}
    )


@tools_bp.route('/password-audit/export/json')
@require_connection
@require_permission('admin')
def export_password_audit_json():
    """Exporter l'audit des mots de passe en JSON."""
    from password_audit import run_password_audit, export_audit_to_json
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.password_audit'))

    base_dn = session.get('ad_base_dn', '')
    audit_result = run_password_audit(conn, base_dn, max_age_days=90)
    conn.unbind()
    return Response(
        export_audit_to_json(audit_result),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=password_audit.json'}
    )
