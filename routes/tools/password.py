# -*- coding: utf-8 -*-
"""Routes politique de mots de passe et audit."""
from flask import render_template, redirect, url_for, flash, session, Response, request, jsonify

from . import tools_bp
from ..core import get_ad_connection, is_connected, require_connection, require_permission


def _clean_ldap_string(s):
    """Nettoyer une chaîne LDAP (encodage UTF-8)."""
    if s is None:
        return ''
    if isinstance(s, bytes):
        return s.decode('utf-8', errors='replace')
    return str(s)


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
        return redirect(url_for('main.connect'))

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
    from core.password_audit import run_password_audit, export_audit_to_csv
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.password_audit'))

    base_dn = session.get('ad_base_dn', '')
    try:
        audit_result = run_password_audit(conn, base_dn, max_age_days=90)
    finally:
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
    from core.password_audit import run_password_audit, export_audit_to_json
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.password_audit'))

    base_dn = session.get('ad_base_dn', '')
    try:
        audit_result = run_password_audit(conn, base_dn, max_age_days=90)
    finally:
        conn.unbind()
    return Response(
        export_audit_to_json(audit_result),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=password_audit.json'}
    )


@tools_bp.route('/password-audit/export/pdf')
@require_connection
@require_permission('admin')
def export_password_audit_pdf():
    """Exporter l'audit des mots de passe en PDF professionnel."""
    from core.password_audit import run_password_audit
    from core.audit_history import save_audit
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, inch
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
        PageBreak, Image
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from io import BytesIO
    from datetime import datetime
    
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.password_audit'))

    base_dn = session.get('ad_base_dn', '')
    domain_name = session.get('ad_domain', 'Domaine AD')
    try:
        audit_result = run_password_audit(conn, base_dn, max_age_days=90)
        # Sauvegarder dans l'historique
        save_audit(audit_result, domain_name)
    finally:
        conn.unbind()
    
    # Créer le PDF (code inchangé...)
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=1.5*cm,
        leftMargin=1.5*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
        title="Audit Mots de Passe AD"
    )
    
    elements = []
    styles = getSampleStyleSheet()
    
    # Styles personnalisés
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#0078d4'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#666666'),
        spaceAfter=20,
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#0078d4'),
        spaceAfter=12,
        spaceBefore=12
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#333333'),
        spaceAfter=6
    )
    
    # En-tête
    elements.append(Paragraph("Audit de Securite des Mots de Passe", title_style))
    elements.append(Paragraph(f"Domaine: {domain_name}", subtitle_style))
    elements.append(Paragraph(
        f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}",
        ParagraphStyle('Date', parent=normal_style, alignment=TA_RIGHT, fontSize=9)
    ))
    elements.append(Spacer(1, 0.5*cm))
    
    # Score Global
    score = audit_result.get('summary', {}).get('global_score', 0)
    score_color = audit_result.get('summary', {}).get('score_color', 'warning')
    
    score_label = {
        'success': 'Excellent',
        'info': 'Acceptable',
        'warning': 'À améliorer',
        'danger': 'Critique'
    }.get(score_color, 'Inconnu')
    
    elements.append(Paragraph("Score Global de Securite", heading_style))
    
    score_table = Table([[
        f"Score: {round(score)}/100",
        f"Niveau: {score_label}",
        f"Problèmes: {audit_result.get('summary', {}).get('total_issues', 0)}"
    ]], colWidths=[6*cm, 6*cm, 6*cm])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0078d4')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#0078d4')),
    ]))
    elements.append(score_table)
    elements.append(Spacer(1, 0.5*cm))
    
    # Statistiques détaillées
    elements.append(Paragraph("Statistiques Detaillees", heading_style))
    
    stats_data = [
        ['Indicateur', 'Valeur'],
        ['Comptes audités', str(audit_result.get('summary', {}).get('accounts_audited', 0))],
        ['Problèmes critiques', str(audit_result.get('summary', {}).get('critical_issues', 0))],
        ['Avertissements', str(audit_result.get('summary', {}).get('warning_issues', 0))],
        ['Total problèmes', str(audit_result.get('summary', {}).get('total_issues', 0))],
    ]
    
    stats_table = Table(stats_data, colWidths=[10*cm, 6*cm])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#005a9e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f6fa')]),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 0.5*cm))
    
    # Politique de mot de passe
    policy = audit_result.get('policy', {})
    if policy:
        elements.append(Paragraph("Politique de Mot de Passe", heading_style))
        
        policy_data = [
            ['Paramètre', 'Valeur'],
            ['Longueur minimale', str(policy.get('minPasswordLength', 'N/A'))],
            ['Historique', str(policy.get('passwordHistoryLength', 'N/A'))],
            ['Âge maximum (jours)', str(policy.get('maxPasswordAge', 'Illimité'))],
            ['Seuil de verrouillage', str(policy.get('lockoutThreshold', 'N/A'))],
        ]
        
        policy_table = Table(policy_data, colWidths=[10*cm, 6*cm])
        policy_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0078d4')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f6fa')]),
        ]))
        elements.append(policy_table)
        elements.append(Spacer(1, 0.5*cm))
    
    # Recommandations
    recommendations = audit_result.get('recommendations', [])
    if recommendations:
        elements.append(Paragraph("Recommandations de Securite", heading_style))
        
        for i, rec in enumerate(recommendations[:10], 1):  # Limiter à 10
            rec_style = ParagraphStyle(
                f'Rec{i}',
                parent=normal_style,
                leftIndent=0.5*cm,
                spaceAfter=8
            )
            
            priority = rec.get('priority', 'info').upper()
            issue = rec.get('issue', 'N/A')
            recommendation = rec.get('recommendation', 'N/A')
            
            elements.append(Paragraph(
                f"<b>{i}. [{priority}] {issue}</b>",
                rec_style
            ))
            elements.append(Paragraph(
                f"   → {recommendation}",
                ParagraphStyle(f'RecDetail{i}', parent=normal_style, leftIndent=1*cm, fontSize=9)
            ))
        
        if len(recommendations) > 10:
            elements.append(Paragraph(
                f"<i>... et {len(recommendations) - 10} autres recommandations (voir export JSON complet)</i>",
                normal_style
            ))
        
        elements.append(Spacer(1, 0.5*cm))
    
    # Pied de page
    elements.append(Spacer(1, 1*cm))
    elements.append(Paragraph(
        "Document généré automatiquement par AD Web Interface - Confidentialité requise",
        ParagraphStyle('Footer', parent=normal_style, alignment=TA_CENTER, fontSize=8, textColor=colors.HexColor('#999999'))
    ))
    
    # Générer le PDF
    doc.build(elements)
    
    buffer.seek(0)
    
    import re
    safe_domain = re.sub(r'[^\w._-]', '_', domain_name)
    safe_filename = f'audit_mdp_{safe_domain}_{datetime.now().strftime("%Y%m%d")}.pdf'

    return Response(
        buffer.getvalue(),
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'attachment;filename={safe_filename}'
        }
    )


@tools_bp.route('/password-audit/report')
@require_connection
@require_permission('admin')
def password_auditor_report():
    """Générer un rapport style Specops Password Auditor."""
    from core.password_audit import run_password_audit, generate_auditor_issues
    from datetime import datetime
    from core.updater import get_current_version

    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('tools.password_audit'))

    base_dn = session.get('ad_base_dn', '')
    domain = base_dn.replace('DC=', '').replace(',', '.').strip('.') if base_dn else session.get('ad_server', 'domaine.local')

    # Lancer l'audit complet
    audit_result = run_password_audit(conn, base_dn, max_age_days=90)
    conn.unbind()

    # Générer les issues formatées style Specops
    issues = generate_auditor_issues(audit_result)

    # Calculer le score (0-100)
    total_issues = sum(issue['weight'] for issue in issues)
    max_score = 100
    score = max(0, max_score - total_issues)

    # Déterminer la classe CSS pour le score
    if score >= 80:
        score_class = 'success'
    elif score >= 50:
        score_class = 'warning'
    else:
        score_class = 'critical'

    version = get_current_version()

    return render_template('password_auditor_report.html',
                         domain=domain,
                         base_dn=base_dn,
                         issues=issues,
                         score=score,
                         score_class=score_class,
                         now=datetime.now(),
                         version=version,
                         connected=is_connected())


# === HISTORIQUE DES AUDITS ===

@tools_bp.route('/password-audit/history')
@require_connection
@require_permission('admin')
def password_audit_history():
    """Page d'historique des audits."""
    from core.audit_history import get_audit_history, get_history_stats
    
    audits = get_audit_history(limit=50)
    stats = get_history_stats()
    
    return render_template('password_audit_history.html',
                         audits=audits,
                         stats=stats,
                         connected=is_connected())


@tools_bp.route('/api/password-audit/history')
@require_connection
@require_permission('admin')
def api_password_audit_history():
    """API - Historique des audits."""
    from core.audit_history import get_audit_history, get_audit_evolution, get_history_stats
    
    limit = request.args.get('limit', 20, type=int)
    days = request.args.get('days', 90, type=int)
    
    return jsonify({
        'audits': get_audit_history(limit=limit),
        'evolution': get_audit_evolution(days=days),
        'stats': get_history_stats()
    })


@tools_bp.route('/api/password-audit/compare')
@require_connection
@require_permission('admin')
def api_password_audit_compare():
    """API - Comparer deux audits."""
    from core.audit_history import compare_audits
    
    audit_id_1 = request.args.get('audit_1', '')
    audit_id_2 = request.args.get('audit_2', '')
    
    if not audit_id_1 or not audit_id_2:
        return jsonify({'error': 'IDs requis'}), 400
    
    return jsonify(compare_audits(audit_id_1, audit_id_2))


@tools_bp.route('/password-audit/history/<audit_id>/delete', methods=['POST'])
@require_connection
@require_permission('admin')
def delete_audit_history(audit_id):
    """Supprimer un audit de l'historique."""
    from core.audit_history import delete_audit
    
    if delete_audit(audit_id):
        flash('Audit supprimé avec succès', 'success')
    else:
        flash('Erreur lors de la suppression', 'error')
    
    return redirect(url_for('tools.password_audit_history'))


# === ENVOI EMAIL ===

@tools_bp.route('/password-audit/send-email', methods=['POST'])
@require_connection
@require_permission('admin')
def send_audit_email_route():
    """Envoyer le dernier audit par email."""
    from core.email_notifications import send_audit_email
    from core.audit_history import get_audit_history
    import os
    from pathlib import Path
    
    # Récupérer le dernier audit
    audits = get_audit_history(limit=1)
    if not audits:
        flash("Aucun audit dans l'historique. Lancez d'abord un audit.", 'error')
        return redirect(url_for('tools.password_audit_history'))
    
    # Reconstruire un objet audit_result minimal pour l'email
    audit = audits[0]
    audit_result = {
        'summary': {
            'global_score': audit.get('score', 0),
            'score_color': audit.get('score_color', 'warning'),
            'total_issues': audit.get('total_issues', 0),
            'critical_issues': audit.get('critical_issues', 0),
            'warning_issues': audit.get('warning_issues', 0),
            'accounts_audited': audit.get('accounts_audited', 0),
        },
        'policy': {},
        'recommendations': []
    }
    
    # Chercher le dernier PDF généré
    pdf_path = None
    downloads_dir = Path('downloads')
    if downloads_dir.exists():
        pdfs = list(downloads_dir.glob('audit_mdp_*.pdf'))
        if pdfs:
            pdf_path = str(pdfs[-1])
    
    # Envoyer l'email
    recipient = request.form.get('email_to', None)
    
    if send_audit_email(audit_result, pdf_path=pdf_path, recipient=recipient):
        flash('Rapport envoyé avec succès par email', 'success')
    else:
        flash('Échec de l\'envoi. Vérifiez la configuration SMTP dans .env', 'error')
    
    return redirect(url_for('tools.password_audit_history'))


@tools_bp.route('/api/password-audit/test-email', methods=['POST'])
@require_connection
@require_permission('admin')
def test_email_config_route():
    """Tester la configuration email."""
    from core.email_notifications import test_email_config
    
    result = test_email_config()
    
    if result['success']:
        return jsonify({'success': True, 'message': 'Configuration email valide'})
    else:
        return jsonify({'success': False, 'message': result['error']}), 400


@tools_bp.route('/api/password-audit/alerts-summary')
@require_connection
@require_permission('admin')
def api_password_audit_alerts_summary():
    """API - Résumé des alertes critiques."""
    from core.auto_alerts import get_alert_summary
    from core.audit_history import get_audit_history
    
    # Récupérer le dernier audit
    audits = get_audit_history(limit=1)
    
    if not audits:
        return jsonify({
            'total': 0,
            'critical': 0,
            'high': 0,
            'alerts': [],
            'message': 'Aucun audit dans l\'historique'
        })
    
    # Reconstruire un objet audit_result minimal
    audit = audits[0]
    audit_result = {
        'summary': {
            'global_score': audit.get('score', 0),
            'critical_issues': audit.get('critical_issues', 0),
            'warning_issues': audit.get('warning_issues', 0),
        },
        'admin_weak_accounts': [],
        'service_accounts': [],
        'legacy_protocols': [],
        'policy': {}
    }
    
    summary = get_alert_summary(audit_result)
    return jsonify(summary)
