"""
Notifications e-mail : rapports d'audit et alertes.

L'envoi passe par core/mailer.py, qui lit la configuration de la page
Admin › SMTP (auparavant ignorée : ces fonctions cherchaient des réglages
SMTP_* absents de config.py et ne partaient jamais).
"""
import logging
from datetime import datetime

from core.mailer import MailError, default_recipient, get_smtp_settings, is_configured, send_mail

logger = logging.getLogger('email_notifications')


def send_audit_email(audit_result, pdf_path=None, recipient=None):
    """
    Envoyer un rapport d'audit par email.

    Args:
        audit_result: Résultats de l'audit
        pdf_path: Chemin vers le fichier PDF à joindre (optionnel)
        recipient: Destinataire (défaut : destinataire des alertes)

    Returns:
        bool: True si envoyé avec succès, False sinon
    """
    smtp = get_smtp_settings()
    email_to = recipient or default_recipient(smtp)
    if not is_configured(smtp) or not email_to:
        return False
    try:
        score = audit_result.get('summary', {}).get('global_score', 0)
        total_issues = audit_result.get('summary', {}).get('total_issues', 0)
        critical_issues = audit_result.get('summary', {}).get('critical_issues', 0)
        urgency = "🔴 CRITIQUE" if critical_issues > 0 else "🟠 ATTENTION" if total_issues > 0 else "🟢 RAS"

        body = f"""
Bonjour,

Voici le rapport d'audit de sécurité des mots de passe Active Directory.

📊 RÉSUMÉ
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{urgency} - Score de sécurité: {round(score)}/100

• Problèmes critiques: {critical_issues}
• Avertissements: {audit_result.get('summary', {}).get('warning_issues', 0)}
• Total problèmes: {total_issues}
• Comptes audités: {audit_result.get('summary', {}).get('accounts_audited', 0)}

📋 POLITIQUE DE MOT DE PASSE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

• Longueur minimale: {audit_result.get('policy', {}).get('minPasswordLength', 'N/A')} caractères
• Historique: {audit_result.get('policy', {}).get('passwordHistoryLength', 'N/A')} mots de passe
• Âge maximum: {audit_result.get('policy', {}).get('maxPasswordAge', 'Illimité')} jours

💡 TOP 5 DES RECOMMANDATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"""
        
        # Ajouter les recommandations (top 5)
        recommendations = audit_result.get('recommendations', [])[:5]
        for i, rec in enumerate(recommendations, 1):
            priority = rec.get('priority', 'info').upper()
            issue = rec.get('issue', 'N/A')
            body += f"{i}. [{priority}] {issue}\n"
            body += f"   → {rec.get('recommendation', 'N/A')}\n\n"
        
        if not recommendations:
            body += "Aucune recommandation - Bonne configuration !\n\n"
        
        body += """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📎 Pièce jointe: Rapport PDF complet

Cordialement,
AD Web Interface
Généré automatiquement le """ + datetime.now().strftime('%d/%m/%Y à %H:%M')
        
        attachments = []
        if pdf_path:
            try:
                with open(pdf_path, 'rb') as f:
                    attachments.append((f'audit_mdp_{datetime.now().strftime("%Y%m%d")}.pdf',
                                        f.read(), 'application/pdf'))
            except OSError as e:
                logger.warning('Pièce jointe illisible : %s', e)
        send_mail(email_to, f"[AD Audit] Rapport de sécurité - {datetime.now().strftime('%d/%m/%Y')}",
                  body, attachments=attachments, smtp=smtp)
        return True
    except MailError as e:
        logger.warning('Rapport d\'audit non envoyé : %s', e)
        return False


def send_alert_email(alert_type, alert_message, recipient=None):
    """
    Envoyer une alerte rapide par email.

    Returns:
        bool: True si envoyé avec succès
    """
    smtp = get_smtp_settings()
    email_to = recipient or default_recipient(smtp)
    if not is_configured(smtp) or not email_to:
        return False
    try:
        body = f"""
Bonjour,

🚨 ALERTE DE SÉCURITÉ

Type: {alert_type}
Date: {datetime.now().strftime('%d/%m/%Y à %H:%M')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{alert_message}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Cordialement,
AD Web Interface
"""
        
        send_mail(email_to, f"[AD Alert] {alert_type}", body, smtp=smtp)
        return True
    except MailError as e:
        logger.warning('Alerte non envoyée : %s', e)
        return False



def test_email_config():
    """
    Tester la configuration email (connexion et authentification).

    Returns:
        dict: {'success': bool, 'error': str}
    """
    import smtplib
    smtp = get_smtp_settings()
    if not is_configured(smtp):
        return {'success': False, 'error': 'Envoi d\'e-mails non configuré (Admin › SMTP).'}
    try:
        if smtp['port'] == 465:
            server = smtplib.SMTP_SSL(smtp['server'], smtp['port'], timeout=20)
        else:
            server = smtplib.SMTP(smtp['server'], smtp['port'], timeout=20)
            if smtp.get('use_tls'):
                server.starttls()
        if smtp.get('use_auth') and smtp.get('username'):
            server.login(smtp['username'], smtp.get('password') or '')
        server.quit()
        return {'success': True, 'error': None}
    except smtplib.SMTPAuthenticationError:
        return {'success': False, 'error': 'Échec authentification SMTP'}
    except (smtplib.SMTPException, OSError) as e:
        return {'success': False, 'error': f'Connexion au serveur SMTP impossible : {e}'}
