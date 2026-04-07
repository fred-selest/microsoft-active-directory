"""
Notifications Email - Envoi de rapports d'audit par email
"""
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from config import get_config


def send_audit_email(audit_result, pdf_path=None, recipient=None):
    """
    Envoyer un rapport d'audit par email.
    
    Args:
        audit_result: Résultats de l'audit
        pdf_path: Chemin vers le fichier PDF à joindre (optionnel)
        recipient: Destinataire (défaut: EMAIL_TO du config)
    
    Returns:
        bool: True si envoyé avec succès, False sinon
    """
    config = get_config()
    
    # Vérifier si les emails sont activés
    if not getattr(config, 'EMAIL_ENABLED', False):
        return False
    
    # Récupérer la configuration SMTP
    smtp_server = getattr(config, 'SMTP_SERVER', None)
    smtp_port = getattr(config, 'SMTP_PORT', 587)
    smtp_username = getattr(config, 'SMTP_USERNAME', None)
    smtp_password = getattr(config, 'SMTP_PASSWORD', None)
    smtp_use_tls = getattr(config, 'SMTP_USE_TLS', True)
    smtp_from = getattr(config, 'SMTP_FROM', 'adweb@localhost')
    email_to = recipient or getattr(config, 'EMAIL_TO', None)
    
    # Vérifier la configuration
    if not smtp_server or not smtp_username or not smtp_password or not email_to:
        return False
    
    try:
        # Créer le message
        msg = MIMEMultipart()
        msg['From'] = smtp_from
        msg['To'] = email_to
        msg['Subject'] = f"[AD Audit] Rapport de sécurité - {datetime.now().strftime('%d/%m/%Y')}"
        
        # Corps du message
        score = audit_result.get('summary', {}).get('global_score', 0)
        score_color = audit_result.get('summary', {}).get('score_color', 'warning')
        total_issues = audit_result.get('summary', {}).get('total_issues', 0)
        critical_issues = audit_result.get('summary', {}).get('critical_issues', 0)
        
        # Déterminer l'urgence
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
Génééré automatiquement le """ + datetime.now().strftime('%d/%m/%Y à %H:%M')
        
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        # Attacher le PDF si fourni
        if pdf_path:
            try:
                with open(pdf_path, 'rb') as f:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename=audit_mdp_{datetime.now().strftime("%Y%m%d")}.pdf'
                    )
                    msg.attach(part)
            except Exception as e:
                print(f"Erreur attachment PDF: {e}")
        
        # Connexion et envoi
        if smtp_use_tls:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        
        return True
        
    except Exception as e:
        print(f"Erreur envoi email: {e}")
        return False


def send_alert_email(alert_type, alert_message, recipient=None):
    """
    Envoyer une alerte rapide par email.
    
    Args:
        alert_type: Type d'alerte (ex: "Comptes expirants", "Mots de passe faibles")
        alert_message: Message de l'alerte
        recipient: Destinataire (optionnel)
    
    Returns:
        bool: True si envoyé avec succès
    """
    config = get_config()
    
    if not getattr(config, 'EMAIL_ENABLED', False):
        return False
    
    smtp_server = getattr(config, 'SMTP_SERVER', None)
    smtp_port = getattr(config, 'SMTP_PORT', 587)
    smtp_username = getattr(config, 'SMTP_USERNAME', None)
    smtp_password = getattr(config, 'SMTP_PASSWORD', None)
    smtp_use_tls = getattr(config, 'SMTP_USE_TLS', True)
    smtp_from = getattr(config, 'SMTP_FROM', 'adweb@localhost')
    email_to = recipient or getattr(config, 'EMAIL_TO', None)
    
    if not smtp_server or not smtp_username or not smtp_password or not email_to:
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_from
        msg['To'] = email_to
        msg['Subject'] = f"[AD Alert] {alert_type}"
        
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
        
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        # Connexion et envoi
        if smtp_use_tls:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        
        return True
        
    except Exception as e:
        print(f"Erreur envoi alerte: {e}")
        return False


def test_email_config():
    """
    Tester la configuration email.
    
    Returns:
        dict: Résultat du test {'success': bool, 'error': str}
    """
    config = get_config()
    
    if not getattr(config, 'EMAIL_ENABLED', False):
        return {'success': False, 'error': 'Email non activé (EMAIL_ENABLED=false)'}
    
    smtp_server = getattr(config, 'SMTP_SERVER', None)
    smtp_username = getattr(config, 'SMTP_USERNAME', None)
    smtp_password = getattr(config, 'SMTP_PASSWORD', None)
    
    if not smtp_server:
        return {'success': False, 'error': 'SMTP_SERVER non configuré'}
    
    if not smtp_username:
        return {'success': False, 'error': 'SMTP_USERNAME non configuré'}
    
    if not smtp_password:
        return {'success': False, 'error': 'SMTP_PASSWORD non configuré'}
    
    try:
        # Tester la connexion
        smtp_use_tls = getattr(config, 'SMTP_USE_TLS', True)
        
        if smtp_use_tls:
            server = smtplib.SMTP(smtp_server, getattr(config, 'SMTP_PORT', 587))
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(smtp_server, getattr(config, 'SMTP_PORT', 465))
        
        server.login(smtp_username, smtp_password)
        server.quit()
        
        return {'success': True, 'error': None}
        
    except smtplib.SMTPAuthenticationError:
        return {'success': False, 'error': 'Échec authentification SMTP'}
    except smtplib.SMTPConnectError:
        return {'success': False, 'error': 'Échec connexion au serveur SMTP'}
    except Exception as e:
        return {'success': False, 'error': str(e)}
