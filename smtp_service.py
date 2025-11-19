"""
Module SMTP pour l'envoi d'emails (alertes, rapports).
"""

import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime

# Configuration SMTP depuis les variables d'environnement
SMTP_HOST = os.environ.get('SMTP_HOST', 'localhost')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 25))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
SMTP_FROM = os.environ.get('SMTP_FROM', 'ad-web@localhost')
SMTP_TLS = os.environ.get('SMTP_TLS', 'false').lower() == 'true'


def send_email(to, subject, body, html=False, attachments=None):
    """
    Envoyer un email.

    Args:
        to: Destinataire(s) (str ou liste)
        subject: Sujet
        body: Corps du message
        html: Si True, le corps est en HTML
        attachments: Liste de fichiers a joindre [(nom, contenu)]

    Returns:
        tuple: (succes, message)
    """
    try:
        # Creer le message
        msg = MIMEMultipart()
        msg['From'] = SMTP_FROM
        msg['To'] = to if isinstance(to, str) else ', '.join(to)
        msg['Subject'] = subject
        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')

        # Corps du message
        if html:
            msg.attach(MIMEText(body, 'html', 'utf-8'))
        else:
            msg.attach(MIMEText(body, 'plain', 'utf-8'))

        # Pieces jointes
        if attachments:
            for filename, content in attachments:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(content)
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
                msg.attach(part)

        # Connexion SMTP
        if SMTP_TLS:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.starttls()
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)

        # Authentification si necessaire
        if SMTP_USER and SMTP_PASSWORD:
            server.login(SMTP_USER, SMTP_PASSWORD)

        # Envoi
        recipients = [to] if isinstance(to, str) else to
        server.sendmail(SMTP_FROM, recipients, msg.as_string())
        server.quit()

        return True, 'Email envoye avec succes'

    except Exception as e:
        return False, str(e)


def send_alert_email(to, alert_type, title, message, severity='warning'):
    """
    Envoyer une alerte par email.

    Args:
        to: Destinataire(s)
        alert_type: Type d'alerte
        title: Titre
        message: Message
        severity: Niveau de gravite
    """
    subject = f"[AD Web] Alerte {severity.upper()}: {title}"

    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif;">
        <h2 style="color: {'#d32f2f' if severity == 'critical' else '#ff9800'};">
            Alerte: {title}
        </h2>
        <p><strong>Type:</strong> {alert_type}</p>
        <p><strong>Gravite:</strong> {severity}</p>
        <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <hr>
        <p>{message}</p>
        <hr>
        <p style="font-size: 12px; color: #666;">
            Cet email a ete envoye automatiquement par AD Web Interface.
        </p>
    </body>
    </html>
    """

    return send_email(to, subject, body, html=True)


def send_report_email(to, report_name, report_content, format='pdf'):
    """
    Envoyer un rapport par email.

    Args:
        to: Destinataire(s)
        report_name: Nom du rapport
        report_content: Contenu du rapport (bytes)
        format: Format du fichier (pdf, csv, xlsx)
    """
    subject = f"[AD Web] Rapport: {report_name}"

    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif;">
        <h2>Rapport: {report_name}</h2>
        <p>Veuillez trouver ci-joint le rapport demande.</p>
        <p><strong>Date de generation:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <hr>
        <p style="font-size: 12px; color: #666;">
            Cet email a ete envoye automatiquement par AD Web Interface.
        </p>
    </body>
    </html>
    """

    filename = f"{report_name}_{datetime.now().strftime('%Y%m%d')}.{format}"
    attachments = [(filename, report_content)]

    return send_email(to, subject, body, html=True, attachments=attachments)


def test_smtp_connection():
    """Tester la connexion SMTP."""
    try:
        if SMTP_TLS:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.starttls()
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)

        if SMTP_USER and SMTP_PASSWORD:
            server.login(SMTP_USER, SMTP_PASSWORD)

        server.quit()
        return True, 'Connexion SMTP reussie'

    except Exception as e:
        return False, str(e)


def get_smtp_config():
    """Obtenir la configuration SMTP actuelle."""
    return {
        'host': SMTP_HOST,
        'port': SMTP_PORT,
        'user': SMTP_USER,
        'from': SMTP_FROM,
        'tls': SMTP_TLS,
        'configured': bool(SMTP_HOST and SMTP_HOST != 'localhost')
    }
