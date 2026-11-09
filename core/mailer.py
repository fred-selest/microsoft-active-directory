"""
Envoi d'e-mails : un seul point d'entrée pour toute l'application.

La configuration est celle de la page Admin › SMTP (settings.json, section
« smtp »). Les variables d'environnement SMTP_* ne servent que de repli,
pour les installations configurées par .env.

Auparavant, la page Admin enregistrait la configuration dans settings.json
mais les fonctions d'envoi (rapports d'audit, alertes) la cherchaient dans
des attributs SMTP_* absents de config.py : aucun e-mail ne partait jamais,
quelle que soit la configuration saisie.
"""
import logging
import os
import smtplib
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

logger = logging.getLogger('mailer')

SMTP_TIMEOUT = 20


class MailError(Exception):
    """Erreur d'envoi présentable à l'utilisateur."""


def get_smtp_settings():
    """Configuration SMTP effective (page Admin, sinon variables d'environnement)."""
    from core.settings_manager import load_settings
    smtp = dict(load_settings().get('smtp') or {})
    if not smtp.get('server') and os.environ.get('SMTP_SERVER'):
        smtp = {
            'enabled': os.environ.get('EMAIL_ENABLED', 'true').lower() == 'true',
            'server': os.environ.get('SMTP_SERVER', ''),
            'port': os.environ.get('SMTP_PORT', 587),
            'use_tls': os.environ.get('SMTP_USE_TLS', 'true').lower() == 'true',
            'use_auth': bool(os.environ.get('SMTP_USERNAME')),
            'username': os.environ.get('SMTP_USERNAME', ''),
            'password': os.environ.get('SMTP_PASSWORD', ''),
            'from_email': os.environ.get('SMTP_FROM', ''),
            'from_name': 'AD Web Interface',
            'alert_recipient': os.environ.get('EMAIL_TO', ''),
        }
    try:
        smtp['port'] = int(smtp.get('port') or 587)
    except (TypeError, ValueError):
        smtp['port'] = 587
    return smtp


def is_configured(smtp=None):
    smtp = smtp or get_smtp_settings()
    return bool(smtp.get('enabled') and smtp.get('server') and smtp.get('from_email'))


def default_recipient(smtp=None):
    """Destinataire des alertes et rapports : réglage dédié, sinon l'expéditeur."""
    smtp = smtp or get_smtp_settings()
    return (smtp.get('alert_recipient') or os.environ.get('EMAIL_TO') or
            smtp.get('from_email') or '')


def send_mail(to, subject, text, html=None, attachments=(), smtp=None):
    """
    Envoie un e-mail.

    Args:
        to: adresse ou liste d'adresses
        attachments: [(nom, octets, type MIME 'application/pdf')]

    Raises:
        MailError avec un message en français.
    """
    smtp = smtp or get_smtp_settings()
    if not is_configured(smtp):
        raise MailError('L\'envoi d\'e-mails n\'est pas configuré (Admin › SMTP).')
    recipients = [to] if isinstance(to, str) else list(to)
    recipients = [r.strip() for r in recipients if r and r.strip()]
    if not recipients:
        raise MailError('Aucun destinataire.')
    for addr in recipients:
        if '\n' in addr or '\r' in addr or '@' not in addr:
            raise MailError(f'Adresse invalide : {addr!r}')

    msg = EmailMessage()
    msg['From'] = formataddr((smtp.get('from_name') or 'AD Web Interface', smtp['from_email']))
    msg['To'] = ', '.join(recipients)
    msg['Subject'] = subject.replace('\n', ' ').replace('\r', ' ')
    msg['Message-ID'] = make_msgid(domain=smtp['from_email'].split('@')[-1])
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype='html')
    for name, data, mime in attachments:
        maintype, _, subtype = (mime or 'application/octet-stream').partition('/')
        msg.add_attachment(data, maintype=maintype, subtype=subtype or 'octet-stream', filename=name)

    port = smtp['port']
    try:
        if port == 465:
            server = smtplib.SMTP_SSL(smtp['server'], port, timeout=SMTP_TIMEOUT)
        else:
            server = smtplib.SMTP(smtp['server'], port, timeout=SMTP_TIMEOUT)
        try:
            if port != 465 and smtp.get('use_tls'):
                server.starttls()
            if smtp.get('use_auth') and smtp.get('username'):
                server.login(smtp['username'], smtp.get('password') or '')
            server.send_message(msg)
        finally:
            try:
                server.quit()
            except Exception:
                pass
    except smtplib.SMTPAuthenticationError:
        raise MailError('Authentification SMTP refusée : vérifiez le compte et le mot de passe.')
    except smtplib.SMTPRecipientsRefused:
        raise MailError(f'Destinataire refusé par le serveur : {", ".join(recipients)}')
    except (smtplib.SMTPException, OSError) as e:
        logger.warning('Envoi SMTP impossible : %s', e)
        raise MailError(f'Envoi impossible ({smtp["server"]}:{port}) : {e}')
    logger.info('E-mail envoyé à %s : %s', ', '.join(recipients), subject)
