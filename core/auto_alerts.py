"""
Alertes Automatiques - Détection et notification des problèmes critiques
"""
from datetime import datetime, timedelta
from core.email_notifications import send_alert_email
from config import get_config


def check_critical_issues(audit_result):
    """
    Vérifier les problèmes critiques dans un audit.
    
    Args:
        audit_result: Résultats de l'audit
    
    Returns:
        list: Liste des alertes critiques détectées
    """
    alerts = []
    
    score = audit_result.get('summary', {}).get('global_score', 0)
    critical_issues = audit_result.get('summary', {}).get('critical_issues', 0)
    
    # Alerte 1: Score très bas
    if score < 40:
        alerts.append({
            'type': 'critical_score',
            'title': 'Score de sécurité critique',
            'message': f'Le score de sécurité est de {round(score)}/100. Des actions immédiates sont requises.',
            'severity': 'critical',
            'priority': 1
        })
    
    # Alerte 2: Comptes admins avec MDP faible
    admin_weak = [a for a in audit_result.get('admin_weak_accounts', []) 
                  if a.get('severity') == 'critical' and a.get('type') != 'admin_ok']
    
    if admin_weak:
        accounts_list = ', '.join([a.get('username', 'N/A') for a in admin_weak[:5]])
        alerts.append({
            'type': 'admin_weak_password',
            'title': f'{len(admin_weak)} compte(s) administrateur à risque',
            'message': f'Comptes concernés: {accounts_list}. Ces comptes ont des privilèges élevés et des configurations de mot de passe faibles.',
            'severity': 'critical',
            'priority': 1,
            'accounts': admin_weak
        })
    
    # Alerte 3: Comptes de service avec MDP n'expirant jamais
    service_never_expire = [s for s in audit_result.get('service_accounts', [])
                            if s.get('type') == 'service_password_never_expires']
    
    if service_never_expire:
        accounts_list = ', '.join([s.get('username', 'N/A') for s in service_never_expire[:5]])
        alerts.append({
            'type': 'service_password_never_expires',
            'title': f'{len(service_never_expire)} compte(s) de service avec MDP n\'expirant jamais',
            'message': f'Comptes concernés: {accounts_list}. Les comptes de service devraient avoir des MDP qui expirent ou utiliser des MSA.',
            'severity': 'high',
            'priority': 2,
            'accounts': service_never_expire
        })
    
    # Alerte 4: Protocoles obsolètes critiques
    legacy_protocols = audit_result.get('legacy_protocols', [])
    critical_protocols = [p for p in legacy_protocols if p.get('severity') == 'critical']
    
    if critical_protocols:
        protocols_list = ', '.join([p.get('item', 'N/A') for p in critical_protocols])
        alerts.append({
            'type': 'critical_legacy_protocols',
            'title': 'Protocoles obsolètes critiques détectés',
            'message': f'Protocoles concernés: {protocols_list}. Ces protocoles présentent des failles de sécurité connues.',
            'severity': 'critical',
            'priority': 1
        })
    
    # Alerte 5: Stockage réversible activé
    policy = audit_result.get('policy', {})
    if policy.get('reversible_encryption'):
        alerts.append({
            'type': 'reversible_encryption',
            'title': 'Stockage réversible des mots de passe activé',
            'message': 'Le stockage réversible des mots de passe est activé dans la politique du domaine. Cela permet de récupérer les MDP en clair.',
            'severity': 'critical',
            'priority': 1
        })
    
    # Trier par priorité
    alerts.sort(key=lambda x: x.get('priority', 99))
    
    return alerts


def send_critical_alerts(audit_result, recipient=None):
    """
    Envoyer les alertes critiques par email.
    
    Args:
        audit_result: Résultats de l'audit
        recipient: Destinataire (optionnel)
    
    Returns:
        dict: Résumé des alertes envoyées
    """
    config = get_config()
    
    # Vérifier si les emails sont activés
    if not getattr(config, 'EMAIL_ENABLED', False):
        return {'success': False, 'reason': 'Email non activé'}
    
    # Vérifier les problèmes critiques
    alerts = check_critical_issues(audit_result)
    
    if not alerts:
        return {'success': True, 'reason': 'Aucune alerte critique', 'alerts_count': 0}
    
    # Envoyer chaque alerte
    sent_count = 0
    failed_count = 0
    
    for alert in alerts:
        # Seulement les alertes critiques et high priority
        if alert.get('severity') not in ['critical', 'high']:
            continue
        
        subject = f"[AD Alert - {alert['severity'].upper()}] {alert['title']}"
        message = format_alert_message(alert, audit_result)
        
        if send_alert_email(subject, message, recipient):
            sent_count += 1
        else:
            failed_count += 1
    
    return {
        'success': sent_count > 0,
        'alerts_count': len(alerts),
        'sent': sent_count,
        'failed': failed_count
    }


def format_alert_message(alert, audit_result):
    """
    Formater le message d'une alerte.
    
    Args:
        alert: Données de l'alerte
        audit_result: Résultats complets de l'audit
    
    Returns:
        str: Message formaté
    """
    score = audit_result.get('summary', {}).get('global_score', 0)
    
    message = f"""
Bonjour,

🚨 ALERTE DE SÉCURITÉ CRITIQUE DÉTECTÉE

Type: {alert.get('type', 'Inconnu')}
Sévérité: {alert.get('severity', 'N/A').upper()}
Date: {datetime.now().strftime('%d/%m/%Y à %H:%M')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 CONTEXTE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Score de sécurité actuel: {round(score)}/100
Problèmes critiques: {audit_result.get('summary', {}).get('critical_issues', 0)}
Avertissements: {audit_result.get('summary', {}).get('warning_issues', 0)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️ PROBLÈME DÉTECTÉ
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{alert.get('title', 'N/A')}

{alert.get('message', 'N/A')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💡 ACTIONS RECOMMANDÉES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"""
    
    # Ajouter des recommandations spécifiques selon le type d'alerte
    alert_type = alert.get('type', '')
    
    if alert_type == 'critical_score':
        message += """
1. Examiner immédiatement les comptes avec mots de passe faibles
2. Activer l'expiration des mots de passe pour tous les comptes
3. Renforcer la politique de mot de passe du domaine
4. Envisager l'activation de MFA pour les comptes privilégiés
"""
    
    elif alert_type == 'admin_weak_password':
        message += """
1. Changer immédiatement les mots de passe des comptes listés
2. Activer l'expiration des mots de passe pour ces comptes
3. Vérifier qu'aucune compromission n'a eu lieu
4. Activer MFA pour tous les comptes administrateurs
"""
    
    elif alert_type == 'service_password_never_expires':
        message += """
1. Examiner chaque compte de service listé
2. Utiliser des Managed Service Accounts (MSA) si possible
3. Si MDP requis, activer l'expiration avec une durée appropriée
4. Documenter l'utilisation de chaque compte de service
"""
    
    elif alert_type == 'critical_legacy_protocols':
        message += """
1. Identifier les systèmes utilisant ces protocoles
2. Mettre à jour les systèmes obsolètes
3. Désactiver les protocoles obsolètes dans la stratégie de groupe
4. Tester la compatibilité avant déploiement
"""
    
    elif alert_type == 'reversible_encryption':
        message += """
1. Identifier pourquoi le stockage réversible est activé
2. Désactiver dans la stratégie de mot de passe du domaine
3. Forcer le changement de tous les mots de passe
4. Auditer les comptes pour détecter d'éventuelles compromissions
"""
    
    else:
        message += """
1. Examiner les détails de l'alerte ci-dessus
2. Consulter la documentation de sécurité
3. Appliquer les correctifs recommandés
4. Documenter les actions entreprises
"""
    
    message += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📎 RAPPORT COMPLET
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Un rapport PDF complet est disponible dans l'interface AD Web Interface.
Connectez-vous pour consulter l'historique des audits et les recommandations détaillées.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Cordialement,
AD Web Interface - Système d'Alertes Automatiques
Généré automatiquement le {datetime.now().strftime('%d/%m/%Y à %H:%M')}
"""
    
    return message


def get_alert_summary(audit_result):
    """
    Obtenir un résumé des alertes pour affichage UI.
    
    Args:
        audit_result: Résultats de l'audit
    
    Returns:
        dict: Résumé des alertes
    """
    alerts = check_critical_issues(audit_result)
    
    return {
        'total': len(alerts),
        'critical': len([a for a in alerts if a.get('severity') == 'critical']),
        'high': len([a for a in alerts if a.get('severity') == 'high']),
        'alerts': alerts[:10]  # Limiter à 10 pour l'affichage
    }
