"""
Module de gestion des alertes pour l'interface Web Active Directory.
Detecte et signale les problemes potentiels.
"""

import json
import os
from datetime import datetime, timedelta

ALERTS_FILE = 'data/alerts.json'


def load_alerts():
    """Charger les alertes depuis le fichier."""
    try:
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return []


def save_alerts(alerts):
    """Sauvegarder les alertes dans le fichier."""
    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
    with open(ALERTS_FILE, 'w') as f:
        json.dump(alerts, f, indent=2, ensure_ascii=False)


def add_alert(alert_type, title, message, severity='warning', data=None):
    """
    Ajouter une nouvelle alerte.

    Args:
        alert_type: Type d'alerte (expiring_account, locked_account, etc.)
        title: Titre de l'alerte
        message: Message detaille
        severity: Niveau de gravite (info, warning, error, critical)
        data: Donnees supplementaires

    Returns:
        ID de l'alerte creee
    """
    alerts = load_alerts()

    alert_id = f"alert_{datetime.now().strftime('%Y%m%d%H%M%S')}_{len(alerts)}"

    alert = {
        'id': alert_id,
        'type': alert_type,
        'title': title,
        'message': message,
        'severity': severity,
        'data': data or {},
        'created': datetime.now().isoformat(),
        'acknowledged': False,
        'acknowledged_by': None,
        'acknowledged_at': None
    }

    alerts.insert(0, alert)  # Ajouter en premier

    # Limiter a 1000 alertes
    if len(alerts) > 1000:
        alerts = alerts[:1000]

    save_alerts(alerts)
    return alert_id


def get_alerts(limit=50, alert_type=None, severity=None, acknowledged=None):
    """
    Obtenir les alertes avec filtres optionnels.

    Args:
        limit: Nombre maximum d'alertes
        alert_type: Filtrer par type
        severity: Filtrer par gravite
        acknowledged: Filtrer par statut d'acquittement

    Returns:
        Liste des alertes
    """
    alerts = load_alerts()

    # Appliquer les filtres
    if alert_type:
        alerts = [a for a in alerts if a['type'] == alert_type]
    if severity:
        alerts = [a for a in alerts if a['severity'] == severity]
    if acknowledged is not None:
        alerts = [a for a in alerts if a['acknowledged'] == acknowledged]

    return alerts[:limit]


def acknowledge_alert(alert_id, user):
    """
    Acquitter une alerte.

    Args:
        alert_id: ID de l'alerte
        user: Utilisateur qui acquitte

    Returns:
        True si succes, False sinon
    """
    alerts = load_alerts()

    for alert in alerts:
        if alert['id'] == alert_id:
            alert['acknowledged'] = True
            alert['acknowledged_by'] = user
            alert['acknowledged_at'] = datetime.now().isoformat()
            save_alerts(alerts)
            return True

    return False


def delete_alert(alert_id):
    """Supprimer une alerte."""
    alerts = load_alerts()
    alerts = [a for a in alerts if a['id'] != alert_id]
    save_alerts(alerts)


def get_alert_counts():
    """Obtenir les compteurs d'alertes par type et gravite."""
    alerts = load_alerts()

    counts = {
        'total': len(alerts),
        'unacknowledged': len([a for a in alerts if not a['acknowledged']]),
        'by_severity': {
            'critical': 0,
            'error': 0,
            'warning': 0,
            'info': 0
        },
        'by_type': {}
    }

    for alert in alerts:
        if not alert['acknowledged']:
            severity = alert.get('severity', 'info')
            counts['by_severity'][severity] = counts['by_severity'].get(severity, 0) + 1

            alert_type = alert.get('type', 'other')
            counts['by_type'][alert_type] = counts['by_type'].get(alert_type, 0) + 1

    return counts


def check_expiring_accounts(conn, base_dn, days=30):
    """
    Verifier les comptes qui expirent bientot.

    Args:
        conn: Connexion LDAP
        base_dn: Base DN pour la recherche
        days: Nombre de jours avant expiration

    Returns:
        Liste des comptes expirants
    """
    from ldap3 import SUBTREE

    expiring = []

    try:
        # Calculer la date limite
        limit_date = datetime.now() + timedelta(days=days)
        # Convertir en format AD (100-nanosecond intervals since 1601)
        ad_timestamp = int((limit_date - datetime(1601, 1, 1)).total_seconds() * 10000000)

        # Rechercher les comptes avec accountExpires defini
        conn.search(
            base_dn,
            f'(&(objectClass=user)(objectCategory=person)(accountExpires>={116444736000000000})(accountExpires<={ad_timestamp}))',
            SUBTREE,
            attributes=['cn', 'sAMAccountName', 'mail', 'accountExpires', 'distinguishedName']
        )

        for entry in conn.entries:
            expiring.append({
                'cn': str(entry.cn) if entry.cn else '',
                'sAMAccountName': str(entry.sAMAccountName) if entry.sAMAccountName else '',
                'mail': str(entry.mail) if entry.mail else '',
                'dn': str(entry.distinguishedName) if entry.distinguishedName else '',
                'accountExpires': str(entry.accountExpires) if entry.accountExpires else ''
            })

    except Exception as e:
        pass

    return expiring


def check_password_expiring(conn, base_dn, days=14):
    """
    Verifier les mots de passe qui expirent bientot.

    Args:
        conn: Connexion LDAP
        base_dn: Base DN pour la recherche
        days: Nombre de jours avant expiration

    Returns:
        Liste des utilisateurs avec mot de passe expirant
    """
    from ldap3 import SUBTREE

    expiring = []

    try:
        # Rechercher les utilisateurs avec pwdLastSet
        conn.search(
            base_dn,
            '(&(objectClass=user)(objectCategory=person)(pwdLastSet>=1))',
            SUBTREE,
            attributes=['cn', 'sAMAccountName', 'mail', 'pwdLastSet', 'distinguishedName']
        )

        # Obtenir la politique de mot de passe du domaine
        conn.search(base_dn, '(objectClass=domain)', SUBTREE, attributes=['maxPwdAge'])

        max_pwd_age_days = 90  # Par defaut
        if conn.entries:
            max_pwd_age = conn.entries[0].maxPwdAge.value
            if max_pwd_age:
                # Convertir en jours (valeur negative en 100-nanosecond intervals)
                max_pwd_age_days = abs(int(max_pwd_age)) / (10000000 * 60 * 60 * 24)

        # Note: Implementation simplifiee, necessite plus de logique pour pwdLastSet

    except Exception as e:
        pass

    return expiring


def check_inactive_accounts(conn, base_dn, days=90):
    """
    Verifier les comptes inactifs.

    Args:
        conn: Connexion LDAP
        base_dn: Base DN pour la recherche
        days: Nombre de jours d'inactivite

    Returns:
        Liste des comptes inactifs
    """
    from ldap3 import SUBTREE

    inactive = []

    try:
        # Calculer la date limite
        limit_date = datetime.now() - timedelta(days=days)
        # Convertir en format AD
        ad_timestamp = int((limit_date - datetime(1601, 1, 1)).total_seconds() * 10000000)

        # Rechercher les comptes avec lastLogonTimestamp ancien
        conn.search(
            base_dn,
            f'(&(objectClass=user)(objectCategory=person)(lastLogonTimestamp<={ad_timestamp}))',
            SUBTREE,
            attributes=['cn', 'sAMAccountName', 'mail', 'lastLogonTimestamp', 'distinguishedName']
        )

        for entry in conn.entries:
            inactive.append({
                'cn': str(entry.cn) if entry.cn else '',
                'sAMAccountName': str(entry.sAMAccountName) if entry.sAMAccountName else '',
                'mail': str(entry.mail) if entry.mail else '',
                'dn': str(entry.distinguishedName) if entry.distinguishedName else '',
                'lastLogon': str(entry.lastLogonTimestamp) if entry.lastLogonTimestamp else ''
            })

    except Exception as e:
        pass

    return inactive
