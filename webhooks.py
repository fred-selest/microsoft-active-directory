"""
Module de webhooks pour notifier des evenements.
"""

import json
import os
import requests
from datetime import datetime

WEBHOOKS_FILE = 'data/webhooks.json'


def load_webhooks():
    """Charger les webhooks depuis le fichier."""
    try:
        if os.path.exists(WEBHOOKS_FILE):
            with open(WEBHOOKS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return []


def save_webhooks(webhooks):
    """Sauvegarder les webhooks."""
    os.makedirs(os.path.dirname(WEBHOOKS_FILE), exist_ok=True)
    with open(WEBHOOKS_FILE, 'w') as f:
        json.dump(webhooks, f, indent=2)


def add_webhook(name, url, events, secret=None):
    """
    Ajouter un webhook.

    Args:
        name: Nom du webhook
        url: URL de destination
        events: Liste des evenements (user_created, group_modified, etc.)
        secret: Secret pour signature HMAC

    Returns:
        ID du webhook
    """
    webhooks = load_webhooks()

    webhook_id = f"wh_{datetime.now().strftime('%Y%m%d%H%M%S')}_{len(webhooks)}"

    webhooks.append({
        'id': webhook_id,
        'name': name,
        'url': url,
        'events': events,
        'secret': secret,
        'enabled': True,
        'created': datetime.now().isoformat(),
        'last_triggered': None,
        'success_count': 0,
        'error_count': 0
    })

    save_webhooks(webhooks)
    return webhook_id


def delete_webhook(webhook_id):
    """Supprimer un webhook."""
    webhooks = load_webhooks()
    webhooks = [w for w in webhooks if w['id'] != webhook_id]
    save_webhooks(webhooks)


def toggle_webhook(webhook_id):
    """Activer/desactiver un webhook."""
    webhooks = load_webhooks()
    for webhook in webhooks:
        if webhook['id'] == webhook_id:
            webhook['enabled'] = not webhook['enabled']
            break
    save_webhooks(webhooks)


def get_webhooks():
    """Obtenir tous les webhooks."""
    return load_webhooks()


def trigger_webhook(event_type, data):
    """
    Declencher les webhooks pour un evenement.

    Args:
        event_type: Type d'evenement (user_created, user_modified, etc.)
        data: Donnees de l'evenement
    """
    webhooks = load_webhooks()
    results = []

    for webhook in webhooks:
        if not webhook['enabled']:
            continue

        if event_type not in webhook['events'] and '*' not in webhook['events']:
            continue

        # Preparer le payload
        payload = {
            'event': event_type,
            'timestamp': datetime.now().isoformat(),
            'data': data
        }

        # Envoyer la requete
        try:
            headers = {'Content-Type': 'application/json'}

            # Ajouter signature si secret
            if webhook.get('secret'):
                import hmac
                import hashlib
                signature = hmac.new(
                    webhook['secret'].encode(),
                    json.dumps(payload).encode(),
                    hashlib.sha256
                ).hexdigest()
                headers['X-Webhook-Signature'] = signature

            response = requests.post(
                webhook['url'],
                json=payload,
                headers=headers,
                timeout=10
            )

            success = response.status_code < 400

            # Mettre a jour les stats
            webhook['last_triggered'] = datetime.now().isoformat()
            if success:
                webhook['success_count'] += 1
            else:
                webhook['error_count'] += 1

            results.append({
                'webhook_id': webhook['id'],
                'success': success,
                'status_code': response.status_code
            })

        except Exception as e:
            webhook['error_count'] += 1
            results.append({
                'webhook_id': webhook['id'],
                'success': False,
                'error': str(e)
            })

    save_webhooks(webhooks)
    return results


# Types d'evenements disponibles
EVENT_TYPES = {
    'user_created': 'Utilisateur cree',
    'user_modified': 'Utilisateur modifie',
    'user_deleted': 'Utilisateur supprime',
    'user_enabled': 'Utilisateur active',
    'user_disabled': 'Utilisateur desactive',
    'user_password_reset': 'Mot de passe reinitialise',
    'group_created': 'Groupe cree',
    'group_modified': 'Groupe modifie',
    'group_deleted': 'Groupe supprime',
    'member_added': 'Membre ajoute au groupe',
    'member_removed': 'Membre retire du groupe',
    'computer_created': 'Ordinateur cree',
    'computer_deleted': 'Ordinateur supprime',
    'computer_moved': 'Ordinateur deplace',
    'ou_created': 'OU creee',
    'ou_deleted': 'OU supprimee',
    'login_success': 'Connexion reussie',
    'login_failed': 'Connexion echouee',
    '*': 'Tous les evenements'
}
