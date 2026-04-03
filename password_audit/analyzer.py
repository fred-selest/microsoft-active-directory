"""Analyse de force des mots de passe, politique de domaine, FGPP, recommandations."""
import re
from datetime import datetime, timedelta
from ldap3 import SUBTREE

from .constants import COMMON_PASSWORDS, KEYBOARD_PATTERNS


def analyze_password_strength(password):
    """Analyser la force d'un mot de passe."""
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    elif len(password) < 6:
        feedback.append("Le mot de passe est trop court (minimum 8 caractères recommandé)")
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1

    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Ajoutez des lettres minuscules")
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Ajoutez des lettres majuscules")
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Ajoutez des chiffres")
    if re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~]', password):
        score += 1
    else:
        feedback.append("Ajoutez des caractères spéciaux")

    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.insert(0, "Mot de passe trop courant - à changer absolument")
    if re.search(r'(.)\1{2,}', password):
        score = max(0, score - 1)
        feedback.append("Évitez les caractères répétés (ex: aaa)")
    if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
        score = max(0, score - 1)
        feedback.append("Évitez les séquences consécutives")
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password.lower():
            score = max(0, score - 1)
            feedback.append(f"Évitez les motifs de clavier courants ({pattern})")
            break

    if score >= 6:
        strength, color = "Fort", "success"
    elif score >= 4:
        strength, color = "Moyen", "warning"
    else:
        strength, color = "Faible", "danger"

    return {'score': score, 'max_score': 8, 'strength': strength,
            'color': color, 'feedback': feedback, 'length': len(password)}


def get_password_policy(conn, base_dn):
    """Récupérer la politique de mot de passe du domaine."""
    policy = {
        'minPasswordLength': 0, 'maxPasswordAge': 0, 'minPasswordAge': 0,
        'passwordHistoryLength': 0, 'lockoutThreshold': 0, 'lockoutDuration': 0,
        'lockoutObservationWindow': 0, 'pwdProperties': 0,
        'complexity_enabled': False, 'reversible_encryption': False,
    }

    def _filetime_days(val):
        if val is None:
            return 0
        if hasattr(val, 'total_seconds'):
            return abs(int(val.total_seconds() / 86400))
        return abs(int(val / -864000000000))

    def _filetime_minutes(val):
        if val is None:
            return 0
        if hasattr(val, 'total_seconds'):
            return abs(int(val.total_seconds() / 60))
        return abs(int(val / -600000000))

    try:
        conn.search(base_dn, '(objectClass=domain)', SUBTREE,
                    attributes=['minPwdLength', 'maxPwdAge', 'minPwdAge',
                                'pwdHistoryLength', 'lockoutThreshold',
                                'lockoutDuration', 'lockoutObservationWindow', 'pwdProperties'])
        if conn.entries:
            e = conn.entries[0]
            policy['minPasswordLength'] = int(e.minPwdLength.value) if hasattr(e, 'minPwdLength') and e.minPwdLength.value is not None else 0
            policy['maxPasswordAge'] = _filetime_days(e.maxPwdAge.value) if hasattr(e, 'maxPwdAge') else 0
            policy['minPasswordAge'] = _filetime_days(e.minPwdAge.value) if hasattr(e, 'minPwdAge') else 0
            policy['passwordHistoryLength'] = int(e.pwdHistoryLength.value) if hasattr(e, 'pwdHistoryLength') and e.pwdHistoryLength.value is not None else 0
            policy['lockoutThreshold'] = int(e.lockoutThreshold.value) if hasattr(e, 'lockoutThreshold') and e.lockoutThreshold.value is not None else 0
            policy['lockoutDuration'] = _filetime_minutes(e.lockoutDuration.value) if hasattr(e, 'lockoutDuration') else 0
            policy['lockoutObservationWindow'] = _filetime_minutes(e.lockoutObservationWindow.value) if hasattr(e, 'lockoutObservationWindow') else 0
            if hasattr(e, 'pwdProperties') and e.pwdProperties.value is not None:
                props = int(e.pwdProperties.value)
                policy['pwdProperties'] = props
                policy['complexity_enabled'] = bool(props & 1)
                policy['reversible_encryption'] = bool(props & 16)
    except Exception as ex:
        policy['error'] = str(ex)

    return policy


def check_fine_grained_policies(conn, base_dn):
    """Vérifier les politiques de mot de passe à granularité fine (FGPP/PSO)."""
    fgpps = []
    try:
        conn.search(base_dn, '(objectClass=msDS-PasswordSettings)', SUBTREE,
                    attributes=['name', 'msDS-PasswordSettingsPrecedence',
                                'msDS-MinimumPasswordLength', 'msDS-MaximumPasswordAge',
                                'msDS-PasswordHistoryLength',
                                'msDS-PasswordReversibleEncryptionEnabled',
                                'msDS-PasswordSettingsAppliedTo'])
        for entry in conn.entries:
            fgpps.append({
                'name': str(entry.name),
                'precedence': int(getattr(entry, 'msDS-PasswordSettingsPrecedence').value) if hasattr(entry, 'msDS-PasswordSettingsPrecedence') else 0,
                'min_length': int(getattr(entry, 'msDS-MinimumPasswordLength').value) if hasattr(entry, 'msDS-MinimumPasswordLength') else 0,
                'max_age': int(getattr(entry, 'msDS-MaximumPasswordAge').value / -864000000000) if hasattr(entry, 'msDS-MaximumPasswordAge') and getattr(entry, 'msDS-MaximumPasswordAge').value else 0,
                'reversible_encryption': bool(getattr(entry, 'msDS-PasswordReversibleEncryptionEnabled').value) if hasattr(entry, 'msDS-PasswordReversibleEncryptionEnabled') else False,
            })
    except Exception as ex:
        fgpps.append({'error': str(ex)})
    return fgpps


def generate_password_recommendations(policy, weak_accounts, old_passwords, fgpps=None):
    """Générer des recommandations basées sur l'audit."""
    recommendations = []

    if policy.get('minPasswordLength', 0) < 8:
        recommendations.append({'priority': 'high', 'category': 'Politique',
            'issue': f'Longueur minimale trop faible ({policy.get("minPasswordLength", 0)})',
            'recommendation': 'Définir une longueur minimale de 12 caractères',
            'specops_reference': 'SP-PP-001: Minimum 12 caractères recommandé'})
    if policy.get('maxPasswordAge', 0) == 0:
        recommendations.append({'priority': 'medium', 'category': 'Politique',
            'issue': "Expiration des mots de passe non activée",
            'recommendation': "Activer l'expiration tous les 90 jours",
            'specops_reference': 'SP-PP-002: Expiration recommandée'})
    if policy.get('passwordHistoryLength', 0) < 5:
        recommendations.append({'priority': 'medium', 'category': 'Politique',
            'issue': f'Historique insuffisant ({policy.get("passwordHistoryLength", 0)})',
            'recommendation': 'Mémoriser les 10 derniers mots de passe',
            'specops_reference': 'SP-PP-003: Historique de 10 mots de passe minimum'})
    if not policy.get('complexity_enabled', False):
        recommendations.append({'priority': 'high', 'category': 'Politique',
            'issue': 'Complexité des mots de passe non activée',
            'recommendation': 'Activer la complexité des mots de passe',
            'specops_reference': 'SP-PP-004: Complexité requise'})
    if policy.get('reversible_encryption', False):
        recommendations.append({'priority': 'critical', 'category': 'Politique',
            'issue': 'Stockage du mot de passe en clair activé',
            'recommendation': 'Désactiver immédiatement le stockage réversible',
            'specops_reference': 'SP-SEC-001: Jamais de stockage en clair'})

    critical_count = sum(1 for a in weak_accounts if a.get('severity') == 'critical')
    warning_count = sum(1 for a in weak_accounts if a.get('severity') == 'warning')
    if critical_count > 0:
        recommendations.append({'priority': 'critical', 'category': 'Comptes',
            'issue': f'{critical_count} compte(s) avec problème critique',
            'recommendation': 'Exiger un changement de mot de passe immédiat',
            'specops_reference': 'SP-ACC-001: Corriger les comptes critiques'})
    if warning_count > 0:
        recommendations.append({'priority': 'high', 'category': 'Comptes',
            'issue': f"{warning_count} compte(s) avec mot de passe n'expirant jamais",
            'recommendation': 'Désactiver "Le mot de passe n\'expire jamais"',
            'specops_reference': 'SP-ACC-002: Expiration pour tous les comptes'})

    very_old = sum(1 for p in old_passwords if p.get('severity') == 'critical')
    if very_old > 0:
        recommendations.append({'priority': 'high', 'category': 'Ancienneté',
            'issue': f'{very_old} mot(s) de passe inchangé(s) depuis > {policy.get("maxPasswordAge", 90)} jours',
            'recommendation': 'Forcer le changement de mot de passe',
            'specops_reference': 'SP-AGE-001: Rotation régulière'})

    if fgpps is not None and len(fgpps) == 0:
        recommendations.append({'priority': 'info', 'category': 'Politiques FGPP',
            'issue': 'Aucune politique à granularité fine détectée',
            'recommendation': 'Envisager des FGPP pour les comptes privilégiés',
            'specops_reference': 'SP-FGPP-001: Politiques différenciées'})

    return recommendations
