"""
Audit de Sécurité des Mots de Passe Active Directory

Module d'analyse de la force et de la sécurité des mots de passe des utilisateurs AD.
"""

import re
from datetime import datetime, timedelta
from ldap3 import SUBTREE
from audit import log_action, ACTIONS


def analyze_password_strength(password):
    """
    Analyser la force d'un mot de passe.
    
    Args:
        password: Le mot de passe à analyser
        
    Returns:
        dict: Résultat de l'analyse avec score et recommandations
    """
    score = 0
    feedback = []
    
    # Longueur
    if len(password) >= 8:
        score += 1
    elif len(password) < 6:
        feedback.append("Le mot de passe est trop court (minimum 8 caractères recommandé)")
    
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    
    # Caractères variés
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
    
    # Pénalités pour motifs courants
    if password.lower() in ['password', 'motdepasse', 'admin', '123456', 'azerty', 'qwerty']:
        score = 0
        feedback.insert(0, "Mot de passe trop courant - à changer absolument")
    
    if re.search(r'(.)\1{2,}', password):  # Caractères répétés
        score = max(0, score - 1)
        feedback.append("Évitez les caractères répétés (ex: aaa)")
    
    if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
        score = max(0, score - 1)
        feedback.append("Évitez les séquences consécutives")
    
    # Détermination du niveau
    if score >= 6:
        strength = "Fort"
        color = "success"
    elif score >= 4:
        strength = "Moyen"
        color = "warning"
    else:
        strength = "Faible"
        color = "danger"
    
    return {
        'score': score,
        'max_score': 8,
        'strength': strength,
        'color': color,
        'feedback': feedback,
        'length': len(password)
    }


def check_weak_passwords_ad(conn, base_dn):
    """
    Vérifier les utilisateurs avec des mots de passe faibles dans AD.
    Note: Ne peut pas lire les mots de passe réels, mais peut identifier
    les comptes avec des politiques de mot de passe faibles.
    
    Args:
        conn: Connexion LDAP
        base_dn: Base DN pour la recherche
        
    Returns:
        list: Liste des utilisateurs avec des problèmes de sécurité
    """
    weak_accounts = []
    
    try:
        # Rechercher les utilisateurs dont le mot de passe n'expire jamais
        conn.search(
            base_dn,
            '(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=64))',
            SUBTREE,
            attributes=['sAMAccountName', 'displayName', 'distinguishedName', 'userAccountControl']
        )
        
        for entry in conn.entries:
            weak_accounts.append({
                'type': 'password_never_expires',
                'username': str(entry.sAMAccountName),
                'display_name': str(entry.displayName) if entry.displayName else '',
                'dn': str(entry.distinguishedName),
                'issue': 'Le mot de passe n\'expire jamais',
                'severity': 'warning'
            })
        
        # Rechercher les utilisateurs sans mot de passe requis
        conn.search(
            base_dn,
            '(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=32))',
            SUBTREE,
            attributes=['sAMAccountName', 'displayName', 'distinguishedName']
        )
        
        for entry in conn.entries:
            weak_accounts.append({
                'type': 'no_password_required',
                'username': str(entry.sAMAccountName),
                'display_name': str(entry.displayName) if entry.displayName else '',
                'dn': str(entry.distinguishedName),
                'issue': 'Mot de passe non requis',
                'severity': 'critical'
            })
            
    except Exception as e:
        weak_accounts.append({
            'type': 'error',
            'issue': f'Erreur de recherche: {str(e)}',
            'severity': 'error'
        })
    
    return weak_accounts


def check_password_age(conn, base_dn, max_age_days=90):
    """
    Vérifier l'ancienneté des mots de passe.
    
    Args:
        conn: Connexion LDAP
        base_dn: Base DN pour la recherche
        max_age_days: Âge maximum en jours avant alerte
        
    Returns:
        list: Utilisateurs avec des mots de passe trop anciens
    """
    old_passwords = []
    threshold_date = datetime.now() - timedelta(days=max_age_days)
    
    try:
        conn.search(
            base_dn,
            '(&(objectClass=user)(objectCategory=person)(pwdLastSet=*))',
            SUBTREE,
            attributes=['sAMAccountName', 'displayName', 'pwdLastSet', 'distinguishedName']
        )
        
        for entry in conn.entries:
            pwd_last_set = entry.pwdLastSet.value
            if pwd_last_set:
                # Conversion Windows FILETIME à datetime
                if isinstance(pwd_last_set, datetime):
                    last_change = pwd_last_set
                else:
                    # FILETIME Windows (100-nanosecond intervals since 1601-01-01)
                    windows_epoch = datetime(1601, 1, 1)
                    last_change = windows_epoch + timedelta(microseconds=pwd_last_set // 10)
                
                if last_change < threshold_date:
                    days_old = (datetime.now() - last_change).days
                    old_passwords.append({
                        'username': str(entry.sAMAccountName),
                        'display_name': str(entry.displayName) if entry.displayName else '',
                        'dn': str(entry.distinguishedName),
                        'pwdLastSet': last_change,
                        'days_old': days_old,
                        'severity': 'critical' if days_old > max_age_days * 2 else 'warning'
                    })
                    
    except Exception as e:
        old_passwords.append({
            'type': 'error',
            'issue': f'Erreur: {str(e)}',
            'severity': 'error'
        })
    
    return old_passwords


def get_password_policy(conn, base_dn):
    """
    Récupérer la politique de mot de passe du domaine.
    
    Args:
        conn: Connexion LDAP
        base_dn: Base DN
        
    Returns:
        dict: Politique de mot de passe
    """
    policy = {
        'minPasswordLength': 0,
        'maxPasswordAge': 0,
        'minPasswordAge': 0,
        'passwordHistoryLength': 0,
        'lockoutThreshold': 0,
        'lockoutDuration': 0
    }
    
    try:
        # Extraire le DN du domaine
        domain_dn = base_dn
        if 'DC=' in base_dn:
            domain_dn = base_dn
        
        conn.search(
            domain_dn,
            '(objectClass=domain)',
            SUBTREE,
            attributes=[
                'minPwdLength', 'maxPwdAge', 'minPwdAge',
                'pwdHistoryLength', 'lockoutThreshold', 'lockoutDuration'
            ]
        )
        
        if conn.entries:
            entry = conn.entries[0]
            
            # Longueur minimale
            if hasattr(entry, 'minPwdLength'):
                policy['minPasswordLength'] = int(entry.minPwdLength.value or 0)
            
            # Âge maximum (en jours)
            if hasattr(entry, 'maxPwdAge'):
                max_age = entry.maxPwdAge.value
                if max_age:
                    # Conversion de FILETIME en jours
                    policy['maxPasswordAge'] = abs(int(max_age / -864000000000))
            
            # Historique
            if hasattr(entry, 'pwdHistoryLength'):
                policy['passwordHistoryLength'] = int(entry.pwdHistoryLength.value or 0)
            
            # Seuil de verrouillage
            if hasattr(entry, 'lockoutThreshold'):
                policy['lockoutThreshold'] = int(entry.lockoutThreshold.value or 0)
                
    except Exception as e:
        policy['error'] = str(e)
    
    return policy


def generate_password_recommendations(policy, weak_accounts, old_passwords):
    """
    Générer des recommandations basées sur l'audit.
    
    Args:
        policy: Politique de mot de passe
        weak_accounts: Comptes avec mots de passe faibles
        old_passwords: Mots de passe anciens
        
    Returns:
        list: Recommandations
    """
    recommendations = []
    
    # Politique
    if policy.get('minPasswordLength', 0) < 8:
        recommendations.append({
            'priority': 'high',
            'category': 'Politique',
            'issue': f'Longueur minimale trop faible ({policy.get("minPasswordLength", 0)})',
            'recommendation': 'Définir une longueur minimale de 12 caractères'
        })
    
    if policy.get('maxPasswordAge', 0) == 0:
        recommendations.append({
            'priority': 'medium',
            'category': 'Politique',
            'issue': 'Expiration des mots de passe non activée',
            'recommendation': 'Activer l\'expiration tous les 90 jours'
        })
    
    if policy.get('passwordHistoryLength', 0) < 5:
        recommendations.append({
            'priority': 'medium',
            'category': 'Politique',
            'issue': f'Historique insuffisant ({policy.get("passwordHistoryLength", 0)})',
            'recommendation': 'Mémoriser les 10 derniers mots de passe'
        })
    
    # Comptes faibles
    critical_count = sum(1 for acc in weak_accounts if acc.get('severity') == 'critical')
    warning_count = sum(1 for acc in weak_accounts if acc.get('severity') == 'warning')
    
    if critical_count > 0:
        recommendations.append({
            'priority': 'critical',
            'category': 'Comptes',
            'issue': f'{critical_count} compte(s) avec problème critique',
            'recommendation': 'Exiger un changement de mot de passe immédiat'
        })
    
    if warning_count > 0:
        recommendations.append({
            'priority': 'high',
            'category': 'Comptes',
            'issue': f'{warning_count} compte(s) avec mot de passe n\'expirant jamais',
            'recommendation': 'Désactiver "Le mot de passe n\'expire jamais"'
        })
    
    # Mots de passe anciens
    very_old = sum(1 for pwd in old_passwords if pwd.get('severity') == 'critical')
    if very_old > 0:
        recommendations.append({
            'priority': 'high',
            'category': 'Ancienneté',
            'issue': f'{very_old} mot(s) de passe inchangé(s) depuis > {policy.get("maxPasswordAge", 90)} jours',
            'recommendation': 'Forcer le changement de mot de passe'
        })
    
    return recommendations


def run_password_audit(conn, base_dn, max_age_days=90):
    """
    Exécuter un audit complet des mots de passe.
    
    Args:
        conn: Connexion LDAP
        base_dn: Base DN
        max_age_days: Âge maximum pour alerte
        
    Returns:
        dict: Rapport d'audit complet
    """
    # Politique
    policy = get_password_policy(conn, base_dn)
    
    # Comptes faibles
    weak_accounts = check_weak_passwords_ad(conn, base_dn)
    
    # Ancienneté
    old_passwords = check_password_age(conn, base_dn, max_age_days)
    
    # Recommandations
    recommendations = generate_password_recommendations(policy, weak_accounts, old_passwords)
    
    # Calcul du score global
    total_issues = len(weak_accounts) + len(old_passwords)
    critical_issues = sum(1 for acc in weak_accounts if acc.get('severity') == 'critical')
    critical_issues += sum(1 for pwd in old_passwords if pwd.get('severity') == 'critical')
    
    if critical_issues > 0:
        global_score = "Critique"
        score_color = "danger"
    elif total_issues > 10:
        global_score = "Mauvais"
        score_color = "warning"
    elif total_issues > 0:
        global_score = "Acceptable"
        score_color = "info"
    else:
        global_score = "Bon"
        score_color = "success"
    
    return {
        'timestamp': datetime.now().isoformat(),
        'policy': policy,
        'weak_accounts': weak_accounts,
        'old_passwords': old_passwords,
        'recommendations': recommendations,
        'summary': {
            'total_issues': total_issues,
            'critical_issues': critical_issues,
            'global_score': global_score,
            'score_color': score_color
        }
    }


# Routes Flask pour l'audit
def create_password_audit_routes(app):
    """
    Créer les routes Flask pour l'audit des mots de passe.
    
    Args:
        app: Application Flask
    """
    from flask import render_template, jsonify, session
    from routes.core import require_connection, get_ad_connection
    
    @app.route('/tools/password-audit')
    @require_connection
    def password_audit_page():
        """Page d'audit des mots de passe."""
        return render_template('password_audit.html')
    
    @app.route('/api/password-audit')
    @require_connection
    def api_password_audit():
        """API d'audit des mots de passe."""
        from routes.core import get_ad_connection
        
        conn, error = get_ad_connection()
        if not conn:
            return jsonify({'error': error}), 500
        
        base_dn = session.get('ad_base_dn', '')
        max_age = int(session.get('password_audit_max_age', 90))
        
        audit_result = run_password_audit(conn, base_dn, max_age)
        
        # Journaliser l'audit
        log_action(
            ACTIONS['OTHER'],
            session.get('ad_username', 'unknown'),
            {'action': 'password_audit', 'issues_found': audit_result['summary']['total_issues']},
            True
        )
        
        conn.unbind()
        return jsonify(audit_result)
