# -*- coding: utf-8 -*-
"""
Gestion des erreurs LDAP pour l'interface AD Web.
Traduction et explication des erreurs LDAP en français.
"""


def format_ldap_error(error_code, error_desc, error_msg='', context=''):
    """
    Formater une erreur LDAP en message utilisateur compréhensible.
    
    Args:
        error_code: Code d'erreur LDAP (ex: 53, 50, 19)
        error_desc: Description de l'erreur (ex: 'unwillingToPerform')
        error_msg: Message d'erreur complet
        context: Contexte de l'opération (ex: 'delete', 'modify', 'create')
    
    Returns:
        Message d'erreur formaté en français
    """
    
    # Nettoyage des entrées
    error_desc = str(error_desc) if error_desc else ''
    error_msg = str(error_msg) if error_msg else ''
    context = str(context) if context else ''
    
    # Détection automatique du type d'erreur
    error_lower = (error_desc + ' ' + error_msg).lower()
    
    # ========================================================================
    # ERREUR : unwillingToPerform (Le serveur refuse d'exécuter)
    # ========================================================================
    if 'unwilling' in error_lower or error_desc == 'unwillingToPerform':
        
        # Protection contre la suppression accidentelle
        if 'protected' in error_lower or 'accidental' in error_lower or 'deletion' in error_lower:
            return (
                "❌ <strong>Compte protégé contre la suppression</strong><br>"
                "Ce compte est protégé contre la suppression accidentelle.<br><br>"
                "<strong>Solution :</strong><br>"
                "1. Ouvrez <em>Utilisateurs et ordinateurs Active Directory</em><br>"
                "2. Menu <em>Affichage</em> → Cochez <em>Fonctionnalités avancées</em><br>"
                "3. Trouvez le compte → Onglet <em>Objet</em><br>"
                "4. Décochez <em>Protéger contre la suppression accidentelle</em><br>"
                "5. Réessayez la suppression dans l'interface web"
            )
        
        # Objet a des enfants
        if 'child' in error_lower or 'subordinate' in error_lower:
            return (
                "❌ <strong>Objet contenant des éléments enfants</strong><br>"
                "Cet objet contient des éléments enfants qui doivent être supprimés d'abord.<br><br>"
                "<strong>Solution :</strong><br>"
                "1. Supprimez ou déplacez les objets enfants<br>"
                "2. Réessayez la suppression"
            )
        
        # Droits insuffisants
        if 'rights' in error_lower or 'permission' in error_lower or 'access' in error_lower:
            return (
                "❌ <strong>Droits insuffisants</strong><br>"
                "Votre compte n'a pas les permissions nécessaires.<br><br>"
                "<strong>Solution :</strong><br>"
                "Contactez un administrateur <em>Domain Admins</em>"
            )
        
        # Cas général unwillingToPerform
        return (
            "❌ <strong>Le serveur Active Directory refuse l'opération</strong><br>"
            "Plusieurs causes possibles :<br><br>"
            "• Le compte est <strong>protégé</strong> (voir solution ci-dessous)<br>"
            "• Le compte a des <strong>objets enfants</strong><br>"
            "• Vos <strong>droits sont insuffisants</strong><br><br>"
            "<strong>Solution pour compte protégé :</strong><br>"
            "1. ADUC → Affichage → Fonctionnalités avancées<br>"
            "2. Trouvez le compte → Onglet Objet<br>"
            "3. Décochez 'Protéger contre la suppression accidentelle'"
        )
    
    # ========================================================================
    # ERREUR : 53 / unwillingToPerform (Server is unwilling)
    # ========================================================================
    if error_code == 53:
        return (
            "❌ <strong>Le serveur refuse l'opération (code 53)</strong><br>"
            "Vérifiez que vous avez les droits nécessaires et que l'objet n'est pas protégé."
        )
    
    # ========================================================================
    # ERREUR : 50 / insufficientAccessRights
    # ========================================================================
    if error_code == 50 or 'insufficient' in error_lower or 'access' in error_lower:
        return (
            "❌ <strong>Droits d'accès insuffisants</strong><br>"
            "Votre compte n'a pas les permissions nécessaires pour cette opération.<br><br>"
            "<strong>Solution :</strong><br>"
            "• Utilisez un compte <em>Domain Admin</em><br>"
            "• Ou demandez une délégation de droits"
        )
    
    # ========================================================================
    # ERREUR : 19 / CONSTRAINT_VIOLATION
    # ========================================================================
    if error_code == 19 or 'constraint' in error_lower or 'violation' in error_lower:
        
        # Violation de politique de mot de passe
        if 'password' in error_lower or 'pwd' in error_lower:
            return (
                "❌ <strong>Mot de passe non conforme</strong><br>"
                "Le mot de passe ne respecte pas la politique du domaine.<br><br>"
                "<strong>Exigences typiques :</strong><br>"
                "• Minimum 7-14 caractères<br>"
                "• Au moins 1 majuscule, 1 minuscule, 1 chiffre<br>"
                "• Au moins 1 caractère spécial<br>"
                "• Ne pas réutiliser les 24 derniers mots de passe"
            )
        
        return (
            "❌ <strong>Violation de contrainte Active Directory</strong><br>"
            "L'opération viole une règle du schéma ou de la politique du domaine."
        )
    
    # ========================================================================
    # ERREUR : 20 / ATTRIBUTE_OR_VALUE_EXISTS
    # ========================================================================
    if error_code == 20 or 'exists' in error_lower or 'already' in error_lower:
        return (
            "❌ <strong>L'objet ou la valeur existe déjà</strong><br>"
            "Un objet avec le même nom ou attribut existe déjà dans l'annuaire."
        )
    
    # ========================================================================
    # ERREUR : 32 / NO_SUCH_OBJECT
    # ========================================================================
    if error_code == 32 or 'no such object' in error_lower or 'not found' in error_lower:
        return (
            "❌ <strong>Objet introuvable</strong><br>"
            "L'objet Active Directory spécifié n'existe pas.<br><br>"
            "<strong>Causes possibles :</strong><br>"
            "• L'objet a déjà été supprimé<br>"
            "• Le DN (Distinguished Name) est incorrect<br>"
            "• Problème de réplication entre contrôleurs de domaine"
        )
    
    # ========================================================================
    # ERREUR : 48 / INAPPROPRIATE_AUTH
    # ========================================================================
    if error_code == 48 or 'inappropriate auth' in error_lower:
        return (
            "❌ <strong>Problème d'authentification</strong><br>"
            "Les informations d'identification sont invalides ou expirées.<br><br>"
            "<strong>Solution :</strong><br>"
            "Déconnectez-vous et reconnectez-vous avec vos identifiants."
        )
    
    # ========================================================================
    # ERREUR : 64 / NAMING_VIOLATION
    # ========================================================================
    if error_code == 64 or 'naming' in error_lower:
        return (
            "❌ <strong>Violation de nommage Active Directory</strong><br>"
            "Le nom ou l'emplacement de l'objet n'est pas valide.<br><br>"
            "<strong>Vérifiez :</strong><br>"
            "• Le nom respecte les règles de nommage AD<br>"
            "• L'OU de destination existe et est accessible"
        )
    
    # ========================================================================
    # ERREUR : 80 / BUSY
    # ========================================================================
    if error_code == 80 or 'busy' in error_lower:
        return (
            "❌ <strong>Contrôleur de domaine occupé</strong><br>"
            "Le serveur est temporairement occupé.<br><br>"
            "<strong>Solution :</strong><br>"
            "Réessayez dans quelques instants."
        )
    
    # ========================================================================
    # ERREUR : 81 / SERVER_DOWN
    # ========================================================================
    if error_code == 81 or 'server down' in error_lower or 'unavailable' in error_lower:
        return (
            "❌ <strong>Contrôleur de domaine inaccessible</strong><br>"
            "Le serveur Active Directory ne répond pas.<br><br>"
            "<strong>Vérifiez :</strong><br>"
            "• La connexion réseau vers le contrôleur de domaine<br>"
            "• Le service AD DS est en cours d'exécution<br>"
            "• Le pare-feu autorise le trafic LDAP (ports 389/636)"
        )
    
    # ========================================================================
    # ERREUR : INVALID_DN_SYNTAX
    # ========================================================================
    if 'dn syntax' in error_lower or 'distinguished name' in error_lower:
        return (
            "❌ <strong>Format DN invalide</strong><br>"
            "Le Distinguished Name (DN) a un format incorrect.<br><br>"
            "<strong>Format attendu :</strong><br>"
            "<code>CN=Nom Utilisateur,OU=Service,DC=domaine,DC=local</code>"
        )
    
    # ========================================================================
    # ERREUR : OBJECT_CLASS_VIOLATION
    # ========================================================================
    if 'object class' in error_lower or 'objectclass' in error_lower:
        return (
            "❌ <strong>Violation de classe d'objet</strong><br>"
            "L'opération viole les règles de classe d'objet Active Directory."
        )
    
    # ========================================================================
    # ERREUR : NON_UNIQUE_NAME
    # ========================================================================
    if 'non unique' in error_lower or 'duplicate' in error_lower:
        return (
            "❌ <strong>Nom non unique</strong><br>"
            "Un objet avec ce nom existe déjà.<br><br>"
            "<strong>Solution :</strong><br>"
            "Utilisez un nom différent pour l'objet."
        )
    
    # ========================================================================
    # ERREUR GÉNÉRIQUE AVEC CODE
    # ========================================================================
    if error_code:
        return (
            f"❌ <strong>Erreur Active Directory (code {error_code})</strong><br>"
            f"{error_desc if error_desc else 'Erreur inconnue'}<br><br>"
            "<strong>Si le problème persiste, contactez l'administrateur.</strong>"
        )
    
    # ========================================================================
    # ERREUR PAR DÉFAUT
    # ========================================================================
    return (
        "❌ <strong>Erreur Active Directory</strong><br>"
        f"{error_msg if error_msg else error_desc if error_desc else 'Erreur inconnue'}<br><br>"
        "<strong>Si le problème persiste, contactez l'administrateur.</strong>"
    )


def handle_ldap_exception(exception, context=''):
    """
    Gérer une exception LDAP et retourner un message utilisateur.
    
    Args:
        exception: L'exception LDAP capturée
        context: Contexte de l'opération
    
    Returns:
        Message d'erreur formaté
    """
    from ldap3.core.exceptions import LDAPException
    
    if isinstance(exception, LDAPException):
        error_code = getattr(exception, 'result', {}).get('result', 0) if hasattr(exception, 'result') else 0
        error_desc = getattr(exception, 'result', {}).get('description', str(exception)) if hasattr(exception, 'result') else str(exception)
        error_msg = str(exception)
        
        return format_ldap_error(error_code, error_desc, error_msg, context)
    
    # Exception non-LDAP
    return (
        "❌ <strong>Erreur inattendue</strong><br>"
        f"{str(exception)}<br><br>"
        "<strong>Si le problème persiste, contactez l'administrateur.</strong>"
    )
