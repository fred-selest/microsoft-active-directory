# -*- coding: utf-8 -*-
"""
Fonctions utilitaires pour les utilisateurs.
"""
from ldap3 import SUBTREE
from typing import List, Dict, Optional


def get_ous(conn, base_dn: str) -> List[Dict[str, str]]:
    """
    Récupérer la liste des OUs.
    
    Args:
        conn: Connexion LDAP
        base_dn: DN de base pour la recherche
    
    Returns:
        Liste des OUs avec nom et DN
    """
    try:
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'distinguishedName'])
        return [
            {'name': str(e.name.value) if e.name else '', 'dn': str(e.entry_dn)}
            for e in conn.entries
        ]
    except Exception:
        return []


def get_user_attributes(conn, dn: str, attributes: List[str] = None) -> Optional[Dict]:
    """
    Récupérer les attributs d'un utilisateur.
    
    Args:
        conn: Connexion LDAP
        dn: DN de l'utilisateur
        attributes: Liste des attributs à récupérer
    
    Returns:
        Dictionnaire des attributs ou None si non trouvé
    """
    if attributes is None:
        attributes = [
            'cn', 'sAMAccountName', 'mail', 'displayName',
            'department', 'title', 'telephoneNumber', 'userAccountControl'
        ]
    
    try:
        search_filter = f'(distinguishedName={dn})'
        conn.search(conn.default_naming_context, search_filter, SUBTREE,
                   attributes=attributes)
        
        if conn.entries:
            entry = conn.entries[0]
            return {attr: str(getattr(entry, attr, '')) for attr in attributes}
        return None
    except Exception:
        return None


def is_account_disabled(uac_value: int) -> bool:
    """
    Vérifier si un compte est désactivé.
    
    Args:
        uac_value: Valeur userAccountControl
    
    Returns:
        True si le compte est désactivé
    """
    return bool(uac_value & 2) if uac_value else False


def is_password_never_expires(uac_value: int) -> bool:
    """
    Vérifier si le mot de passe n'expire jamais.
    
    Args:
        uac_value: Valeur userAccountControl
    
    Returns:
        True si le mot de passe n'expire jamais
    """
    return bool(uac_value & 64) if uac_value else False


def is_admin_account(uac_value: int) -> bool:
    """
    Vérifier si c'est un compte administrateur.
    
    Args:
        uac_value: Valeur userAccountControl
    
    Returns:
        True si c'est un compte administrateur
    """
    return bool(uac_value & 8192) if uac_value else False
