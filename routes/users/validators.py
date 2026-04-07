# -*- coding: utf-8 -*-
"""
Validateurs pour les données utilisateurs.
Validation centralisée et réutilisable.
"""
import re
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class UserCreateRequest:
    """Requête de création d'utilisateur."""
    username: str
    first_name: str
    last_name: str
    password: str
    email: Optional[str]
    ou: str
    department: Optional[str] = None
    title: Optional[str] = None
    
    def validate(self) -> List[str]:
        """Valider toutes les données. Retourne liste d'erreurs."""
        errors = []
        
        # Validation username
        if not self.username or len(self.username.strip()) < 3:
            errors.append("Nom d'utilisateur trop court (min 3 caractères)")
        if not re.match(r'^[a-zA-Z0-9_.-]+$', self.username):
            errors.append("Caractères non autorisés dans le nom d'utilisateur (a-z, 0-9, _, ., -)")
        
        # Validation noms
        if not self.first_name or not self.first_name.strip():
            errors.append("Prénom requis")
        if not self.last_name or not self.last_name.strip():
            errors.append("Nom de famille requis")
        
        # Validation mot de passe
        pwd_errors = validate_password_strength(self.password)
        errors.extend(pwd_errors)
        
        # Validation email
        if self.email and not re.match(r'^[^@]+@[^@]+\.[^@]+$', self.email):
            errors.append("Format d'email invalide")
        
        # Validation OU (accepte DC=, OU= et CN= comme CN=Users,DC=...)
        if not self.ou or not self.ou.strip():
            errors.append("Unité d'organisation requise")
        elif not (self.ou.startswith('DC=') or self.ou.startswith('OU=') or self.ou.startswith('CN=')):
            errors.append("DN d'unité d'organisation invalide")
        
        return errors


def validate_password_strength(password: str) -> List[str]:
    """
    Valider la force d'un mot de passe.
    
    Returns:
        Liste des erreurs de validation
    """
    errors = []
    
    if len(password) < 8:
        errors.append("Mot de passe trop court (min 8 caractères)")
    
    if not any(c.isupper() for c in password):
        errors.append("Le mot de passe doit contenir au moins une majuscule")
    
    if not any(c.islower() for c in password):
        errors.append("Le mot de passe doit contenir au moins une minuscule")
    
    if not any(c.isdigit() for c in password):
        errors.append("Le mot de passe doit contenir au moins un chiffre")
    
    # Caractères spéciaux recommandés mais pas obligatoires
    special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?')
    if not any(c in special_chars for c in password):
        errors.append("Le mot de passe devrait contenir un caractère spécial (recommandé)")
    
    return errors


def validate_username_available(username: str, existing_users: List[str]) -> bool:
    """
    Vérifier si un nom d'utilisateur est disponible.
    
    Args:
        username: Nom d'utilisateur à vérifier
        existing_users: Liste des noms existants
    
    Returns:
        True si disponible, False sinon
    """
    return username.lower() not in [u.lower() for u in existing_users]


def sanitize_ldap_input(value: str) -> str:
    """
    Nettoyer une entrée pour éviter les injections LDAP.
    
    Args:
        value: Valeur à nettoyer
    
    Returns:
        Valeur nettoyée
    """
    if not value:
        return ''
    
    # Caractères spéciaux LDAP à échapper
    ldap_special = ['\\', '*', '(', ')', '\x00']
    result = value
    for char in ldap_special:
        result = result.replace(char, f'\\{ord(char):02x}')
    
    return result.strip()
