# -*- coding: utf-8 -*-
"""
Générateur de mots de passe sécurisés pour Active Directory.
Génère des mots de passe conformes aux politiques de sécurité.
"""
import secrets
import string
import random
from typing import Optional


def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
    exclude_ambiguous: bool = False,
    exclude_chars: str = ''
) -> str:
    """
    Générer un mot de passe sécurisé.
    
    Args:
        length: Longueur du mot de passe (min 8, max 128)
        use_uppercase: Inclure les majuscules (A-Z)
        use_lowercase: Inclure les minuscules (a-z)
        use_digits: Inclure les chiffres (0-9)
        use_special: Inclure les caractères spéciaux (!@#$%^&*)
        exclude_ambiguous: Exclure les caractères ambigus (0,O,1,l,I)
        exclude_chars: Caractères à exclure manuellement
    
    Returns:
        Mot de passe généré
    """
    # Validation des paramètres
    length = max(8, min(128, length))  # Entre 8 et 128 caractères
    
    # Définir les pools de caractères
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    # Caractères ambigus à exclure
    ambiguous = '0O1lI'
    
    # Construire le pool de caractères
    char_pool = ''
    required_chars = []
    
    if use_lowercase:
        chars = lowercase
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        chars = ''.join(c for c in chars if c not in exclude_chars)
        char_pool += chars
        required_chars.append(secrets.choice(chars))
    
    if use_uppercase:
        chars = uppercase
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        chars = ''.join(c for c in chars if c not in exclude_chars)
        char_pool += chars
        required_chars.append(secrets.choice(chars))
    
    if use_digits:
        chars = digits
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        chars = ''.join(c for c in chars if c not in exclude_chars)
        char_pool += chars
        required_chars.append(secrets.choice(chars))
    
    if use_special:
        chars = special
        chars = ''.join(c for c in chars if c not in exclude_chars)
        char_pool += chars
        required_chars.append(secrets.choice(chars))
    
    # Vérifier qu'il reste des caractères
    if not char_pool:
        raise ValueError("Aucun caractère disponible avec ces options")
    
    # Générer le reste du mot de passe
    remaining_length = length - len(required_chars)
    password_chars = required_chars + [secrets.choice(char_pool) for _ in range(remaining_length)]
    
    # Mélanger aléatoirement
    random.SystemRandom().shuffle(password_chars)
    
    return ''.join(password_chars)


def generate_ad_password(complexity: str = 'high') -> str:
    """
    Générer un mot de passe conforme aux exigences Active Directory.
    
    Args:
        complexity: Niveau de complexité ('low', 'medium', 'high', 'very_high')
    
    Returns:
        Mot de passe généré
    """
    configs = {
        'low': {
            'length': 10,
            'use_uppercase': True,
            'use_lowercase': True,
            'use_digits': True,
            'use_special': False,
            'exclude_ambiguous': True
        },
        'medium': {
            'length': 12,
            'use_uppercase': True,
            'use_lowercase': True,
            'use_digits': True,
            'use_special': True,
            'exclude_ambiguous': False
        },
        'high': {
            'length': 16,
            'use_uppercase': True,
            'use_lowercase': True,
            'use_digits': True,
            'use_special': True,
            'exclude_ambiguous': False
        },
        'very_high': {
            'length': 20,
            'use_uppercase': True,
            'use_lowercase': True,
            'use_digits': True,
            'use_special': True,
            'exclude_ambiguous': False
        }
    }
    
    config = configs.get(complexity, configs['high'])
    return generate_password(**config)


def check_password_complexity(password: str) -> dict:
    """
    Vérifier la complexité d'un mot de passe.
    
    Args:
        password: Mot de passe à vérifier
    
    Returns:
        Dictionnaire avec les critères de complexité
    """
    result = {
        'length': len(password),
        'length_ok': len(password) >= 8,
        'has_uppercase': any(c.isupper() for c in password),
        'has_lowercase': any(c.islower() for c in password),
        'has_digit': any(c.isdigit() for c in password),
        'has_special': any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password),
        'has_ambiguous': any(c in '0O1lI' for c in password),
    }
    
    # Calculer le score
    score = 0
    if result['length_ok']:
        score += 1
    if result['length'] >= 12:
        score += 1
    if result['length'] >= 16:
        score += 1
    if result['has_uppercase']:
        score += 1
    if result['has_lowercase']:
        score += 1
    if result['has_digit']:
        score += 1
    if result['has_special']:
        score += 1
    if not result['has_ambiguous']:
        score += 1
    
    result['score'] = score
    result['max_score'] = 8
    result['strength'] = 'Faible'
    
    if score >= 7:
        result['strength'] = 'Très fort'
    elif score >= 5:
        result['strength'] = 'Fort'
    elif score >= 3:
        result['strength'] = 'Moyen'
    
    return result


def generate_temporary_password(
    username: str, 
    domain: str = '', 
    expiry_hours: int = 24
) -> str:
    """
    Générer un mot de passe temporaire basé sur l'username.
    Utile pour les réinitialisations de masse.
    
    Args:
        username: Nom d'utilisateur
        domain: Domaine (optionnel)
        expiry_hours: Durée de validité en heures
    
    Returns:
        Mot de passe temporaire
    """
    # Générer un mot de passe aléatoire
    password = generate_password(
        length=16,
        use_uppercase=True,
        use_lowercase=True,
        use_digits=True,
        use_special=True,
        exclude_ambiguous=True
    )
    
    return password


# Générateur de mots de passe lisibles (prononçables)
def generate_readable_password(length: int = 12) -> str:
    """
    Générer un mot de passe lisible et prononçable.
    Plus facile à communiquer oralement.
    
    Args:
        length: Longueur approximative
    
    Returns:
        Mot de passe lisible
    """
    consonants = 'bcdfghjklmnpqrstvwxyz'
    vowels = 'aeiou'
    digits = '23456789'  # Exclure 0 et 1
    
    password = []
    
    # Alterner consonnes et voyelles
    for i in range(length // 2):
        password.append(secrets.choice(consonants).upper() if i % 2 == 0 else secrets.choice(consonants))
        password.append(secrets.choice(vowels))
    
    # Ajouter des chiffres
    password.append(secrets.choice(digits))
    password.append(secrets.choice(digits))
    
    # Ajouter un caractère spécial
    password.append(secrets.choice('!@#$%^&*'))
    
    random.SystemRandom().shuffle(password)
    
    return ''.join(password)
