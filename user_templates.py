"""
Module de gestion des modeles d'utilisateurs.
Permet de creer des templates pour la creation rapide d'utilisateurs.
"""

import json
import os
from datetime import datetime

TEMPLATES_FILE = 'data/user_templates.json'


def load_templates():
    """Charger les modeles depuis le fichier."""
    try:
        if os.path.exists(TEMPLATES_FILE):
            with open(TEMPLATES_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}


def save_templates(templates):
    """Sauvegarder les modeles dans le fichier."""
    os.makedirs(os.path.dirname(TEMPLATES_FILE), exist_ok=True)
    with open(TEMPLATES_FILE, 'w') as f:
        json.dump(templates, f, indent=2, ensure_ascii=False)


def get_all_templates():
    """Obtenir tous les modeles."""
    return load_templates()


def get_template(template_id):
    """Obtenir un modele par son ID."""
    templates = load_templates()
    return templates.get(template_id)


def create_template(name, description, attributes, groups=None, ou=None):
    """
    Creer un nouveau modele d'utilisateur.

    Args:
        name: Nom du modele
        description: Description du modele
        attributes: Attributs par defaut (department, title, etc.)
        groups: Liste des DNs de groupes a ajouter automatiquement
        ou: OU par defaut pour la creation

    Returns:
        ID du modele cree
    """
    templates = load_templates()

    # Generer un ID unique
    template_id = f"tpl_{datetime.now().strftime('%Y%m%d%H%M%S')}_{len(templates)}"

    templates[template_id] = {
        'name': name,
        'description': description,
        'attributes': attributes,
        'groups': groups or [],
        'ou': ou or '',
        'created': datetime.now().isoformat(),
        'modified': datetime.now().isoformat()
    }

    save_templates(templates)
    return template_id


def update_template(template_id, name=None, description=None, attributes=None, groups=None, ou=None):
    """Mettre a jour un modele existant."""
    templates = load_templates()

    if template_id not in templates:
        return False

    if name is not None:
        templates[template_id]['name'] = name
    if description is not None:
        templates[template_id]['description'] = description
    if attributes is not None:
        templates[template_id]['attributes'] = attributes
    if groups is not None:
        templates[template_id]['groups'] = groups
    if ou is not None:
        templates[template_id]['ou'] = ou

    templates[template_id]['modified'] = datetime.now().isoformat()
    save_templates(templates)
    return True


def delete_template(template_id):
    """Supprimer un modele."""
    templates = load_templates()

    if template_id in templates:
        del templates[template_id]
        save_templates(templates)
        return True
    return False


def apply_template(template_id, user_data):
    """
    Appliquer un modele a des donnees utilisateur.

    Args:
        template_id: ID du modele a appliquer
        user_data: Donnees de base de l'utilisateur

    Returns:
        Donnees utilisateur avec les attributs du modele appliques
    """
    template = get_template(template_id)
    if not template:
        return user_data

    # Fusionner les attributs
    merged = dict(template.get('attributes', {}))
    merged.update(user_data)

    # Ajouter les groupes et l'OU
    merged['_template_groups'] = template.get('groups', [])
    merged['_template_ou'] = template.get('ou', '')

    return merged


# Templates par defaut
DEFAULT_TEMPLATES = {
    'default_employee': {
        'name': 'Employe standard',
        'description': 'Modele pour les employes standards de l\'entreprise',
        'attributes': {
            'department': '',
            'title': 'Employe',
            'description': 'Compte utilisateur standard'
        },
        'groups': [],
        'ou': '',
        'created': datetime.now().isoformat(),
        'modified': datetime.now().isoformat()
    },
    'default_admin': {
        'name': 'Administrateur',
        'description': 'Modele pour les administrateurs systeme',
        'attributes': {
            'department': 'IT',
            'title': 'Administrateur systeme',
            'description': 'Compte administrateur'
        },
        'groups': [],
        'ou': '',
        'created': datetime.now().isoformat(),
        'modified': datetime.now().isoformat()
    },
    'default_contractor': {
        'name': 'Prestataire',
        'description': 'Modele pour les prestataires externes',
        'attributes': {
            'department': 'Externe',
            'title': 'Prestataire',
            'description': 'Compte prestataire externe'
        },
        'groups': [],
        'ou': '',
        'created': datetime.now().isoformat(),
        'modified': datetime.now().isoformat()
    }
}


def init_default_templates():
    """Initialiser les modeles par defaut s'ils n'existent pas."""
    templates = load_templates()

    if not templates:
        templates = DEFAULT_TEMPLATES
        save_templates(templates)

    return templates
