"""
Persistance des modeles utilisateur (attributs par defaut reutilisables
lors de la creation d'un compte AD).
"""

import json
import uuid
from datetime import datetime
from pathlib import Path

TEMPLATES_FILE = Path(__file__).resolve().parent.parent / 'data' / 'user_templates.json'


def _ensure_data_dir():
    TEMPLATES_FILE.parent.mkdir(parents=True, exist_ok=True)


def load_templates():
    """Charger les modeles depuis le fichier JSON. {} si absent/illisible."""
    if not TEMPLATES_FILE.exists():
        return {}
    try:
        with open(TEMPLATES_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_templates(templates):
    """Sauvegarder l'ensemble des modeles dans le fichier JSON."""
    _ensure_data_dir()
    with open(TEMPLATES_FILE, 'w', encoding='utf-8') as f:
        json.dump(templates, f, indent=2, ensure_ascii=False)


def create_template(name, description, attributes):
    """Creer un modele et le persister. Retourne son id."""
    templates = load_templates()
    template_id = uuid.uuid4().hex[:12]
    templates[template_id] = {
        'name': name,
        'description': description,
        'created': datetime.now().isoformat(),
        'attributes': attributes,
    }
    save_templates(templates)
    return template_id


def update_template(template_id, name, description, attributes):
    """Mettre a jour un modele existant. Retourne False s'il n'existe pas."""
    templates = load_templates()
    if template_id not in templates:
        return False
    templates[template_id].update({
        'name': name,
        'description': description,
        'attributes': attributes,
    })
    save_templates(templates)
    return True


def delete_template(template_id):
    """Supprimer un modele. Retourne False s'il n'existait pas."""
    templates = load_templates()
    if template_id not in templates:
        return False
    del templates[template_id]
    save_templates(templates)
    return True
