"""
Persistance des modeles utilisateur (attributs par defaut reutilisables
lors de la creation d'un compte AD).
"""

import json
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path

logger = logging.getLogger('user_templates')

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
    except (json.JSONDecodeError, OSError) as e:
        # Ne pas retourner {} en silence : sans trace, une sauvegarde
        # ulterieure ecraserait un fichier simplement illisible et ferait
        # disparaitre tous les modeles sans que personne ne le sache.
        logger.error(f"Modeles utilisateur illisibles ({TEMPLATES_FILE}): {e}")
        return {}


def save_templates(templates):
    """
    Sauvegarder l'ensemble des modeles dans le fichier JSON.

    Ecriture atomique (fichier temporaire + os.replace, meme approche que
    core/updater.py) : une coupure en pleine ecriture laisserait sinon un
    JSON tronque, que load_templates() interpreterait comme « aucun modele »
    — perte silencieuse de la totalite des modeles.
    """
    _ensure_data_dir()
    tmp = TEMPLATES_FILE.with_suffix('.json.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(templates, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, TEMPLATES_FILE)


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
