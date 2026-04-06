"""
Blueprint 'tools' — LAPS, BitLocker, comptes, mots de passe, sauvegardes.
"""
from flask import Blueprint

tools_bp = Blueprint('\1', __name__, url_prefix='/(tools)')

# Enregistrement des routes (imports en bas pour éviter les imports circulaires)
from . import laps, bitlocker, accounts, password, backups, misc  # noqa: E402, F401

