# -*- coding: utf-8 -*-
"""
Blueprint 'users' — Gestion des utilisateurs Active Directory.
Architecture modulaire pour une meilleure maintenance.
"""
from flask import Blueprint

users_bp = Blueprint('users', __name__, url_prefix='/users')

# Import des routes après création du blueprint pour éviter imports circulaires
from . import list_users, create, delete, update, password, move
