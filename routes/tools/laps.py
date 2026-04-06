"""Routes LAPS (Local Administrator Password Solution)."""
from flask import render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPAttributeError

from . import tools_bp
from ..core import get_ad_connection, decode_ldap_value, is_connected, require_connection, require_permission
from security import escape_ldap_filter


@tools_bp.route('/laps')
@require_connection
@require_permission('admin')
def laps_passwords():
    """Afficher les mots de passe LAPS (redirige vers la gestion complète)."""
    return redirect(url_for('laps_management.laps_dashboard'))
