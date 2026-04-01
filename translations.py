"""
Module de traduction multi-langue pour l'interface Web Active Directory.
Support Francais (fr) et Anglais (en).
"""

TRANSLATIONS = {
    'fr': {
        # Navigation
        'nav_dashboard': 'Tableau de bord',
        'nav_users': 'Utilisateurs',
        'nav_groups': 'Groupes',
        'nav_computers': 'Ordinateurs',
        'nav_ous': 'Unites d\'org.',
        'nav_tree': 'Arborescence',
        'nav_audit': 'Audit',
        'nav_disconnect': 'Deconnexion',
        'nav_connect': 'Connexion AD',
        'nav_home': 'Accueil',
        'nav_update': 'Mise a jour',
        'nav_search': 'Recherche',
        'nav_alerts': 'Alertes',
        'nav_templates': 'Modeles',
        'nav_expiring': 'Expirations',
        'nav_favorites': 'Favoris',

        # Dashboard
        'dashboard_title': 'Tableau de bord',
        'dashboard_total_users': 'Total utilisateurs',
        'dashboard_active_users': 'Utilisateurs actifs',
        'dashboard_disabled_users': 'Utilisateurs desactives',
        'dashboard_total_groups': 'Total groupes',
        'dashboard_empty_groups': 'Groupes vides',
        'dashboard_total_ous': 'Total OUs',
        'dashboard_recent_activity': 'Activite recente',
        'dashboard_quick_actions': 'Actions rapides',
        'dashboard_statistics': 'Statistiques',

        # Users
        'users_title': 'Utilisateurs',
        'users_search': 'Rechercher un utilisateur...',
        'users_create': 'Nouvel utilisateur',
        'users_import': 'Importer',
        'users_export': 'Exporter',
        'users_bulk': 'Operations en masse',
        'user_name': 'Nom',
        'user_login': 'Identifiant',
        'user_email': 'Email',
        'user_department': 'Service',
        'user_status': 'Statut',
        'user_actions': 'Actions',
        'user_edit': 'Modifier',
        'user_delete': 'Supprimer',
        'user_duplicate': 'Dupliquer',
        'user_active': 'Actif',
        'user_disabled': 'Desactive',

        # Groups
        'groups_title': 'Groupes',
        'groups_search': 'Rechercher un groupe...',
        'groups_create': 'Nouveau groupe',
        'group_name': 'Nom',
        'group_description': 'Description',
        'group_members': 'Membres',

        # Computers
        'computers_title': 'Ordinateurs',
        'computers_search': 'Rechercher un ordinateur...',
        'computer_name': 'Nom',
        'computer_os': 'Systeme d\'exploitation',
        'computer_dns': 'Nom DNS',
        'computer_status': 'Statut',
        'computer_move': 'Deplacer',
        'computer_enable': 'Activer',
        'computer_disable': 'Desactiver',

        # Common
        'search': 'Rechercher',
        'save': 'Enregistrer',
        'cancel': 'Annuler',
        'delete': 'Supprimer',
        'edit': 'Modifier',
        'create': 'Creer',
        'back': 'Retour',
        'yes': 'Oui',
        'no': 'Non',
        'loading': 'Chargement...',
        'no_results': 'Aucun resultat',
        'success': 'Succes',
        'error': 'Erreur',
        'warning': 'Attention',
        'info': 'Information',
        'confirm_delete': 'Confirmer la suppression ?',
        'results_count': '{count} resultat(s)',
        'page': 'Page',
        'of': 'sur',
        'previous': 'Precedent',
        'next': 'Suivant',

        # Forms
        'form_required': 'Champs obligatoires',
        'form_password': 'Mot de passe',
        'form_password_confirm': 'Confirmer le mot de passe',
        'form_generate_password': 'Generer',
        'form_show_password': 'Voir',

        # Alerts
        'alerts_title': 'Alertes',
        'alerts_expiring_accounts': 'Comptes expirants',
        'alerts_locked_accounts': 'Comptes verrouilles',
        'alerts_password_expiring': 'Mots de passe expirants',
        'alerts_inactive_accounts': 'Comptes inactifs',

        # Search
        'global_search': 'Recherche globale',
        'search_placeholder': 'Rechercher dans tous les objets...',
        'search_users': 'Utilisateurs',
        'search_groups': 'Groupes',
        'search_computers': 'Ordinateurs',
        'search_ous': 'Unites d\'organisation',

        # Templates
        'templates_title': 'Modeles d\'utilisateurs',
        'template_name': 'Nom du modele',
        'template_create': 'Creer un modele',
        'template_apply': 'Appliquer',

        # Export
        'export_pdf': 'Exporter en PDF',
        'export_csv': 'Exporter en CSV',
        'export_json': 'Exporter en JSON',

        # Favorites
        'favorites_title': 'Favoris',
        'favorites_add': 'Ajouter aux favoris',
        'favorites_remove': 'Retirer des favoris',

        # API
        'api_documentation': 'Documentation API',
        'api_key': 'Cle API',
        'api_generate_key': 'Generer une cle',
    },

    'en': {
        # Navigation
        'nav_dashboard': 'Dashboard',
        'nav_users': 'Users',
        'nav_groups': 'Groups',
        'nav_computers': 'Computers',
        'nav_ous': 'Org. Units',
        'nav_tree': 'Tree View',
        'nav_audit': 'Audit',
        'nav_disconnect': 'Disconnect',
        'nav_connect': 'AD Connect',
        'nav_home': 'Home',
        'nav_update': 'Update',
        'nav_search': 'Search',
        'nav_alerts': 'Alerts',
        'nav_templates': 'Templates',
        'nav_expiring': 'Expiring',
        'nav_favorites': 'Favorites',

        # Dashboard
        'dashboard_title': 'Dashboard',
        'dashboard_total_users': 'Total Users',
        'dashboard_active_users': 'Active Users',
        'dashboard_disabled_users': 'Disabled Users',
        'dashboard_total_groups': 'Total Groups',
        'dashboard_empty_groups': 'Empty Groups',
        'dashboard_total_ous': 'Total OUs',
        'dashboard_recent_activity': 'Recent Activity',
        'dashboard_quick_actions': 'Quick Actions',
        'dashboard_statistics': 'Statistics',

        # Users
        'users_title': 'Users',
        'users_search': 'Search user...',
        'users_create': 'New User',
        'users_import': 'Import',
        'users_export': 'Export',
        'users_bulk': 'Bulk Operations',
        'user_name': 'Name',
        'user_login': 'Login',
        'user_email': 'Email',
        'user_department': 'Department',
        'user_status': 'Status',
        'user_actions': 'Actions',
        'user_edit': 'Edit',
        'user_delete': 'Delete',
        'user_duplicate': 'Duplicate',
        'user_active': 'Active',
        'user_disabled': 'Disabled',

        # Groups
        'groups_title': 'Groups',
        'groups_search': 'Search group...',
        'groups_create': 'New Group',
        'group_name': 'Name',
        'group_description': 'Description',
        'group_members': 'Members',

        # Computers
        'computers_title': 'Computers',
        'computers_search': 'Search computer...',
        'computer_name': 'Name',
        'computer_os': 'Operating System',
        'computer_dns': 'DNS Name',
        'computer_status': 'Status',
        'computer_move': 'Move',
        'computer_enable': 'Enable',
        'computer_disable': 'Disable',

        # Common
        'search': 'Search',
        'save': 'Save',
        'cancel': 'Cancel',
        'delete': 'Delete',
        'edit': 'Edit',
        'create': 'Create',
        'back': 'Back',
        'yes': 'Yes',
        'no': 'No',
        'loading': 'Loading...',
        'no_results': 'No results',
        'success': 'Success',
        'error': 'Error',
        'warning': 'Warning',
        'info': 'Information',
        'confirm_delete': 'Confirm deletion?',
        'results_count': '{count} result(s)',
        'page': 'Page',
        'of': 'of',
        'previous': 'Previous',
        'next': 'Next',

        # Forms
        'form_required': 'Required fields',
        'form_password': 'Password',
        'form_password_confirm': 'Confirm password',
        'form_generate_password': 'Generate',
        'form_show_password': 'Show',

        # Alerts
        'alerts_title': 'Alerts',
        'alerts_expiring_accounts': 'Expiring Accounts',
        'alerts_locked_accounts': 'Locked Accounts',
        'alerts_password_expiring': 'Expiring Passwords',
        'alerts_inactive_accounts': 'Inactive Accounts',

        # Search
        'global_search': 'Global Search',
        'search_placeholder': 'Search all objects...',
        'search_users': 'Users',
        'search_groups': 'Groups',
        'search_computers': 'Computers',
        'search_ous': 'Organizational Units',

        # Templates
        'templates_title': 'User Templates',
        'template_name': 'Template Name',
        'template_create': 'Create Template',
        'template_apply': 'Apply',

        # Export
        'export_pdf': 'Export to PDF',
        'export_csv': 'Export to CSV',
        'export_json': 'Export to JSON',

        # Favorites
        'favorites_title': 'Favorites',
        'favorites_add': 'Add to favorites',
        'favorites_remove': 'Remove from favorites',

        # API
        'api_documentation': 'API Documentation',
        'api_key': 'API Key',
        'api_generate_key': 'Generate Key',
    }
}


def get_translation(key, lang='fr'):
    """Obtenir une traduction pour une cle donnee."""
    return TRANSLATIONS.get(lang, TRANSLATIONS['fr']).get(key, key)


def get_all_translations(lang='fr'):
    """Obtenir toutes les traductions pour une langue."""
    return TRANSLATIONS.get(lang, TRANSLATIONS['fr'])


class Translator:
    """Classe pour gerer les traductions dans les templates."""

    def __init__(self, lang='fr'):
        self.lang = lang
        self.translations = TRANSLATIONS.get(lang, TRANSLATIONS['fr'])

    def __call__(self, key, **kwargs):
        """Traduire une cle avec des arguments optionnels."""
        text = self.translations.get(key, key)
        if kwargs:
            try:
                text = text.format(**kwargs)
            except KeyError:
                pass
        return text

    def set_language(self, lang):
        """Changer la langue."""
        self.lang = lang
        self.translations = TRANSLATIONS.get(lang, TRANSLATIONS['fr'])
