# -*- coding: utf-8 -*-
"""
Création d'utilisateurs Active Directory.
"""
from flask import render_template, request, redirect, url_for, flash, session
from ldap3 import SUBTREE, MODIFY_ADD, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException
import logging

from . import users_bp
from ..core import (get_ad_connection, is_connected, require_connection,
                   require_permission)
from core.security import escape_ldap_filter, sanitize_dn_component, validate_csrf_token
from core.audit import log_action, ACTIONS
from .validators import UserCreateRequest

logger = logging.getLogger(__name__)


def _home_folder_root():
    """Racine des dossiers personnels si la fonction est disponible pour ce compte."""
    from config import get_config
    from core.folders import get_folder_settings
    from core.granular_permissions import has_permission
    cfg = get_config()
    if not getattr(cfg, 'FEATURE_FOLDERS_ENABLED', False):
        return ''
    if cfg.RBAC_ENABLED and not has_permission(
            session.get('user_groups', []), 'tools:home_folders',
            username=session.get('ad_username'), user_dn=session.get('user_dn')):
        return ''
    return get_folder_settings()['home_root']


def _create_home_folder(conn, user_dn):
    """Dossier personnel du compte créé ; un échec n'annule pas la création."""
    from core.folders import FolderError
    from routes.folders import provision_home_folder
    try:
        path = provision_home_folder(conn, user_dn)
        log_action('home_folder', session.get('ad_username'), {'dn': user_dn, 'path': path},
                   True, request.remote_addr)
        flash(f'Dossier personnel {path} créé.', 'success')
    except FolderError as e:
        log_action('home_folder', session.get('ad_username'), {'dn': user_dn, 'error': str(e)},
                   False, request.remote_addr)
        flash(f'Compte créé, mais le dossier personnel n\'a pas pu l\'être : {e}', 'warning')


def _onboarding_context(conn, base_dn):
    """Paramètres de messagerie, suffixes UPN et groupes de licence pour le formulaire."""
    from core.mailer import is_configured
    from core.onboarding import get_onboarding_settings, get_upn_suffixes, resolve_license_groups
    settings = get_onboarding_settings()
    try:
        suffixes = get_upn_suffixes(conn, base_dn)
        groups = resolve_license_groups(conn, base_dn, settings['license_groups'])
    except Exception as ex:
        logger.warning(f"Paramètres de messagerie indisponibles : {ex}")
        suffixes, groups = [], []
    domain = settings['email_domain'] or next((d for d in suffixes if not d.endswith(('.local', '.lan'))), '')
    return {'settings': settings, 'suffixes': suffixes, 'license_groups': groups,
            'default_domain': domain, 'smtp_ready': is_configured()}


def _validate_identity(conn, base_dn, onboarding, user_req):
    """
    Adresse pro, adresse personnelle, UPN, groupe de licence et mail de
    bienvenue demandés dans le formulaire.

    Returns:
        (identity, erreurs)
    """
    from core.onboarding import address_owner, identity_attributes, valid_email
    errors = []
    pro = (user_req.email or '').strip().lower()
    personal = request.form.get('personal_email', '').strip()
    set_upn = bool(pro) and request.form.get('set_upn') == 'on'
    send_welcome = request.form.get('send_welcome') == 'on'
    license_dn = request.form.get('license_group', '').strip()

    if pro:
        if not valid_email(pro):
            errors.append('Adresse professionnelle invalide.')
        else:
            domain = pro.split('@', 1)[1]
            if set_upn and onboarding['suffixes'] and domain not in onboarding['suffixes']:
                errors.append(f'Le domaine {domain} n\'est pas un suffixe UPN de la forêt '
                              f'({", ".join(onboarding["suffixes"])}). Ajoutez-le dans « Domaines et '
                              'approbations Active Directory » ou décochez « Adresse pro = identifiant ».')
            owner = address_owner(conn, base_dn, pro)
            if owner:
                errors.append(f'L\'adresse {pro} est déjà utilisée par {owner}.')
    if personal:
        if not valid_email(personal):
            errors.append('Adresse personnelle invalide.')
        elif personal.lower() == pro:
            errors.append('L\'adresse personnelle doit être différente de l\'adresse professionnelle.')
    if send_welcome:
        if not personal:
            errors.append('Indiquez l\'adresse personnelle pour envoyer le mail de bienvenue.')
        elif not onboarding['smtp_ready']:
            errors.append('Le mail de bienvenue ne peut pas partir : l\'envoi d\'e-mails n\'est pas '
                          'configuré (Admin › SMTP).')
    if license_dn and license_dn not in [g['dn'] for g in onboarding['license_groups']]:
        errors.append('Groupe de licence inconnu.')

    return {'pro': pro, 'personal': personal, 'set_upn': set_upn, 'send_welcome': send_welcome,
            'license_dn': license_dn,
            'attributes': identity_attributes(pro, personal, set_upn)}, errors


def _after_create(conn, user_dn, user_req, identity):
    """Groupe de licence et mail de bienvenue ; un échec n'annule pas la création."""
    from core.mailer import MailError, send_mail
    from core.onboarding import get_onboarding_settings, render_welcome
    if identity['license_dn']:
        conn.modify(identity['license_dn'], {'member': [(MODIFY_ADD, [user_dn])]})
        if conn.result.get('result') in (0, 68):
            flash('Compte ajouté au groupe de licence Microsoft 365 : la boîte sera créée après la '
                  'prochaine synchronisation.', 'success')
        else:
            flash('Compte créé, mais l\'ajout au groupe de licence a échoué : '
                  f'{conn.result.get("message") or conn.result.get("description")}', 'warning')
    if identity['send_welcome']:
        base_dn = session.get('ad_base_dn', '')
        netbios = next((p.split('=', 1)[1] for p in base_dn.split(',')
                        if p.strip().upper().startswith('DC=')), '').upper()
        login = identity.get('login') or user_req.username
        subject, text, html = render_welcome(get_onboarding_settings(), {
            'prenom': user_req.first_name, 'nom': user_req.last_name,
            'nom_complet': f'{user_req.first_name} {user_req.last_name}'.strip(),
            'identifiant': login, 'login_windows': f'{netbios}\\{user_req.username}',
            'adresse_pro': identity['pro'] or '—', 'mot_de_passe': user_req.password,
        })
        try:
            send_mail(identity['personal'], subject, text, html=html)
            log_action('welcome_mail', session.get('ad_username'),
                       {'dn': user_dn, 'to': identity['personal']}, True, request.remote_addr)
            flash(f'Mail de bienvenue envoyé à {identity["personal"]}.', 'success')
        except MailError as e:
            log_action('welcome_mail', session.get('ad_username'),
                       {'dn': user_dn, 'to': identity['personal'], 'error': str(e)}, False,
                       request.remote_addr)
            flash(f'Compte créé, mais le mail de bienvenue n\'est pas parti : {e}', 'warning')


def _user_templates():
    """Modèles de compte (service, fonction) proposés à la création."""
    try:
        from core.user_templates import load_templates
        return [{'id': k, 'name': v.get('name', k), **(v.get('attributes') or {})}
                for k, v in sorted(load_templates().items(), key=lambda kv: str(kv[1].get('name', '')).lower())]
    except Exception:
        return []


@users_bp.route('/create', methods=['GET', 'POST'])
@require_connection
@require_permission('users:create')
def create_user():
    """Créer un nouvel utilisateur."""
    conn, error = get_ad_connection()
    if not conn:
        flash(f'Erreur: {error}', 'error')
        return redirect(url_for('users.list_users'))

    base_dn = session.get('ad_base_dn', '')
    use_ssl      = session.get('ad_use_ssl', False)
    use_starttls = session.get('ad_starttls', False)
    # La définition du mot de passe requiert un canal chiffré (LDAPS ou STARTTLS)
    can_set_password = use_ssl or use_starttls

    # Récupérer les OUs pour le formulaire
    try:
        conn.search(base_dn, '(objectClass=organizationalUnit)', SUBTREE,
                   attributes=['name', 'distinguishedName'])
        ou_list = [
            {'name': str(e.name.value) if e.name else '', 'dn': str(e.entry_dn)}
            for e in conn.entries
        ]
        ou_list.sort(key=lambda x: x['name'])
    except Exception as ex:
        logger.error(f"Erreur récupération OUs: {ex}")
        ou_list = []

    # OU par défaut = CN=Users du domaine
    default_ou = f"CN=Users,{base_dn}" if base_dn else ''
    home_folder_root = _home_folder_root()
    onboarding = _onboarding_context(conn, base_dn)

    def render():
        return render_template('create_user.html',
                               ous=ou_list, default_ou=default_ou,
                               can_set_password=can_set_password, home_folder_root=home_folder_root,
                               onboarding=onboarding, user_templates=_user_templates(),
                               form=request.form if request.method == 'POST' else {},
                               connected=is_connected())

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('Token CSRF invalide.', 'error')
            return render()

        # Récupérer les valeurs du formulaire
        target_ou = request.form.get('target_ou', '').strip()

        # Appliquer l'OU par défaut AVANT la validation
        if not target_ou:
            target_ou = default_ou

        user_req = UserCreateRequest(
            username=request.form.get('username', '').strip(),
            first_name=request.form.get('first_name', '').strip(),
            last_name=request.form.get('last_name', '').strip(),
            password=request.form.get('password', ''),
            email=request.form.get('email', '').strip(),
            ou=target_ou,
            department=request.form.get('department', '').strip(),
            title=request.form.get('title', '').strip()
        )

        must_change_password = request.form.get('must_change_password') == 'on'

        # Valider les données
        errors = user_req.validate()
        identity = None
        if not errors:
            identity, id_errors = _validate_identity(conn, base_dn, onboarding, user_req)
            errors += id_errors
        if errors:
            for err in errors:
                flash(err, 'error')
            return render()

        # Construire le DN.
        # Le CN doit être échappé (RFC 4514) AVANT d'être interpolé dans le
        # DN : un nom légitime contenant une virgule ou « + » (« O'Brien,
        # John ») produirait sinon un DN malformé — compte créé au mauvais
        # endroit ou création en échec. Les attributs cn/displayName
        # ci-dessous gardent la valeur littérale, non échappée.
        cn = f"{user_req.first_name} {user_req.last_name}".strip() or user_req.username
        user_dn = f"CN={sanitize_dn_component(cn)},{user_req.ou}"

        # Préparer les attributs
        domain = base_dn.replace('DC=', '').replace(',', '.') if base_dn else 'local'
        attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'sAMAccountName': user_req.username,
            'userPrincipalName': f"{user_req.username}@{domain}",
            'cn': cn,
            'displayName': cn,
            'givenName': user_req.first_name,
            'sn': user_req.last_name,
        }
        # Adresse pro (mail, proxyAddresses, UPN) et adresse personnelle
        # (otherMailbox) : reprises par la synchronisation Entra ID.
        attributes.update(identity['attributes'])
        identity['login'] = attributes['userPrincipalName']
        if user_req.department:
            attributes['department'] = user_req.department
        if user_req.title:
            attributes['title'] = user_req.title

        try:
            logger.info(f"Création utilisateur {user_req.username} dans {user_req.ou}")
            success = conn.add(user_dn, attributes=attributes)
            logger.info(f"Résultat création: success={success}, result={conn.result}")

            if success and conn.result.get('result') == 0:
                # Définir le mot de passe (requiert LDAPS/STARTTLS)
                unicode_pwd = f'"{user_req.password}"'.encode('utf-16-le')
                pwd_success = conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})
                logger.info(f"Définition mot de passe: success={pwd_success}, result={conn.result}")

                if pwd_success and conn.result.get('result') == 0:
                    # Activer le compte (userAccountControl=512 = compte normal activé)
                    conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})

                    if must_change_password:
                        conn.modify(user_dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]})

                    log_action(ACTIONS.get('CREATE_USER', 'create_user'),
                               session.get('ad_username'),
                               {'dn': user_dn, 'username': user_req.username},
                               True, request.remote_addr)

                    flash(f'Utilisateur {user_req.username} créé avec succès.', 'success')
                    _after_create(conn, user_dn, user_req, identity)
                    if request.form.get('create_home') == 'on' and home_folder_root:
                        _create_home_folder(conn, user_dn)
                    conn.unbind()
                    return redirect(url_for('users.list_users'))
                else:
                    # Échec mot de passe → supprimer l'entrée incomplète
                    error_desc = conn.result.get('description', '')
                    error_msg  = conn.result.get('message', '')
                    logger.warning(f"Échec mot de passe {user_req.username}: {error_desc} {error_msg}")
                    conn.delete(user_dn)

                    if not can_set_password:
                        flash('⚠️ Connexion sécurisée requise pour définir le mot de passe. '
                              'Déconnectez-vous et reconnectez via LDAPS (port 636) ou STARTTLS.', 'warning')
                    else:
                        flash(f'Erreur lors de la définition du mot de passe : {error_desc}. {error_msg}', 'error')
            else:
                error_desc = conn.result.get('description', 'Erreur inconnue')
                error_msg  = conn.result.get('message', '')
                flash(f'Erreur création utilisateur : {error_desc}. {error_msg}', 'error')

        except LDAPException as ex:
            logger.error(f"Erreur LDAP création: {ex}")
            flash(f'Erreur LDAP : {str(ex)}', 'error')
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

        return render()

    # GET
    conn.unbind()
    return render()


@users_bp.route('/api/address-suggestion')
@require_connection
@require_permission('users:create')
def address_suggestion():
    """
    Adresse professionnelle proposée (première libre selon le format
    configuré) ou, avec ?address=, disponibilité d'une adresse saisie.
    """
    from flask import jsonify
    from core.onboarding import (address_owner, get_onboarding_settings, suggest_address,
                                 valid_email)
    conn, error = get_ad_connection()
    if not conn:
        return jsonify({'success': False, 'error': error}), 502
    base_dn = session.get('ad_base_dn', '')
    try:
        address = request.args.get('address', '').strip().lower()
        if address:
            if not valid_email(address):
                return jsonify({'success': True, 'address': address, 'valid': False, 'owner': None})
            return jsonify({'success': True, 'address': address, 'valid': True,
                            'owner': address_owner(conn, base_dn, address)})
        domain = request.args.get('domain', '').strip().lower()
        settings = get_onboarding_settings()
        suggestion = suggest_address(conn, base_dn, request.args.get('first', ''),
                                     request.args.get('last', ''), domain, settings['pattern'])
        return jsonify({'success': True, 'address': suggestion, 'valid': bool(suggestion), 'owner': None})
    finally:
        conn.unbind()


@users_bp.route('/settings/messagerie', methods=['GET', 'POST'])
@require_connection
@require_permission('admin:settings')
def onboarding_settings():
    """Domaine et format des adresses pro, groupes de licence, modèle du mail de bienvenue."""
    from core.mailer import MailError, is_configured, send_mail
    from core.onboarding import (DEFAULT_BODY, DEFAULT_SUBJECT, PATTERNS, PLACEHOLDERS,
                                 OnboardingError, build_address, get_onboarding_settings,
                                 get_upn_suffixes, render_welcome, resolve_license_groups,
                                 save_onboarding_settings, valid_email)
    base_dn = session.get('ad_base_dn', '')
    settings = get_onboarding_settings()

    if request.method == 'POST':
        if request.form.get('action') == 'test':
            to = request.form.get('test_to', '').strip()
            domain = settings['email_domain'] or 'domaine.fr'
            values = {'prenom': 'Jean', 'nom': 'Dupont', 'nom_complet': 'Jean Dupont',
                      'identifiant': build_address('Jean', 'Dupont', domain, settings['pattern']),
                      'login_windows': 'DOMAINE\\jdupont',
                      'adresse_pro': build_address('Jean', 'Dupont', domain, settings['pattern']),
                      'mot_de_passe': 'Exemple-1234!'}
            try:
                if not valid_email(to):
                    raise MailError('Adresse de test invalide.')
                subject, text, html = render_welcome(settings, values)
                send_mail(to, '[Exemple] ' + subject, text, html=html)
                flash(f'Exemple de mail de bienvenue envoyé à {to}.', 'success')
            except MailError as e:
                flash(str(e), 'error')
            return redirect(url_for('users.onboarding_settings'))
        try:
            save_onboarding_settings(request.form.get('email_domain', ''), request.form.get('pattern', ''),
                                     request.form.get('set_upn') == 'on',
                                     request.form.get('license_groups', ''),
                                     request.form.get('welcome_subject', ''),
                                     request.form.get('welcome_body', ''))
            log_action('onboarding_settings', session.get('ad_username'), {}, True, request.remote_addr)
            flash('Paramètres de messagerie enregistrés.', 'success')
            return redirect(url_for('users.onboarding_settings'))
        except OnboardingError as e:
            flash(str(e), 'error')
            settings = dict(settings, email_domain=request.form.get('email_domain', ''),
                            pattern=request.form.get('pattern', settings['pattern']),
                            license_groups=request.form.get('license_groups', '').split('\n'),
                            welcome_subject=request.form.get('welcome_subject', ''),
                            welcome_body=request.form.get('welcome_body', ''))

    suffixes, groups = [], []
    conn, _ = get_ad_connection()
    if conn:
        try:
            suffixes = get_upn_suffixes(conn, base_dn)
            groups = resolve_license_groups(conn, base_dn, settings['license_groups'])
        finally:
            conn.unbind()
    found = {g['name'] for g in groups}
    missing = [g for g in settings['license_groups'] if g.strip() and g not in found]
    try:
        preview = render_welcome(settings, {
            'prenom': 'Jean', 'nom': 'Dupont', 'nom_complet': 'Jean Dupont',
            'identifiant': build_address('Jean', 'Dupont', settings['email_domain'] or 'domaine.fr',
                                         settings['pattern']),
            'login_windows': 'DOMAINE\\jdupont',
            'adresse_pro': build_address('Jean', 'Dupont', settings['email_domain'] or 'domaine.fr',
                                         settings['pattern']),
            'mot_de_passe': 'Exemple-1234!'})
    except (KeyError, ValueError, IndexError):
        preview = None
    return render_template('onboarding_settings.html', settings=settings, suffixes=suffixes,
                           patterns=PATTERNS, placeholders=PLACEHOLDERS, missing_groups=missing,
                           preview=preview, smtp_ready=is_configured(),
                           default_subject=DEFAULT_SUBJECT, default_body=DEFAULT_BODY,
                           connected=is_connected())
