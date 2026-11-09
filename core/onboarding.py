"""
Arrivée d'un utilisateur : adresse professionnelle synchronisée avec
Microsoft Entra ID, groupe de licence Microsoft 365 et mail de bienvenue
envoyé sur l'adresse personnelle.

Entra Connect (ou Cloud Sync) reprend de l'AD :
- userPrincipalName : identifiant de connexion Microsoft 365. Son suffixe
  (@domaine.fr) doit être un suffixe UPN déclaré dans la forêt et un domaine
  vérifié dans Microsoft 365, sinon le compte arrive en @….onmicrosoft.com ;
- mail et proxyAddresses (« SMTP: » en majuscules = adresse principale) :
  adresse de la boîte une fois la licence attribuée.

La licence est attribuée par Entra ID aux membres d'un groupe (attribution
par groupe) : l'application ajoute seulement le compte au groupe choisi.
"""
import re
import unicodedata
from html import escape
from string import Formatter

PATTERNS = {
    'prenom.nom': 'prenom.nom',
    'p.nom': 'p.nom (initiale du prénom)',
    'prenomnom': 'prenomnom',
    'nom.prenom': 'nom.prenom',
    'prenom-nom': 'prenom-nom',
}

DEFAULT_SUBJECT = 'Bienvenue {prenom} — vos accès informatiques'
DEFAULT_BODY = """Bonjour {prenom},

Votre compte informatique a été créé.

Identifiant de connexion : {identifiant}
Adresse e-mail professionnelle : {adresse_pro}
Mot de passe provisoire : {mot_de_passe}

Vous devrez choisir un nouveau mot de passe lors de votre première connexion.
Votre boîte e-mail professionnelle sera disponible dans les heures qui suivent,
le temps de la synchronisation avec Microsoft 365.

Ce message contient votre mot de passe provisoire : supprimez-le dès que vous
l'avez changé.

Cordialement,
Le service informatique
"""

PLACEHOLDERS = {
    'prenom': 'Prénom',
    'nom': 'Nom',
    'nom_complet': 'Prénom et nom',
    'identifiant': 'Identifiant de connexion (adresse pro si elle sert d\'UPN, sinon UPN)',
    'login_windows': 'Ouverture de session Windows (DOMAINE\\login)',
    'adresse_pro': 'Adresse e-mail professionnelle',
    'mot_de_passe': 'Mot de passe provisoire',
}

_EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+\'-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$')
_DOMAIN_RE = re.compile(r'^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$')


class OnboardingError(Exception):
    """Erreur présentable à l'utilisateur."""


def valid_email(value):
    value = (value or '').strip()
    return bool(_EMAIL_RE.match(value)) and len(value) <= 254 and '..' not in value


# --- Paramètres --------------------------------------------------------------

def get_onboarding_settings():
    from core.settings_manager import load_settings
    raw = load_settings().get('onboarding') or {}
    pattern = raw.get('pattern') if raw.get('pattern') in PATTERNS else 'prenom.nom'
    groups = [g for g in (raw.get('license_groups') or []) if isinstance(g, str) and g.strip()]
    return {
        'email_domain': (raw.get('email_domain') or '').strip().lower(),
        'pattern': pattern,
        'set_upn': raw.get('set_upn', True) is not False,
        'license_groups': groups,
        'welcome_subject': raw.get('welcome_subject') or DEFAULT_SUBJECT,
        'welcome_body': raw.get('welcome_body') or DEFAULT_BODY,
    }


def save_onboarding_settings(email_domain, pattern, set_upn, license_groups_text,
                             welcome_subject, welcome_body):
    from core.settings_manager import set_setting
    email_domain = (email_domain or '').strip().lower().lstrip('@')
    if email_domain and not _DOMAIN_RE.match(email_domain):
        raise OnboardingError('Domaine de messagerie invalide.')
    if pattern not in PATTERNS:
        raise OnboardingError('Format d\'adresse inconnu.')
    groups = []
    for line in (license_groups_text or '').replace('\r', '').split('\n'):
        line = line.strip()
        if line and line not in groups:
            if len(line) > 256 or any(c in line for c in '()*\x00'):
                raise OnboardingError(f'Nom de groupe invalide : {line}')
            groups.append(line)
    for text in (welcome_subject, welcome_body):
        check_template(text or '')
    if '\n' in (welcome_subject or '') or len(welcome_subject or '') > 200:
        raise OnboardingError('Objet du mail invalide (une ligne, 200 caractères au plus).')
    set_setting('onboarding', {
        'email_domain': email_domain, 'pattern': pattern, 'set_upn': bool(set_upn),
        'license_groups': groups,
        'welcome_subject': (welcome_subject or '').strip() or DEFAULT_SUBJECT,
        'welcome_body': (welcome_body or '').replace('\r\n', '\n').strip() + '\n' if welcome_body else DEFAULT_BODY,
    })
    return get_onboarding_settings()


# --- Modèle du mail ----------------------------------------------------------

def check_template(text):
    """Refuse les champs inconnus ou les formats ({x.attr}, {x[0]}, {x!r})."""
    try:
        fields = list(Formatter().parse(text))
    except ValueError as e:
        raise OnboardingError(f'Modèle invalide : {e}')
    for _, field, spec, conversion in fields:
        if field is None:
            continue
        if field not in PLACEHOLDERS or spec or conversion:
            raise OnboardingError(
                f'Champ inconnu dans le modèle : {{{field}}}. Champs disponibles : '
                + ', '.join('{' + k + '}' for k in PLACEHOLDERS))


def render_welcome(settings, values):
    """
    (objet, texte, html) du mail de bienvenue.

    Seuls les champs de PLACEHOLDERS sont remplacés ; les valeurs sont
    échappées dans la version HTML.
    """
    safe = {k: str(values.get(k, '')) for k in PLACEHOLDERS}
    subject = settings['welcome_subject'].format_map(safe).replace('\n', ' ')
    text = settings['welcome_body'].format_map(safe)
    html_values = {k: f'<strong>{escape(v)}</strong>' if k in ('identifiant', 'adresse_pro', 'mot_de_passe')
                   else escape(v) for k, v in safe.items()}
    body = escape(settings['welcome_body'], quote=False)
    # Les accolades ne sont pas touchées par escape : format_map reste possible.
    html = ('<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222">'
            + body.format_map(html_values).replace('\n', '<br>\n') + '</body></html>')
    return subject, text, html


# --- Adresse professionnelle -------------------------------------------------

def _ascii(value):
    value = unicodedata.normalize('NFKD', value or '')
    value = ''.join(c for c in value if not unicodedata.combining(c))
    value = value.replace('æ', 'ae').replace('Æ', 'AE').replace('œ', 'oe').replace('Œ', 'OE')
    return value.lower()


def local_part(value):
    """Partie d'adresse : minuscules sans accents, espaces → tirets."""
    value = _ascii(value).replace("'", '').replace('’', '')
    value = re.sub(r'[\s_]+', '-', value.strip())
    value = re.sub(r'[^a-z0-9.-]', '', value)
    value = re.sub(r'([.-])[.-]+', r'\1', value).strip('.-')
    return value


def build_address(first, last, domain, pattern='prenom.nom'):
    first, last = local_part(first), local_part(last)
    if not first or not last or not domain:
        return ''
    local = {
        'prenom.nom': f'{first}.{last}',
        'p.nom': f'{first[0]}.{last}',
        'prenomnom': f'{first}{last}'.replace('-', ''),
        'nom.prenom': f'{last}.{first}',
        'prenom-nom': f'{first}-{last}',
    }.get(pattern, f'{first}.{last}')
    return f'{local[:64]}@{domain.lower()}'


def get_upn_suffixes(conn, base_dn):
    """
    Suffixes UPN utilisables : domaine DNS de la base, plus les suffixes
    déclarés dans la forêt (Domaines et approbations Active Directory,
    attribut uPNSuffixes de CN=Partitions).
    """
    from ldap3 import BASE
    suffixes = []
    dns = '.'.join(p.split('=', 1)[1] for p in base_dn.split(',') if p.strip().upper().startswith('DC='))
    config_nc = None
    try:
        info = conn.server.info
        if info and info.other:
            config_nc = (info.other.get('configurationNamingContext') or [None])[0]
    except Exception:
        config_nc = None
    if not config_nc and dns:
        config_nc = 'CN=Configuration,' + ','.join(f'DC={p}' for p in dns.split('.'))
    if config_nc:
        try:
            conn.search(f'CN=Partitions,{config_nc}', '(objectClass=*)', BASE, attributes=['uPNSuffixes'])
            if conn.entries and 'uPNSuffixes' in conn.entries[0]:
                suffixes = [str(s).lower() for s in conn.entries[0].uPNSuffixes.values]
        except Exception:
            suffixes = []
    if dns and dns.lower() not in suffixes:
        suffixes.append(dns.lower())
    return sorted(set(suffixes), key=lambda s: (s.endswith('.local') or s.endswith('.lan'), s))


def address_owner(conn, base_dn, address, exclude_dn=None):
    """DN du compte qui utilise déjà address (mail, UPN ou proxyAddresses), sinon None."""
    from ldap3 import SUBTREE
    from core.security import escape_ldap_filter
    safe = escape_ldap_filter(address)
    conn.search(base_dn, f'(|(mail={safe})(userPrincipalName={safe})(proxyAddresses=smtp:{safe}))',
                SUBTREE, attributes=['cn'], size_limit=5)
    for entry in conn.entries:
        if not exclude_dn or entry.entry_dn.lower() != exclude_dn.lower():
            return entry.entry_dn
    return None


def suggest_address(conn, base_dn, first, last, domain, pattern):
    """Première adresse libre : prenom.nom@, puis prenom.nom2@, prenom.nom3@…"""
    address = build_address(first, last, domain, pattern)
    if not address:
        return ''
    local, _, dom = address.partition('@')
    for n in range(1, 50):
        candidate = address if n == 1 else f'{local}{n}@{dom}'
        if not address_owner(conn, base_dn, candidate):
            return candidate
    return ''


def identity_attributes(pro_email, personal_email, set_upn):
    """Attributs AD à poser à la création (ou en modification)."""
    attrs = {}
    if pro_email:
        attrs['mail'] = pro_email
        attrs['proxyAddresses'] = [f'SMTP:{pro_email}']
        if set_upn:
            attrs['userPrincipalName'] = pro_email
    if personal_email:
        attrs['otherMailbox'] = [personal_email]
    return attrs


def resolve_license_groups(conn, base_dn, names):
    """[{name, dn}] des groupes de licence configurés qui existent."""
    from ldap3 import SUBTREE
    from core.security import escape_ldap_filter
    groups = []
    for name in names:
        safe = escape_ldap_filter(name)
        conn.search(base_dn, f'(&(objectClass=group)(|(sAMAccountName={safe})(cn={safe})))', SUBTREE,
                    attributes=['cn'], size_limit=2)
        if len(conn.entries) == 1:
            groups.append({'name': name, 'dn': conn.entries[0].entry_dn})
    return groups
