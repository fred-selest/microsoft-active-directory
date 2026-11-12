"""
Départ d'un collaborateur : désactivation du compte, retrait des groupes,
déplacement, et rapport permettant de revenir en arrière.

Chaque étape est indépendante : un échec est noté dans le rapport et les
étapes suivantes continuent. Rien n'est supprimé — ni le compte, ni son
dossier personnel, ni sa boîte aux lettres : un départ doit pouvoir être
annulé (erreur de personne, retour du collaborateur).

Le rapport (data/offboarding/) garde l'état d'origine : unité
d'organisation, groupes, description. « Annuler le départ » s'en sert pour
réactiver le compte, le remettre à sa place et dans ses groupes. Le mot de
passe réinitialisé et la boîte convertie ne sont pas rétablis.
"""
import json
import logging
import os
import re
from datetime import datetime

logger = logging.getLogger('offboarding')

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'offboarding')
_REPORT_RE = re.compile(r'^\d{8}-\d{6}-[A-Za-z0-9._-]{1,64}$')

UF_DISABLED = 0x2

STEPS = {
    'disable': 'Désactiver le compte',
    'password': 'Remplacer le mot de passe par un mot de passe aléatoire',
    'groups': 'Retirer le compte de tous ses groupes (licences Microsoft 365 comprises)',
    'hide': 'Masquer le compte dans le carnet d\'adresses',
    'mailbox': 'Convertir sa boîte aux lettres en boîte partagée (le courrier est conservé sans licence)',
    'move': 'Déplacer le compte dans l\'unité d\'organisation des départs',
}
DEFAULT_STEPS = ('disable', 'password', 'groups', 'hide', 'move')


class OffboardingError(Exception):
    """Erreur présentable à l'utilisateur."""


def _val(entry, attr, default=''):
    if attr in entry:
        value = getattr(entry, attr).value
        return default if value in (None, []) else value
    return default


def _values(entry, attr):
    return [str(v) for v in getattr(entry, attr).values] if attr in entry else []


def _read(conn, base_dn, dn):
    from ldap3 import BASE
    if not dn or not dn.lower().endswith(base_dn.lower()):
        raise OffboardingError('Compte hors du domaine.')
    conn.search(dn, '(&(objectClass=user)(objectCategory=person))', BASE,
                attributes=['sAMAccountName', 'displayName', 'cn', 'userPrincipalName', 'mail', 'memberOf',
                            'userAccountControl', 'description', 'adminCount', 'homeDirectory', 'manager'])
    if not conn.entries:
        raise OffboardingError('Utilisateur introuvable.')
    return conn.entries[0]


def _name(dn):
    return dn.split(',')[0].split('=', 1)[-1]


def plan(conn, base_dn, dn, current_user=''):
    """Ce que le départ changera, pour l'aperçu avant confirmation."""
    entry = _read(conn, base_dn, dn)
    sam = str(_val(entry, 'sAMAccountName'))
    groups = sorted(_values(entry, 'memberOf'), key=str.lower)
    uac = int(_val(entry, 'userAccountControl', 512) or 512)
    warnings = []
    if int(_val(entry, 'adminCount', 0) or 0) == 1:
        warnings.append('Ce compte est membre d\'un groupe d\'administration protégé.')
    if current_user and sam.lower() == current_user.split('\\')[-1].split('@')[0].lower():
        warnings.append('C\'est le compte avec lequel vous êtes connecté.')
    if sam.lower() in ('administrateur', 'administrator', 'krbtgt'):
        raise OffboardingError('Ce compte intégré ne peut pas faire l\'objet d\'un départ.')
    return {'dn': entry.entry_dn, 'sam': sam,
            'name': str(_val(entry, 'displayName') or _val(entry, 'cn') or sam),
            'upn': str(_val(entry, 'userPrincipalName')), 'mail': str(_val(entry, 'mail')),
            'enabled': not uac & UF_DISABLED, 'uac': uac,
            'description': (_values(entry, 'description') or [''])[0],
            'groups': [{'dn': g, 'name': _name(g)} for g in groups],
            'home': str(_val(entry, 'homeDirectory')), 'ou': entry.entry_dn.split(',', 1)[1],
            'warnings': warnings}


def _result(conn):
    return conn.result.get('result') == 0, \
        str(conn.result.get('message') or conn.result.get('description') or 'erreur LDAP')


def _try(conn, call, *args, **kwargs):
    """Écriture LDAP qui ne lève jamais : (ok, détail). Une étape en échec n'arrête pas les autres."""
    try:
        call(*args, **kwargs)
        return _result(conn)
    except Exception as e:      # ldap3 lève p. ex. LDAPAttributeError si l'attribut est absent du schéma
        logger.warning('Départ : écriture refusée (%s)', e)
        return False, str(e)


def execute(conn, base_dn, dn, steps, by, target_ou='', can_set_password=True, mailbox_delegate=''):
    """
    Exécute le départ. Returns le rapport (dict), déjà enregistré.

    steps : sous-ensemble des clés de STEPS.
    """
    from ldap3 import MODIFY_DELETE, MODIFY_REPLACE
    from ldap3.utils.dn import safe_rdn
    info = plan(conn, base_dn, dn, by)
    steps = [s for s in STEPS if s in steps]
    if not steps:
        raise OffboardingError('Choisissez au moins une action.')
    if 'move' in steps:
        if not target_ou or not target_ou.lower().endswith(base_dn.lower()):
            raise OffboardingError('Choisissez l\'unité d\'organisation des départs.')
        if target_ou.lower() == info['ou'].lower():
            steps.remove('move')
    now = datetime.now()
    report = {'date': now.strftime('%Y-%m-%d %H:%M:%S'), 'by': by, 'sam': info['sam'], 'name': info['name'],
              'upn': info['upn'], 'original': {'dn': info['dn'], 'ou': info['ou'], 'enabled': info['enabled'],
                                               'description': info['description'],
                                               'groups': [g['dn'] for g in info['groups']]},
              'home': info['home'], 'steps': [], 'undone': None}
    current_dn = info['dn']

    def note(step, ok, detail=''):
        report['steps'].append({'step': step, 'label': STEPS[step], 'ok': bool(ok), 'detail': detail})

    if 'disable' in steps:
        stamp = f'Départ le {now.strftime("%d/%m/%Y")} (par {by.split(chr(92))[-1]})'
        description = f'{stamp} — {info["description"]}'[:1024] if info['description'] else stamp
        ok, detail = _try(conn, conn.modify, current_dn, {
            'userAccountControl': [(MODIFY_REPLACE, [info['uac'] | UF_DISABLED])],
            'description': [(MODIFY_REPLACE, [description])]})
        note('disable', ok, '' if ok else detail)

    if 'password' in steps:
        if not can_set_password:
            note('password', False, 'Connexion LDAP non chiffrée : reconnectez-vous en LDAPS pour changer un mot de passe.')
        else:
            from core.password_generator import generate_ad_password
            password = generate_ad_password('very_high')
            ok, detail = _try(conn, conn.modify, current_dn,
                              {'unicodePwd': [(MODIFY_REPLACE, [f'"{password}"'.encode('utf-16-le')])]})
            note('password', ok, '' if ok else detail)    # le mot de passe n'est conservé nulle part

    if 'groups' in steps:
        removed, failed = [], []
        for group in info['groups']:
            ok, _ = _try(conn, conn.modify, group['dn'], {'member': [(MODIFY_DELETE, [current_dn])]})
            (removed if ok else failed).append(group['name'])
        report['removed_groups'] = removed
        note('groups', not failed, f'{len(removed)} groupe(s) retiré(s)'
             + (f' ; échec pour : {", ".join(failed)}' if failed else ''))

    if 'hide' in steps:
        ok, detail = _try(conn, conn.modify, current_dn,
                          {'msExchHideFromAddressLists': [(MODIFY_REPLACE, ['TRUE'])]})
        report['hidden'] = ok
        note('hide', ok, '' if ok else 'Attribut absent de cet annuaire (schéma Exchange non étendu) : '
                                       'masquez le compte depuis Microsoft 365.')

    if 'mailbox' in steps:
        from core import exchange as ex
        try:
            address = ex.convert_to_shared(info['upn'] or info['mail'])
            detail = f'{address} est maintenant une boîte partagée'
            if mailbox_delegate:
                _, delegate = ex.grant(address, mailbox_delegate, True, False)
                detail += f', accessible à {delegate}'
            note('mailbox', True, detail)
        except ex.ExchangeError as e:
            note('mailbox', False, str(e))

    if 'move' in steps:
        rdn = '+'.join(safe_rdn(current_dn))
        ok, detail = _try(conn, conn.modify_dn, current_dn, rdn, new_superior=target_ou)
        if ok:
            current_dn = f'{rdn},{target_ou}'
        note('move', ok, target_ou if ok else detail)

    report['dn'] = current_dn
    report['id'] = _save(report, now)
    return report


def _save(report, now):
    os.makedirs(REPORT_DIR, exist_ok=True)
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', report['sam'])[:64] or 'compte'
    ident = f'{now.strftime("%Y%m%d-%H%M%S")}-{safe}'
    with open(os.path.join(REPORT_DIR, ident + '.json'), 'w', encoding='utf-8') as f:
        json.dump(dict(report, id=ident), f, ensure_ascii=False, indent=2)
    return ident


def load(report_id):
    if not _REPORT_RE.match(report_id or ''):
        raise OffboardingError('Rapport inconnu.')
    try:
        with open(os.path.join(REPORT_DIR, report_id + '.json'), encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        raise OffboardingError('Rapport introuvable.')


def list_reports(sam=None):
    """Rapports de départ, le plus récent d'abord (filtrés sur un identifiant si donné)."""
    if not os.path.isdir(REPORT_DIR):
        return []
    reports = []
    for fname in sorted(os.listdir(REPORT_DIR), reverse=True):
        if not fname.endswith('.json') or not _REPORT_RE.match(fname[:-5]):
            continue
        try:
            with open(os.path.join(REPORT_DIR, fname), encoding='utf-8') as f:
                report = json.load(f)
        except (OSError, ValueError):
            continue
        if sam is None or str(report.get('sam', '')).lower() == sam.lower():
            reports.append(report)
    return reports


def undo(conn, base_dn, report_id, by):
    """
    Annule un départ : compte réactivé (s'il l'était), remis dans son unité
    d'organisation et dans ses groupes, description rétablie.
    """
    from ldap3 import BASE, MODIFY_ADD, MODIFY_REPLACE
    from ldap3.utils.dn import safe_rdn
    report = load(report_id)
    if report.get('undone'):
        raise OffboardingError('Ce départ a déjà été annulé.')
    original = report['original']
    dn = report.get('dn') or original['dn']
    for value in (dn, original['dn'], original['ou']):
        if not value.lower().endswith(base_dn.lower()):
            raise OffboardingError('Rapport hors du domaine.')
    conn.search(dn, '(objectClass=user)', BASE, attributes=['userAccountControl'])
    if not conn.entries:
        raise OffboardingError('Le compte est introuvable à son emplacement de départ : '
                               'restaurez-le d\'abord (corbeille AD) ou replacez-le.')
    uac = int(conn.entries[0].userAccountControl.value or 512)
    results = []

    if dn.lower() != original['dn'].lower():
        rdn = '+'.join(safe_rdn(dn))
        ok, detail = _try(conn, conn.modify_dn, dn, rdn, new_superior=original['ou'])
        if ok:
            dn = f'{rdn},{original["ou"]}'
        results.append({'label': 'Remise dans son unité d\'organisation', 'ok': ok, 'detail': '' if ok else detail})

    changes = {'description': [(MODIFY_REPLACE, [original['description']] if original['description'] else [])]}
    if original['enabled']:
        changes['userAccountControl'] = [(MODIFY_REPLACE, [uac & ~UF_DISABLED])]
    ok, detail = _try(conn, conn.modify, dn, changes)
    results.append({'label': 'Compte réactivé' if original['enabled'] else 'Description rétablie',
                    'ok': ok, 'detail': '' if ok else detail})

    if report.get('hidden'):
        ok, detail = _try(conn, conn.modify, dn, {'msExchHideFromAddressLists': [(MODIFY_REPLACE, [])]})
        results.append({'label': 'Compte de nouveau visible dans le carnet d\'adresses',
                        'ok': ok, 'detail': '' if ok else detail})

    added, failed = 0, []
    for group in original['groups']:
        ok, _ = _try(conn, conn.modify, group, {'member': [(MODIFY_ADD, [dn])]})
        if ok or conn.result.get('result') == 68:          # 68 : déjà membre
            added += 1
        else:
            failed.append(_name(group))
    results.append({'label': f'{added} groupe(s) rétabli(s)', 'ok': not failed,
                    'detail': f'échec pour : {", ".join(failed)}' if failed else ''})

    report['undone'] = {'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'by': by, 'results': results}
    report['dn'] = dn
    with open(os.path.join(REPORT_DIR, report_id + '.json'), 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return report
