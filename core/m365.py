"""
État de Microsoft 365 rapproché de l'annuaire : licences, synchronisation,
comptes présents d'un seul côté, licences gaspillées, taille des boîtes.

Lecture seule. Les données viennent de Microsoft Graph (scripts/m365.ps1,
avec le certificat de l'application mis en place par
scripts/setup_m365.ps1) et, pour la taille des boîtes, d'Exchange Online
(core/exchange.py). Rien n'est modifié dans Microsoft 365.

Le rapprochement AD ↔ cloud se fait par l'ancre de synchronisation
(objectGUID de l'AD = onPremisesImmutableId du cloud), puis à défaut par
l'identifiant de connexion (UPN).
"""
import base64
import json
import logging
import os
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone

from core import exchange as ex

logger = logging.getLogger('m365')

PS_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts', 'm365.ps1')
PS_TIMEOUT = 180
CACHE_TTL = 600
STATS_TTL = 6 * 3600
SYNC_LATE_MINUTES = 180          # Entra Connect synchronise toutes les 30 minutes

# Noms commerciaux des références les plus courantes (entreprises et éducation).
SKU_NAMES = {
    'O365_BUSINESS_ESSENTIALS': 'Microsoft 365 Business Basic',
    'O365_BUSINESS_PREMIUM': 'Microsoft 365 Business Standard',
    'SPB': 'Microsoft 365 Business Premium',
    'O365_BUSINESS': 'Microsoft 365 Apps for business',
    'OFFICESUBSCRIPTION': 'Microsoft 365 Apps for enterprise',
    'STANDARDPACK': 'Office 365 E1', 'ENTERPRISEPACK': 'Office 365 E3', 'ENTERPRISEPREMIUM': 'Office 365 E5',
    'SPE_E3': 'Microsoft 365 E3', 'SPE_E5': 'Microsoft 365 E5', 'SPE_F1': 'Microsoft 365 F3',
    'DESKLESSPACK': 'Office 365 F3',
    'EXCHANGESTANDARD': 'Exchange Online (plan 1)', 'EXCHANGEENTERPRISE': 'Exchange Online (plan 2)',
    'EXCHANGEDESKLESS': 'Exchange Online Kiosk',
    'STANDARDWOFFPACK_FACULTY': 'Office 365 A1 (enseignants)',
    'STANDARDWOFFPACK_STUDENT': 'Office 365 A1 (élèves)',
    'STANDARDWOFFPACK_IW_FACULTY': 'Office 365 A1 Plus (enseignants)',
    'STANDARDWOFFPACK_IW_STUDENT': 'Office 365 A1 Plus (élèves)',
    'OFFICESUBSCRIPTION_FACULTY': 'Microsoft 365 Apps (enseignants)',
    'OFFICESUBSCRIPTION_STUDENT': 'Microsoft 365 Apps (élèves)',
    'ENTERPRISEPACKPLUS_FACULTY': 'Office 365 A3 (enseignants)',
    'ENTERPRISEPACKPLUS_STUDENT': 'Office 365 A3 (élèves)',
    'M365EDU_A1': 'Microsoft 365 A1',
    'M365EDU_A3_FACULTY': 'Microsoft 365 A3 (enseignants)', 'M365EDU_A3_STUDENT': 'Microsoft 365 A3 (élèves)',
    'M365EDU_A3_STUUSEBNFT': 'Microsoft 365 A3 (élèves, avantage)',
    'M365EDU_A5_FACULTY': 'Microsoft 365 A5 (enseignants)', 'M365EDU_A5_STUDENT': 'Microsoft 365 A5 (élèves)',
    'AAD_PREMIUM': 'Entra ID P1', 'AAD_PREMIUM_P2': 'Entra ID P2', 'EMS': 'Enterprise Mobility + Security E3',
    'INTUNE_A': 'Intune', 'INTUNE_EDU': 'Intune pour l\'éducation',
    'FLOW_FREE': 'Power Automate (gratuit)', 'POWER_BI_STANDARD': 'Power BI (gratuit)',
    'POWER_BI_PRO': 'Power BI Pro', 'TEAMS_EXPLORATORY': 'Teams Exploratory',
    'Microsoft_Teams_Exploratory_Dept': 'Teams Exploratory', 'TEAMS_ESSENTIALS': 'Teams Essentials',
    'MCOEV': 'Téléphonie Teams', 'MCOMEETADV': 'Audioconférence Teams',
    'PROJECTPROFESSIONAL': 'Project (plan 3)', 'VISIOCLIENT': 'Visio (plan 2)',
    'WINDOWS_STORE': 'Windows Store pour entreprises', 'RIGHTSMANAGEMENT_ADHOC': 'Rights Management (ad hoc)',
    'POWERAPPS_VIRAL': 'Power Apps (essai)', 'POWERAPPS_DEV': 'Power Apps (développeur)',
    'CCIBOTS_PRIVPREV_VIRAL': 'Copilot Studio (essai)', 'Microsoft_365_Copilot': 'Microsoft 365 Copilot',
}
# Références gratuites ou « virales » : jamais comptées comme des licences gaspillées.
FREE_SKUS = {'FLOW_FREE', 'POWER_BI_STANDARD', 'POWERAPPS_VIRAL', 'POWERAPPS_DEV', 'WINDOWS_STORE',
             'RIGHTSMANAGEMENT_ADHOC', 'TEAMS_EXPLORATORY', 'Microsoft_Teams_Exploratory_Dept',
             'CCIBOTS_PRIVPREV_VIRAL', 'STREAM', 'MICROSOFT_BUSINESS_CENTER'}

_cache = {'at': 0, 'data': None}
_lock = threading.Lock()
_stats = {'status': 'idle', 'at': 0, 'data': None, 'error': ''}


class M365Error(Exception):
    """Erreur présentable à l'utilisateur."""


def status():
    """'ready', 'no_graph' (liaison faite avant la v1.59 : relancer le script) ou 'none'."""
    cfg = ex.get_config()
    if not cfg:
        return 'none'
    return 'ready' if cfg.get('graph') else 'no_graph'


def _friendly(message):
    text = message or ''
    low = text.lower()
    if 'certificate' in low and ('not found' in low or 'private key' in low):
        return 'Certificat introuvable ou illisible sur ce serveur : relancez scripts\\setup_m365.ps1.'
    if 'authorization_requestdenied' in low or 'insufficient privileges' in low or '403' in low:
        return ('Microsoft 365 refuse la lecture des comptes : relancez scripts\\setup_m365.ps1 pour accorder '
                'à l\'application la lecture des comptes et des licences.')
    if 'aadsts' in low or '401' in low:
        return f'Microsoft 365 refuse la connexion de l\'application : relancez scripts\\setup_m365.ps1. ({text[:160]})'
    if 'remote name' in low or 'unable to connect' in low or 'timed out' in low:
        return 'Microsoft 365 est injoignable depuis ce serveur (accès Internet, proxy).'
    return text[:300] or 'Erreur inconnue.'


def _run_ps():
    cfg = ex.get_config()
    if not cfg:
        raise M365Error('La liaison Microsoft 365 n\'est pas configurée.')
    if not cfg.get('graph'):
        raise M365Error('Relancez scripts\\setup_m365.ps1 pour accorder la lecture des comptes et des licences.')
    if os.name != 'nt':
        raise M365Error('La lecture de Microsoft 365 nécessite que l\'application tourne sous Windows.')
    data = {'organization': cfg['organization'], 'app_id': cfg['app_id'], 'thumbprint': cfg['thumbprint']}
    try:
        proc = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', PS_SCRIPT_PATH],
            input=json.dumps(data), capture_output=True, text=True, encoding='utf-8',
            errors='replace', timeout=PS_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise M365Error('Microsoft 365 n\'a pas répondu dans le délai imparti.')
    except OSError as e:
        raise M365Error(f'PowerShell introuvable : {e}')
    lines = [ln for ln in (proc.stdout or '').strip().splitlines() if ln.strip().startswith('{')]
    try:
        result = json.loads(lines[-1].lstrip('﻿')) if lines else None
    except ValueError:
        result = None
    if not isinstance(result, dict):
        logger.error('Réponse Microsoft 365 illisible (code %s) : %s', proc.returncode,
                     (proc.stderr or proc.stdout or '')[:500])
        raise M365Error(_friendly(proc.stderr or proc.stdout))
    if not result.get('ok'):
        raise M365Error(_friendly(result.get('error')))
    return result


def _when(text):
    """Date ISO de Graph → datetime UTC, ou None."""
    try:
        return datetime.fromisoformat(str(text).replace('Z', '+00:00')).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def fetch(refresh=False):
    """Organisation, licences et comptes du cloud, gardés 10 minutes."""
    with _lock:
        if not refresh and _cache['data'] and time.time() - _cache['at'] < CACHE_TTL:
            return _cache['data']
    raw = _run_ps()
    skus = {}
    for s in raw.get('skus') or []:
        code = str(s.get('code') or '')
        total, used = int(s.get('total') or 0), int(s.get('used') or 0)
        skus[str(s.get('id') or '').lower()] = {
            'code': code, 'name': SKU_NAMES.get(code, code), 'free_sku': code in FREE_SKUS,
            'total': total, 'used': used, 'free': max(total - used, 0), 'over': max(used - total, 0),
            'warning': int(s.get('warning') or 0), 'suspended': int(s.get('suspended') or 0),
            'status': str(s.get('status') or '')}
    users = []
    for u in raw.get('users') or []:
        users.append({'name': str(u.get('name') or ''), 'upn': str(u.get('upn') or '').lower(),
                      'mail': str(u.get('mail') or '').lower(), 'enabled': bool(u.get('enabled')),
                      'guest': str(u.get('type') or '').lower() == 'guest', 'synced': bool(u.get('synced')),
                      'sam': str(u.get('sam') or ''), 'anchor': str(u.get('anchor') or ''),
                      'last_sync': str(u.get('last_sync') or ''), 'created': str(u.get('created') or '')[:10],
                      'licenses': [str(i).lower() for i in u.get('licenses') or []]})
    org = raw.get('organization') or {}
    data = {'organization': {'name': str(org.get('name') or ''), 'sync_enabled': bool(org.get('sync_enabled')),
                             'last_sync': str(org.get('last_sync') or '')},
            'skus': skus, 'users': users, 'at': time.time()}
    with _lock:
        _cache.update(at=time.time(), data=data)
    return data


def anchor_of(guid):
    """objectGUID de l'AD (texte ou 16 octets) → ancre de synchronisation (base64)."""
    try:
        raw = guid if isinstance(guid, (bytes, bytearray)) and len(guid) == 16 \
            else uuid.UUID(str(guid).strip('{}')).bytes_le
        return base64.b64encode(bytes(raw)).decode()
    except (ValueError, AttributeError, TypeError):
        return ''


def _routable(upn):
    return bool(upn) and '@' in upn and not upn.lower().endswith(('.local', '.lan', '.internal', '.corp'))


def read_ad_users(conn, base_dn):
    """Comptes de personnes de l'AD : [{dn, sam, name, upn, mail, enabled, anchor}]."""
    from routes.core import paged_search
    users = []
    for e in paged_search(conn, base_dn, '(&(objectClass=user)(objectCategory=person))',
                          attributes=['objectGUID', 'sAMAccountName', 'displayName', 'userPrincipalName',
                                      'mail', 'userAccountControl']):
        def val(attr):
            value = getattr(e, attr).value if attr in e else None
            return '' if value is None else value
        try:
            uac = int(val('userAccountControl') or 512)
        except (TypeError, ValueError):
            uac = 512
        sam = str(val('sAMAccountName'))
        users.append({'dn': e.entry_dn, 'sam': sam, 'name': str(val('displayName') or sam),
                      'upn': str(val('userPrincipalName')).lower(), 'mail': str(val('mail')).lower(),
                      'enabled': not uac & 0x2, 'anchor': anchor_of(val('objectGUID'))})
    return users


def _license_names(data, user, paid_only=False):
    names = []
    for sku_id in user['licenses']:
        sku = data['skus'].get(sku_id)
        if sku and paid_only and sku['free_sku']:
            continue
        names.append(sku['name'] if sku else sku_id)
    return sorted(names)


def compare(data, ad_users, now=None):
    """
    Rapproche les comptes du cloud et ceux de l'AD.

    Returns:
        dict: organization (avec retard de synchronisation), licenses,
        counts, findings {clé: [lignes]}.
    """
    now = now or datetime.now(timezone.utc)
    org = dict(data['organization'])
    last = _when(org['last_sync'])
    org['sync_age_minutes'] = int((now - last).total_seconds() // 60) if last else None
    org['sync_late'] = bool(org['sync_enabled'] and (last is None or org['sync_age_minutes'] > SYNC_LATE_MINUTES))

    by_anchor = {u['anchor']: u for u in ad_users if u['anchor']}
    by_upn = {u['upn']: u for u in ad_users if u['upn']}
    matched_dns = set()
    findings = {k: [] for k in ('disabled_licensed', 'orphans', 'upn_mismatch', 'cloud_only', 'unlicensed', 'ad_only')}
    members = [u for u in data['users'] if not u['guest']]

    for cu in members:
        ad = by_anchor.get(cu['anchor']) if cu['anchor'] else None
        if ad is None:
            ad = by_upn.get(cu['upn'])
        paid = _license_names(data, cu, paid_only=True)
        row = {'name': cu['name'], 'upn': cu['upn'], 'sam': ad['sam'] if ad else cu['sam'],
               'dn': ad['dn'] if ad else '', 'licenses': paid, 'detail': ''}
        if ad:
            matched_dns.add(ad['dn'])
        disabled = not cu['enabled'] or (ad is not None and not ad['enabled'])
        if paid and disabled:
            where = 'dans l\'AD' if ad is not None and not ad['enabled'] else 'dans Microsoft 365'
            findings['disabled_licensed'].append(dict(row, detail=f'Compte désactivé {where}'))
        if cu['synced'] and ad is None and org['sync_enabled']:
            findings['orphans'].append(dict(row, detail='Synchronisé depuis un compte AD introuvable'))
        elif ad is not None and cu['anchor'] and ad['upn'] and ad['upn'] != cu['upn']:
            findings['upn_mismatch'].append(dict(row, detail=f'AD : {ad["upn"]}'))
        if not cu['synced'] and ad is None and cu['enabled']:
            findings['cloud_only'].append(dict(row, detail=f'Créé le {cu["created"]}' if cu['created'] else ''))
        if cu['synced'] and ad is not None and ad['enabled'] and cu['enabled'] and not paid:
            findings['unlicensed'].append(row)

    if org['sync_enabled']:
        for ad in ad_users:
            if ad['dn'] not in matched_dns and ad['enabled'] and _routable(ad['upn']):
                findings['ad_only'].append({'name': ad['name'], 'upn': ad['upn'], 'sam': ad['sam'],
                                            'dn': ad['dn'], 'licenses': [], 'detail': ''})
    for rows in findings.values():
        rows.sort(key=lambda r: r['name'].lower())

    licenses = sorted(data['skus'].values(), key=lambda s: (s['free_sku'], -s['total'], s['name'].lower()))
    return {'organization': org, 'licenses': licenses, 'findings': findings,
            'counts': {'cloud': len(members), 'guests': len(data['users']) - len(members),
                       'synced': sum(1 for u in members if u['synced']),
                       'licensed': sum(1 for u in members if _license_names(data, u, paid_only=True)),
                       'ad': len(ad_users),
                       'wasted': sum(len(r['licenses']) for r in findings['disabled_licensed'])},
            'at': data.get('at')}


def user_status(data, upn='', anchor=''):
    """Ce que Microsoft 365 sait d'un compte de l'AD (pour sa fiche), ou None."""
    anchor, upn = (anchor or '').strip(), (upn or '').strip().lower()
    for cu in data['users']:
        if (anchor and cu['anchor'] == anchor) or (upn and cu['upn'] == upn):
            return {'upn': cu['upn'], 'enabled': cu['enabled'], 'synced': cu['synced'],
                    'last_sync': cu['last_sync'], 'licenses': _license_names(data, cu)}
    return None


# --- Taille des boîtes : traitement long, en arrière-plan ---------------------

def mailbox_stats(start=False, refresh=False):
    """
    État du relevé de taille des boîtes : {status, data, at, error}.
    start=True le lance s'il n'existe pas (ou s'il a expiré) ; refresh=True le relance.
    """
    with _lock:
        fresh = _stats['data'] is not None and time.time() - _stats['at'] < STATS_TTL
        if _stats['status'] != 'running' and (refresh or (start and not fresh)):
            _stats.update(status='running', error='')
            threading.Thread(target=_collect_stats, daemon=True).start()
        return dict(_stats)


def _collect_stats():
    try:
        rows = ex.mailbox_stats()
        with _lock:
            _stats.update(status='done', data=rows, at=time.time(), error='')
    except Exception as e:                       # le fil ne doit jamais mourir en laissant « running »
        logger.warning('Relevé des boîtes impossible : %s', e)
        with _lock:
            _stats.update(status='error', error=str(e))
