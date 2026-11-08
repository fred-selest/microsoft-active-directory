"""
Lecture des dates et durées Active Directory.

Avec get_info=ALL (cas de get_ad_connection), ldap3 applique le schéma et
renvoie déjà des objets Python :
- les FILETIME (pwdLastSet, lastLogon, lastLogonTimestamp, accountExpires,
  lockoutTime) en datetime UTC, 1601-01-01 pour 0 et 9999-12-31 pour
  « jamais » ;
- les intervalles (maxPwdAge, lockoutDuration…) en timedelta positif,
  timedelta.max pour « jamais ».

Sans schéma (connexions de test, MOCK_SYNC), les mêmes attributs arrivent en
entiers ou en chaînes. L'ancien code faisait int(str(valeur)) : sur un vrai
AD, str(datetime) n'est pas un entier, l'exception était avalée et la date
ignorée — les mots de passe expirant étaient toujours comptés à 0.

Ces fonctions acceptent les deux formes et renvoient des datetime naïfs en
UTC, comparables entre eux et à utcnow().
"""
from datetime import datetime, timedelta, timezone

_FILETIME_EPOCH = datetime(1601, 1, 1)
_FILETIME_NEVER = 0x7FFFFFFFFFFFFFFF
_TICKS_PER_SECOND = 10_000_000


def utcnow():
    """Maintenant, en datetime naïf UTC (même référence que ad_datetime)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _raw(value):
    """Valeur brute d'un attribut ldap3 (ou de la valeur elle-même)."""
    if hasattr(value, 'value'):
        value = value.value
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if isinstance(value, bytes):
        value = value.decode('ascii', errors='ignore')
    return value


def ad_datetime(value):
    """
    Date AD (FILETIME ou GeneralizedTime) en datetime naïf UTC.

    Renvoie None pour une valeur absente, 0, « jamais » ou illisible.
    """
    value = _raw(value)
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        if value.year <= 1601 or value.year >= 9999:
            return None
        return value
    if isinstance(value, str):
        text = value.strip()
        # GeneralizedTime (whenCreated sans schéma) : 20240131123000.0Z
        if len(text) >= 14 and text[:14].isdigit() and not text.lstrip('-').isdigit():
            try:
                return datetime.strptime(text[:14], '%Y%m%d%H%M%S')
            except ValueError:
                return None
        value = text
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return None
    if ticks <= 0 or ticks >= _FILETIME_NEVER:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
    except OverflowError:
        return None


def ad_interval(value):
    """
    Intervalle AD (maxPwdAge, lockoutDuration…) en timedelta positif.

    Renvoie None pour « jamais » (valeur minimale négative ou timedelta.max),
    timedelta(0) pour 0, None si absent ou illisible.
    """
    value = _raw(value)
    if value is None or value == '':
        return None
    if isinstance(value, timedelta):
        if value >= timedelta(days=999_999_999):
            return None
        return abs(value)
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return None
    if ticks <= -_FILETIME_NEVER:
        return None
    try:
        return timedelta(seconds=abs(ticks) / _TICKS_PER_SECOND)
    except OverflowError:
        return None


def last_logon(entry):
    """
    Dernière connexion connue d'un compte.

    lastLogonTimestamp est répliqué (avec jusqu'à 14 jours de retard) ;
    lastLogon est exact mais propre au DC interrogé. Avec plusieurs DC, ne
    lire que lastLogon fait passer pour inactifs les comptes qui
    s'authentifient sur un autre DC : on garde la plus récente des deux.
    """
    dates = [ad_datetime(getattr(entry, attr, None))
             for attr in ('lastLogonTimestamp', 'lastLogon')]
    dates = [d for d in dates if d]
    return max(dates) if dates else None


def get_account_policy(conn, base_dn):
    """
    Stratégie de comptes du domaine (objet racine).

    Returns:
        dict: max_pwd_age (timedelta ou None si les mots de passe
        n'expirent jamais) et lockout_duration (timedelta, 0 = verrouillé
        jusqu'à déblocage par un administrateur ; None si inconnu).
    """
    from ldap3 import BASE
    policy = {'max_pwd_age': None, 'lockout_duration': None}
    try:
        conn.search(base_dn, '(objectClass=*)', BASE,
                    attributes=['maxPwdAge', 'lockoutDuration'])
        if conn.entries:
            entry = conn.entries[0]
            max_age = ad_interval(getattr(entry, 'maxPwdAge', None))
            policy['max_pwd_age'] = max_age if max_age else None
            policy['lockout_duration'] = ad_interval(getattr(entry, 'lockoutDuration', None))
    except Exception:
        pass
    return policy


def is_locked_out(lockout_time, lockout_duration, now=None):
    """
    Le compte est-il réellement verrouillé ?

    AD ne remet pas lockoutTime à 0 quand la durée de verrouillage expire :
    il ne le fait qu'à la connexion suivante. Un lockoutTime non nul ne
    suffit donc pas ; il faut qu'il soit plus récent que lockoutDuration.
    """
    locked_at = ad_datetime(lockout_time)
    if not locked_at:
        return False
    if lockout_duration is None or lockout_duration == timedelta(0):
        return True
    return locked_at + lockout_duration > (now or utcnow())


def password_expiry(pwd_last_set, max_pwd_age, uac=0):
    """
    Date d'expiration du mot de passe, ou None s'il n'expire pas.

    None aussi si pwdLastSet vaut 0 (changement imposé à la prochaine
    connexion : il n'y a pas d'échéance à annoncer).
    """
    if not max_pwd_age:
        return None
    try:
        if int(_raw(uac) or 0) & 0x10000:  # DONT_EXPIRE_PASSWORD
            return None
    except (TypeError, ValueError):
        pass
    set_at = ad_datetime(pwd_last_set)
    if not set_at:
        return None
    return set_at + max_pwd_age
