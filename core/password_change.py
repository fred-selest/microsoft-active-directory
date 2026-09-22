"""
Changement d'un mot de passe AD expire (ou « doit etre change a la prochaine
ouverture de session »).

Pourquoi pas LDAP : un bind avec un mot de passe expire est TOUJOURS refuse
par Active Directory (codes data 532 / 773). Impossible donc de se lier avec
les identifiants de l'utilisateur pour modifier unicodePwd — et se lier avec
le compte de service reviendrait a une reinitialisation privilegiee qui
contourne l'historique des mots de passe.

On passe donc par NetUserChangePassword (netapi32), le mecanisme qu'utilise
Windows lui-meme a l'ouverture de session : il fonctionne sans bind prealable,
reverifie l'ancien mot de passe et applique la strategie de mot de passe du
domaine (longueur, complexite, historique, age minimal). Disponible uniquement
sous Windows, plateforme cible de l'application.
"""

import os

# Codes NET_API_STATUS documentes pour NetUserChangePassword
NERR_SUCCESS = 0
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PASSWORD = 86
NERR_INVALID_COMPUTER = 2351
NERR_NOT_PRIMARY = 2226
NERR_USER_NOT_FOUND = 2221
NERR_PASSWORD_TOO_SHORT = 2245

_MESSAGES = {
    ERROR_ACCESS_DENIED: "Acces refuse : ce compte n'est pas autorise a changer "
                         "son mot de passe.",
    ERROR_INVALID_PASSWORD: "L'ancien mot de passe est incorrect.",
    NERR_INVALID_COMPUTER: "Controleur de domaine introuvable.",
    NERR_NOT_PRIMARY: "Operation possible uniquement sur le controleur de domaine principal.",
    NERR_USER_NOT_FOUND: "Utilisateur introuvable dans le domaine.",
    NERR_PASSWORD_TOO_SHORT: "Le nouveau mot de passe ne respecte pas la strategie du "
                             "domaine (longueur, complexite, historique ou age minimal).",
}


def describe_status(status):
    """Traduire un code NET_API_STATUS en message utilisateur."""
    return _MESSAGES.get(status, f"Echec du changement de mot de passe (code {status}).")


def _net_user_change_password(domain, username, old_password, new_password):
    """Appel brut a netapi32!NetUserChangePassword. Retourne le NET_API_STATUS."""
    import ctypes
    from ctypes import wintypes

    func = ctypes.windll.netapi32.NetUserChangePassword
    func.argtypes = [wintypes.LPCWSTR] * 4
    func.restype = wintypes.DWORD
    return func(domain, username, old_password, new_password)


def change_expired_password(domain, username, old_password, new_password):
    """
    Changer le mot de passe d'un compte AD sans bind LDAP prealable.

    Args:
        domain: nom DNS/NetBIOS du domaine ou du controleur de domaine
        username: nom de compte (sAMAccountName, sans prefixe DOMAINE\\)
        old_password: mot de passe actuel (expire)
        new_password: nouveau mot de passe

    Returns:
        (True, None) en cas de succes, (False, message) sinon.
    """
    if os.name != 'nt':
        return False, ("Le changement d'un mot de passe expire n'est possible que "
                       "lorsque l'application s'execute sous Windows. Changez-le "
                       "depuis un poste du domaine (Ctrl+Alt+Suppr).")
    try:
        status = _net_user_change_password(domain, username, old_password, new_password)
    except OSError as e:
        return False, f"Appel systeme impossible : {e}"
    if status == NERR_SUCCESS:
        return True, None
    return False, describe_status(status)
