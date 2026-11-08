"""
Vérification d'un compte administrateur par Windows, sans LDAP.

Sert aux actions de réparation proposées sur la page de connexion, quand la
connexion LDAP échoue justement (exigence de signature ou de liaison de
canal) : on ne peut pas s'appuyer sur une session de l'application. Les
identifiants sont vérifiés par LogonUser (ouverture de session réseau sur le
serveur de l'application, le contrôleur de domaine), puis l'appartenance au
groupe Administrateurs (BUILTIN, S-1-5-32-544) par CheckTokenMembership.

Sur un contrôleur de domaine, ce groupe contient les Admins du domaine et
les Administrateurs de l'entreprise.
"""
import os

LOGON32_LOGON_NETWORK = 3
LOGON32_PROVIDER_DEFAULT = 0
ADMINISTRATORS_SID = 'S-1-5-32-544'


def split_account(username):
    """(domaine, compte) depuis DOMAINE\\compte, compte@domaine ou compte."""
    username = (username or '').strip()
    if '\\' in username:
        domain, user = username.split('\\', 1)
        return domain, user
    if '@' in username:
        return None, username      # UPN : LogonUser accepte domaine NULL
    return '.', username


def _check_admin(domain, user, password):
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    token = wintypes.HANDLE()
    advapi32.LogonUserW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                    wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.LogonUserW.restype = wintypes.BOOL
    if not advapi32.LogonUserW(user, domain, password, LOGON32_LOGON_NETWORK,
                               LOGON32_PROVIDER_DEFAULT, ctypes.byref(token)):
        return False, 'Identifiant ou mot de passe incorrect.'
    try:
        sid = ctypes.c_void_p()
        advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        if not advapi32.ConvertStringSidToSidW(ADMINISTRATORS_SID, ctypes.byref(sid)):
            return False, 'Vérification impossible (SID).'
        try:
            is_member = wintypes.BOOL()
            # Une ouverture de session réseau fournit un jeton d'emprunt
            # d'identité, ce qu'attend CheckTokenMembership.
            advapi32.CheckTokenMembership.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                                      ctypes.POINTER(wintypes.BOOL)]
            if not advapi32.CheckTokenMembership(token, sid, ctypes.byref(is_member)):
                return False, 'Vérification des droits impossible.'
            if not is_member.value:
                return False, 'Ce compte n\'est pas administrateur du contrôleur de domaine.'
            return True, None
        finally:
            kernel32.LocalFree(sid)
    finally:
        kernel32.CloseHandle(token)


def verify_local_admin(username, password):
    """
    Le compte est-il administrateur de ce serveur ?

    Returns:
        (bool, str|None): succès, message d'erreur.
    """
    if not username or not password:
        return False, 'Indiquez un compte administrateur et son mot de passe.'
    if os.name != 'nt':
        return False, 'Disponible uniquement quand l\'application tourne sous Windows.'
    domain, user = split_account(username)
    try:
        return _check_admin(domain, user, password)
    except OSError as e:
        return False, f'Vérification impossible : {e}'
