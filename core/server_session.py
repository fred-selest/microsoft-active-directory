"""
Sessions côté serveur (constat C4 de AUDIT_2026-07-20.md).

Par défaut Flask stocke la session dans un cookie signé côté client : les
données de session — dont le mot de passe AD chiffré — voyagent donc dans le
navigateur à chaque requête, sans possibilité de révocation côté serveur.

Ce module remplace ce mécanisme par un stockage sur fichier : le cookie ne
contient qu'un identifiant de session opaque (signé), et les données résident
dans data/sessions/ sur le serveur. Avantages : le secret ne quitte plus le
serveur, la déconnexion/expiration invalide réellement la session, et on peut
énumérer/révoquer les sessions actives.

Implémentation autonome (aucune dépendance pip supplémentaire) : sur un
contrôleur de domaine isolé, ajouter une dépendance installée à la volée par
l'updater serait un risque de panne. On n'utilise que la bibliothèque standard
et itsdangerous (déjà fourni par Flask).
"""
import hashlib
import os
import pickle
import time
from pathlib import Path
from datetime import datetime, timedelta

from itsdangerous import URLSafeTimedSerializer, BadSignature
from werkzeug.datastructures import CallbackDict
from flask.sessions import SessionInterface, SessionMixin


class ServerSession(CallbackDict, SessionMixin):
    """Session dont les données vivent côté serveur."""

    def __init__(self, initial=None, sid=None, new=False):
        def _on_update(_):
            self.modified = True
        CallbackDict.__init__(self, initial, _on_update)
        self.sid = sid
        self.new = new
        self.modified = False


class FileSystemSessionInterface(SessionInterface):
    """
    Stocke les sessions dans des fichiers. Le cookie ne porte qu'un sid signé.

    Args:
        directory: dossier de stockage des sessions
        key_prefix: préfixe des fichiers
    """
    session_class = ServerSession
    _CLEANUP_PROBABILITY = 0.02  # ménage opportuniste (~1 requête sur 50)

    def __init__(self, directory, key_prefix='sess_'):
        self.directory = Path(directory)
        self.key_prefix = key_prefix
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    # --- Sérialisation identifiant <-> fichier ------------------------------

    def _signer(self, app):
        return URLSafeTimedSerializer(app.secret_key, salt='ad-web-session')

    def _path(self, sid):
        # sid est aléatoire (token_urlsafe) ; on le hache pour un nom de fichier
        # sûr et de longueur fixe, jamais dérivé d'une entrée client brute.
        h = hashlib.sha256(sid.encode()).hexdigest()
        return self.directory / f"{self.key_prefix}{h}"

    def _lifetime(self, app):
        lt = app.permanent_session_lifetime
        return lt if isinstance(lt, timedelta) else timedelta(seconds=int(lt or 7200))

    # --- Contrat SessionInterface -------------------------------------------

    def open_session(self, app, request):
        cookie_name = app.config.get('SESSION_COOKIE_NAME', 'ad_session')
        signed = request.cookies.get(cookie_name)
        if not signed:
            return self.session_class(sid=self._new_sid(), new=True)

        try:
            sid = self._signer(app).loads(
                signed, max_age=int(self._lifetime(app).total_seconds()))
        except (BadSignature, Exception):
            # Cookie invalide/expiré/falsifié → nouvelle session vierge.
            return self.session_class(sid=self._new_sid(), new=True)

        path = self._path(sid)
        try:
            if path.exists():
                age = time.time() - path.stat().st_mtime
                if age > self._lifetime(app).total_seconds():
                    self._safe_unlink(path)
                    return self.session_class(sid=sid, new=True)
                with open(path, 'rb') as f:
                    data = pickle.load(f)
                return self.session_class(data, sid=sid)
        except Exception:
            # Fichier corrompu → repartir sur une session vierge.
            self._safe_unlink(path)
        return self.session_class(sid=sid, new=True)

    def save_session(self, app, session, response):
        cookie_name = app.config.get('SESSION_COOKIE_NAME', 'ad_session')
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)

        # Session vidée → supprimer le fichier et le cookie.
        if not session:
            if not session.new:
                self._safe_unlink(self._path(session.sid))
            if session.modified:
                response.delete_cookie(cookie_name, domain=domain, path=path)
            return

        if self._CLEANUP_PROBABILITY and os.urandom(1)[0] < 256 * self._CLEANUP_PROBABILITY:
            self._cleanup(app)

        if not (session.modified or session.new):
            return

        try:
            fpath = self._path(session.sid)
            tmp = fpath.with_suffix('.tmp')
            with open(tmp, 'wb') as f:
                pickle.dump(dict(session), f)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, fpath)
        except Exception:
            # Ne jamais faire échouer la requête sur un problème d'écriture de session.
            import logging
            logging.getLogger('server_session').error(
                "Échec d'écriture de la session serveur", exc_info=True)
            return

        signed = self._signer(app).dumps(session.sid)
        response.set_cookie(
            cookie_name, signed,
            expires=self.get_expiration_time(app, session),
            httponly=self.get_cookie_httponly(app),
            secure=self.get_cookie_secure(app),
            samesite=self.get_cookie_samesite(app),
            domain=domain, path=path,
        )

    # --- Helpers ------------------------------------------------------------

    @staticmethod
    def _new_sid():
        import secrets
        return secrets.token_urlsafe(32)

    @staticmethod
    def _safe_unlink(path):
        try:
            Path(path).unlink()
        except OSError:
            pass

    def _cleanup(self, app):
        """Supprimer les fichiers de session expirés (ménage opportuniste)."""
        cutoff = time.time() - self._lifetime(app).total_seconds()
        try:
            for p in self.directory.glob(f"{self.key_prefix}*"):
                try:
                    if p.stat().st_mtime < cutoff:
                        p.unlink()
                except OSError:
                    pass
        except OSError:
            pass


def init_server_sessions(app, directory):
    """Installer le stockage de session côté serveur sur l'application Flask."""
    app.session_interface = FileSystemSessionInterface(directory)
