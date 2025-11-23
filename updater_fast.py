#!/usr/bin/env python3
"""
Système de mise à jour rapide et incrémentale.
Télécharge uniquement les fichiers modifiés depuis GitHub.
"""

import os
import sys
import json
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
GITHUB_REPO = "fred-selest/microsoft-active-directory"
GITHUB_BRANCH = "main"
VERSION_FILE = "VERSION"
CACHE_FILE = "data/update_cache.json"
MAX_WORKERS = 5  # Téléchargements parallèles

# Fichiers à ne jamais mettre à jour
PRESERVE_FILES = {'.env', 'logs', 'data', 'venv', '__pycache__', '.git'}


class FastUpdater:
    """Gestionnaire de mise à jour incrémentale."""

    def __init__(self, app_dir: Path = None, silent: bool = False):
        self.app_dir = app_dir or Path(__file__).parent
        self.silent = silent
        self.last_error = None
        self.session = requests.Session()
        self.session.headers['Accept'] = 'application/vnd.github.v3+json'
        # Token optionnel pour éviter les limites de rate
        github_token = os.environ.get('GITHUB_TOKEN')
        if github_token:
            self.session.headers['Authorization'] = f'token {github_token}'

    def log(self, message: str):
        """Afficher un message si pas en mode silencieux."""
        if not self.silent:
            print(message)

    def get_github_tree(self):
        """Récupérer l'arbre des fichiers depuis GitHub API."""
        try:
            # Obtenir le SHA du commit le plus récent
            url = f"https://api.github.com/repos/{GITHUB_REPO}/branches/{GITHUB_BRANCH}"
            response = self.session.get(url, timeout=10)

            if response.status_code == 403:
                # Rate limit atteint
                self.last_error = "Limite de requêtes GitHub atteinte (60/h). Réessayez plus tard ou définissez GITHUB_TOKEN."
                return None
            elif response.status_code == 404:
                self.last_error = f"Dépôt ou branche non trouvé: {GITHUB_REPO}/{GITHUB_BRANCH}"
                return None
            elif response.status_code != 200:
                self.last_error = f"Erreur GitHub API: HTTP {response.status_code}"
                return None

            commit_sha = response.json()['commit']['sha']

            # Obtenir l'arbre complet (récursif)
            tree_url = f"https://api.github.com/repos/{GITHUB_REPO}/git/trees/{commit_sha}?recursive=1"
            tree_response = self.session.get(tree_url, timeout=30)

            if tree_response.status_code == 403:
                self.last_error = "Limite de requêtes GitHub atteinte. Réessayez plus tard."
                return None
            elif tree_response.status_code != 200:
                self.last_error = f"Erreur récupération arbre: HTTP {tree_response.status_code}"
                return None

            return tree_response.json()
        except requests.exceptions.ConnectionError:
            self.last_error = "Impossible de se connecter à GitHub. Vérifiez votre connexion Internet."
            return None
        except requests.exceptions.Timeout:
            self.last_error = "Timeout lors de la connexion à GitHub."
            return None
        except Exception as e:
            self.last_error = f"Erreur API GitHub: {e}"
            self.log(f"Erreur API GitHub: {e}")
            return None

    def load_cache(self) -> Dict:
        """Charger le cache des fichiers."""
        cache_path = self.app_dir / CACHE_FILE
        try:
            if cache_path.exists():
                with open(cache_path, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {'files': {}, 'version': '0.0.0'}

    def save_cache(self, cache: Dict):
        """Sauvegarder le cache des fichiers."""
        cache_path = self.app_dir / CACHE_FILE
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, 'w') as f:
            json.dump(cache, f, indent=2)

    def should_skip_file(self, filepath: str) -> bool:
        """Vérifier si un fichier doit être ignoré."""
        parts = Path(filepath).parts
        for part in parts:
            if part in PRESERVE_FILES:
                return True
        return False

    def get_files_to_update(self) -> Tuple[List[Dict], List[str], int]:
        """
        Comparer les fichiers locaux avec GitHub et retourner ceux à mettre à jour.

        Returns:
            (files_to_download, files_to_delete, total_size)
        """
        self.log("Analyse des fichiers...")

        tree = self.get_github_tree()
        if not tree:
            error_msg = self.last_error or "Impossible de récupérer la liste des fichiers depuis GitHub"
            raise Exception(error_msg)

        cache = self.load_cache()
        files_to_download = []
        files_to_delete = []
        total_size = 0
        remote_files = set()

        for item in tree.get('tree', []):
            if item['type'] != 'blob':
                continue

            filepath = item['path']
            remote_files.add(filepath)

            if self.should_skip_file(filepath):
                continue

            # Vérifier si le fichier a changé (via SHA Git)
            remote_sha = item['sha']
            cached_sha = cache.get('files', {}).get(filepath, {}).get('sha')

            if remote_sha != cached_sha:
                # Fichier modifié ou nouveau
                files_to_download.append({
                    'path': filepath,
                    'sha': remote_sha,
                    'size': item.get('size', 0)
                })
                total_size += item.get('size', 0)

        # Fichiers locaux supprimés sur le remote
        for local_file in cache.get('files', {}).keys():
            if local_file not in remote_files and not self.should_skip_file(local_file):
                files_to_delete.append(local_file)

        return files_to_download, files_to_delete, total_size

    def download_file(self, file_info: Dict) -> Tuple[str, bool, str]:
        """
        Télécharger un fichier depuis GitHub.

        Returns:
            (filepath, success, error_message)
        """
        filepath = file_info['path']
        try:
            url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{filepath}"
            response = self.session.get(url, timeout=30)

            if response.status_code == 200:
                local_path = self.app_dir / filepath
                local_path.parent.mkdir(parents=True, exist_ok=True)

                with open(local_path, 'wb') as f:
                    f.write(response.content)

                return filepath, True, ""
            else:
                return filepath, False, f"HTTP {response.status_code}"
        except Exception as e:
            return filepath, False, str(e)

    def download_files_parallel(self, files: List[Dict], progress_callback=None) -> Dict:
        """
        Télécharger plusieurs fichiers en parallèle.

        Returns:
            Résultats avec succès/échecs
        """
        results = {'success': [], 'failed': []}
        total = len(files)
        completed = 0

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(self.download_file, f): f for f in files}

            for future in as_completed(futures):
                filepath, success, error = future.result()
                completed += 1

                if success:
                    results['success'].append(filepath)
                else:
                    results['failed'].append({'path': filepath, 'error': error})

                if progress_callback:
                    progress_callback(completed, total, filepath)
                elif not self.silent:
                    print(f"\r  [{completed}/{total}] {filepath[:50]}...", end='', flush=True)

        if not self.silent:
            print()  # Nouvelle ligne après la progression

        return results

    def apply_incremental_update(self, progress_callback=None) -> Dict:
        """
        Appliquer une mise à jour incrémentale.

        Returns:
            Résultat de la mise à jour
        """
        result = {
            'success': False,
            'files_updated': 0,
            'files_deleted': 0,
            'bytes_downloaded': 0,
            'errors': []
        }

        try:
            # Obtenir la liste des fichiers à mettre à jour
            files_to_download, files_to_delete, total_size = self.get_files_to_update()

            if not files_to_download and not files_to_delete:
                self.log("Aucune mise à jour nécessaire.")
                result['success'] = True
                return result

            self.log(f"Fichiers à télécharger: {len(files_to_download)}")
            self.log(f"Fichiers à supprimer: {len(files_to_delete)}")
            self.log(f"Taille totale: {total_size / 1024:.1f} Ko")

            # Télécharger les fichiers modifiés
            if files_to_download:
                self.log("\nTéléchargement des fichiers...")
                download_results = self.download_files_parallel(files_to_download, progress_callback)
                result['files_updated'] = len(download_results['success'])
                result['bytes_downloaded'] = total_size

                if download_results['failed']:
                    result['errors'].extend(download_results['failed'])

            # Supprimer les fichiers obsolètes
            for filepath in files_to_delete:
                try:
                    local_path = self.app_dir / filepath
                    if local_path.exists():
                        local_path.unlink()
                        result['files_deleted'] += 1
                except Exception as e:
                    result['errors'].append({'path': filepath, 'error': str(e)})

            # Mettre à jour le cache
            cache = self.load_cache()
            for f in files_to_download:
                if f['path'] in [r['path'] for r in download_results.get('failed', [])]:
                    continue
                cache['files'][f['path']] = {'sha': f['sha']}

            for filepath in files_to_delete:
                cache['files'].pop(filepath, None)

            # Lire la nouvelle version
            version_path = self.app_dir / VERSION_FILE
            if version_path.exists():
                with open(version_path, 'r') as f:
                    cache['version'] = f.read().strip()

            self.save_cache(cache)
            result['success'] = len(result['errors']) == 0

        except Exception as e:
            result['errors'].append({'error': str(e)})

        return result


def check_for_updates_fast() -> Dict:
    """Vérifier rapidement si une mise à jour est disponible."""
    updater = FastUpdater(silent=True)

    try:
        files_to_update, _, total_size = updater.get_files_to_update()

        # Lire les versions
        current_version = "0.0.0"
        version_path = updater.app_dir / VERSION_FILE
        if version_path.exists():
            with open(version_path, 'r') as f:
                current_version = f.read().strip()

        # Obtenir la version distante
        try:
            url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{VERSION_FILE}"
            response = updater.session.get(url, timeout=10)
            latest_version = response.text.strip() if response.status_code == 200 else None
        except:
            latest_version = None

        return {
            'update_available': len(files_to_update) > 0,
            'current_version': current_version,
            'latest_version': latest_version,
            'files_to_update': len(files_to_update),
            'download_size_kb': total_size / 1024,
            'error': None
        }
    except Exception as e:
        return {
            'update_available': False,
            'current_version': '0.0.0',
            'latest_version': None,
            'files_to_update': 0,
            'download_size_kb': 0,
            'error': str(e)
        }


def perform_fast_update(silent: bool = False, progress_callback=None) -> Dict:
    """
    Effectuer une mise à jour incrémentale rapide.

    Args:
        silent: Mode silencieux
        progress_callback: Fonction(completed, total, filename) pour le suivi

    Returns:
        Résultat de la mise à jour
    """
    updater = FastUpdater(silent=silent)

    if not silent:
        print("\n" + "="*50)
        print("MISE À JOUR INCRÉMENTALE RAPIDE")
        print("="*50 + "\n")

    result = updater.apply_incremental_update(progress_callback)

    if not silent:
        print(f"\nRésultat:")
        print(f"  - Fichiers mis à jour: {result['files_updated']}")
        print(f"  - Fichiers supprimés: {result['files_deleted']}")
        print(f"  - Données téléchargées: {result['bytes_downloaded'] / 1024:.1f} Ko")

        if result['errors']:
            print(f"  - Erreurs: {len(result['errors'])}")
            for err in result['errors'][:5]:
                print(f"    * {err}")

        if result['success']:
            print("\nMise à jour terminée avec succès!")
        else:
            print("\nMise à jour terminée avec des erreurs.")

    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Mise à jour incrémentale rapide')
    parser.add_argument('--check', action='store_true', help='Vérifier uniquement')
    parser.add_argument('--silent', action='store_true', help='Mode silencieux')
    args = parser.parse_args()

    if args.check:
        info = check_for_updates_fast()
        print(json.dumps(info, indent=2))
    else:
        result = perform_fast_update(silent=args.silent)
        sys.exit(0 if result['success'] else 1)
