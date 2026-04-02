#!/usr/bin/env python3
"""
CLI de gestion — remplace tous les scripts .bat de lancement et d'installation.

Usage:
    python manage.py run              # Serveur de développement
    python manage.py run --prod       # Serveur de production (Waitress/Gunicorn)
    python manage.py run --port 8080  # Port personnalisé
    python manage.py install          # Créer le venv et installer les dépendances
    python manage.py service install  # Installer le service Windows
    python manage.py service remove   # Supprimer le service Windows
    python manage.py service start    # Démarrer le service Windows
    python manage.py service stop     # Arrêter le service Windows
"""
import os
import sys
import platform
import subprocess
from pathlib import Path

# Flask inclut Click — pas de dépendance supplémentaire
import click

BASE_DIR = Path(__file__).resolve().parent
IS_WINDOWS = platform.system() == 'Windows'


def _venv_python():
    if IS_WINDOWS:
        return BASE_DIR / 'venv' / 'Scripts' / 'python.exe'
    return BASE_DIR / 'venv' / 'bin' / 'python'


def _venv_pip():
    if IS_WINDOWS:
        return BASE_DIR / 'venv' / 'Scripts' / 'pip.exe'
    return BASE_DIR / 'venv' / 'bin' / 'pip'


def _ensure_env():
    """Créer le fichier .env s'il n'existe pas."""
    from run import ensure_env_file
    ensure_env_file()


# ─── run ────────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """AD Web Interface — outil de gestion."""


@cli.command()
@click.option('--prod', is_flag=True, default=False, help='Mode production (Waitress/Gunicorn)')
@click.option('--host', default=None, help='Adresse d\'écoute (défaut: AD_WEB_HOST ou 0.0.0.0)')
@click.option('--port', default=None, type=int, help='Port (défaut: AD_WEB_PORT ou 5000)')
def run(prod, host, port):
    """Démarrer le serveur Flask."""
    _ensure_env()
    os.chdir(BASE_DIR)

    # Charger .env
    try:
        from dotenv import load_dotenv
        load_dotenv(BASE_DIR / '.env', encoding='utf-8')
    except ImportError:
        pass

    if prod:
        os.environ['FLASK_DEBUG'] = 'false'
        os.environ['FLASK_ENV'] = 'production'
    else:
        os.environ.setdefault('FLASK_DEBUG', 'true')
        os.environ.setdefault('FLASK_ENV', 'development')

    if host:
        os.environ['AD_WEB_HOST'] = host
    if port:
        os.environ['AD_WEB_PORT'] = str(port)

    click.echo(f"Démarrage {'production' if prod else 'développement'} sur "
               f"http://{os.environ.get('AD_WEB_HOST', '0.0.0.0')}:{os.environ.get('AD_WEB_PORT', '5000')}")

    from app import run_server
    run_server()


# ─── install ────────────────────────────────────────────────────────────────

@cli.command()
@click.option('--upgrade', is_flag=True, default=False, help='Mettre à jour les dépendances')
def install(upgrade):
    """Créer le venv et installer les dépendances."""
    venv_dir = BASE_DIR / 'venv'

    if not venv_dir.exists():
        click.echo('Création de l\'environnement virtuel...')
        subprocess.run([sys.executable, '-m', 'venv', str(venv_dir)], check=True)
        click.echo('Environnement virtuel créé.')

    pip = _venv_pip()
    req = BASE_DIR / 'requirements.txt'
    cmd = [str(pip), 'install', '-r', str(req)]
    if upgrade:
        cmd.append('--upgrade')
    click.echo('Installation des dépendances...')
    subprocess.run(cmd, check=True)
    click.echo('Dépendances installées.')

    _ensure_env()
    click.echo('Prêt. Lancez: python manage.py run')


# ─── service (Windows uniquement) ───────────────────────────────────────────

@cli.group()
def service():
    """Gestion du service Windows (NSSM)."""
    if not IS_WINDOWS:
        click.echo('La gestion de service est uniquement disponible sur Windows.', err=True)
        sys.exit(1)


@service.command('install')
@click.option('--name', default='ADWebInterface', help='Nom du service Windows')
@click.option('--port', default=5000, help='Port du serveur')
def service_install(name, port):
    """Installer le service Windows via NSSM."""
    python = _venv_python()
    run_py = BASE_DIR / 'run.py'

    nssm = _find_nssm()
    if not nssm:
        click.echo('NSSM introuvable. Téléchargez-le sur https://nssm.cc/', err=True)
        sys.exit(1)

    subprocess.run([nssm, 'install', name, str(python), str(run_py)], check=True)
    subprocess.run([nssm, 'set', name, 'AppDirectory', str(BASE_DIR)], check=True)
    subprocess.run([nssm, 'set', name, 'AppEnvironmentExtra',
                    f'AD_WEB_PORT={port}', 'FLASK_ENV=production', 'FLASK_DEBUG=false'], check=True)
    click.echo(f'Service "{name}" installé. Démarrez-le avec: python manage.py service start')


@service.command('remove')
@click.option('--name', default='ADWebInterface', help='Nom du service Windows')
def service_remove(name):
    """Supprimer le service Windows."""
    nssm = _find_nssm()
    if not nssm:
        click.echo('NSSM introuvable.', err=True)
        sys.exit(1)
    subprocess.run([nssm, 'remove', name, 'confirm'], check=True)
    click.echo(f'Service "{name}" supprimé.')


@service.command('start')
@click.option('--name', default='ADWebInterface', help='Nom du service Windows')
def service_start(name):
    """Démarrer le service Windows."""
    subprocess.run(['sc', 'start', name], check=True)
    click.echo(f'Service "{name}" démarré.')


@service.command('stop')
@click.option('--name', default='ADWebInterface', help='Nom du service Windows')
def service_stop(name):
    """Arrêter le service Windows."""
    subprocess.run(['sc', 'stop', name], check=True)
    click.echo(f'Service "{name}" arrêté.')


def _find_nssm():
    """Chercher NSSM dans PATH et dans le répertoire du projet."""
    import shutil
    nssm = shutil.which('nssm')
    if nssm:
        return nssm
    local = BASE_DIR / 'nssm.exe'
    return str(local) if local.exists() else None


if __name__ == '__main__':
    cli()
