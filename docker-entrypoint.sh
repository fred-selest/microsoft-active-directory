#!/bin/bash
# =============================================================================
# Script d'entree Docker pour AD Web Interface
# =============================================================================

set -e

# Couleurs pour les logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# =============================================================================
# Verification de la configuration
# =============================================================================

log_info "Demarrage de AD Web Interface..."
log_info "Version: $(cat VERSION 2>/dev/null || echo 'inconnue')"

# Verifier SECRET_KEY
if [ -z "$SECRET_KEY" ] || [ "$SECRET_KEY" = "changez-moi-en-production-avec-une-cle-forte" ]; then
    log_warn "SECRET_KEY non definie ou par defaut. Generez une cle securisee pour la production!"
    log_warn "Exemple: python -c 'import secrets; print(secrets.token_hex(32))'"
fi

# Verifier la configuration AD
if [ -z "$AD_SERVER" ]; then
    log_warn "AD_SERVER non defini. Configurez-le via les variables d'environnement."
fi

# =============================================================================
# Preparation des repertoires
# =============================================================================

log_info "Verification des repertoires..."

# Creer les repertoires si necessaire
mkdir -p "${AD_LOG_DIR:-/app/logs}" "${AD_DATA_DIR:-/app/data}"

# =============================================================================
# Demarrage de l'application
# =============================================================================

log_info "Demarrage du serveur Gunicorn..."
log_info "Ecoute sur: http://0.0.0.0:${AD_WEB_PORT:-5000}"

# Executer la commande passee en argument ou gunicorn par defaut
if [ $# -eq 0 ]; then
    exec gunicorn \
        --bind "0.0.0.0:${AD_WEB_PORT:-5000}" \
        --workers "${GUNICORN_WORKERS:-4}" \
        --threads "${GUNICORN_THREADS:-2}" \
        --timeout "${GUNICORN_TIMEOUT:-120}" \
        --access-logfile - \
        --error-logfile - \
        --capture-output \
        app:app
else
    exec "$@"
fi
