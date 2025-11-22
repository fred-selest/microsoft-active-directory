# =============================================================================
# Dockerfile pour AD Web Interface
# Interface Web pour Microsoft Active Directory
# =============================================================================

FROM python:3.11-slim

# Metadata
LABEL maintainer="fred-selest"
LABEL version="1.12.0"
LABEL description="Interface Web pour Microsoft Active Directory"

# Variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    AD_WEB_HOST=0.0.0.0 \
    AD_WEB_PORT=5000 \
    AD_LOG_DIR=/app/logs \
    AD_DATA_DIR=/app/data

# Repertoire de travail
WORKDIR /app

# Installer les dependances systeme
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copier et installer les dependances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

# Copier le code source
COPY . .

# Creer les repertoires necessaires
RUN mkdir -p /app/logs /app/data \
    && chmod 755 /app/logs /app/data

# Supprimer les fichiers Windows inutiles
RUN rm -f *.bat *.vbs *.ps1 2>/dev/null || true

# Utilisateur non-root pour la securite
RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app
USER appuser

# Exposer le port
EXPOSE 5000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')" || exit 1

# Point d'entree
COPY --chown=appuser:appuser docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh 2>/dev/null || true

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "app:app"]
