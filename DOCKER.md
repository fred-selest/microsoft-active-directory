# Guide Docker - AD Web Interface

Ce guide explique comment deployer AD Web Interface avec Docker.

## Prerequis

- Docker 20.10+
- Docker Compose 2.0+ (optionnel mais recommande)
- Acces reseau vers votre controleur de domaine Active Directory

## Demarrage rapide

### Option 1: Docker Compose (recommande)

```bash
# Cloner le depot
git clone https://github.com/fred-selest/microsoft-active-directory.git
cd microsoft-active-directory

# Creer le fichier de configuration
cp .env.example .env

# Editer la configuration
nano .env  # ou votre editeur prefere

# Demarrer
docker-compose up -d
```

### Option 2: Docker simple

```bash
# Telecharger l'image
docker pull ghcr.io/fred-selest/microsoft-active-directory:latest

# Demarrer le container
docker run -d \
  --name ad-web-interface \
  -p 5000:5000 \
  -e SECRET_KEY=votre-cle-secrete-generee \
  -e AD_SERVER=dc.example.com \
  -e AD_BASE_DN=DC=example,DC=com \
  -v ad-logs:/app/logs \
  -v ad-data:/app/data \
  ghcr.io/fred-selest/microsoft-active-directory:latest
```

## Configuration

### Variables d'environnement

| Variable | Description | Defaut | Obligatoire |
|----------|-------------|--------|-------------|
| `SECRET_KEY` | Cle secrete pour sessions/CSRF | - | **Oui** |
| `AD_SERVER` | Serveur Active Directory | - | Non* |
| `AD_PORT` | Port LDAP | 389 | Non |
| `AD_USE_SSL` | Utiliser LDAPS | false | Non |
| `AD_BASE_DN` | Base DN de recherche | - | Non* |
| `SESSION_TIMEOUT` | Timeout session (minutes) | 30 | Non |
| `FORCE_HTTPS` | Forcer redirection HTTPS | false | Non |
| `RBAC_ENABLED` | Activer controle d'acces | true | Non |
| `DEFAULT_ROLE` | Role par defaut | reader | Non |

> *Peut etre configure via l'interface web

### Generer une SECRET_KEY

```bash
python -c 'import secrets; print(secrets.token_hex(32))'
```

### Exemple de fichier .env

```env
# Configuration obligatoire
SECRET_KEY=a1b2c3d4e5f6...votre-cle-generee

# Configuration Active Directory
AD_SERVER=dc.mondomaine.local
AD_PORT=389
AD_USE_SSL=false
AD_BASE_DN=DC=mondomaine,DC=local

# Securite
FORCE_HTTPS=true
SESSION_TIMEOUT=30

# RBAC
RBAC_ENABLED=true
DEFAULT_ROLE=reader
```

## Deploiement en production

### Avec reverse proxy Nginx

```yaml
# docker-compose.yml
version: '3.8'

services:
  ad-web-interface:
    image: ghcr.io/fred-selest/microsoft-active-directory:latest
    container_name: ad-web-interface
    restart: unless-stopped
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - AD_SERVER=${AD_SERVER}
      - AD_BASE_DN=${AD_BASE_DN}
      - FORCE_HTTPS=true
    volumes:
      - ad-logs:/app/logs
      - ad-data:/app/data
    networks:
      - web

  nginx:
    image: nginx:alpine
    container_name: nginx-proxy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/ssl:ro
    networks:
      - web
    depends_on:
      - ad-web-interface

volumes:
  ad-logs:
  ad-data:

networks:
  web:
```

### Configuration Nginx

```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream app {
        server ad-web-interface:5000;
    }

    # Redirection HTTP -> HTTPS
    server {
        listen 80;
        server_name ad.example.com;
        return 301 https://$server_name$request_uri;
    }

    # HTTPS
    server {
        listen 443 ssl http2;
        server_name ad.example.com;

        ssl_certificate /etc/ssl/cert.pem;
        ssl_certificate_key /etc/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;

        location / {
            proxy_pass http://app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

### Avec Traefik

```yaml
# docker-compose.yml avec Traefik
version: '3.8'

services:
  ad-web-interface:
    image: ghcr.io/fred-selest/microsoft-active-directory:latest
    restart: unless-stopped
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - AD_SERVER=${AD_SERVER}
      - AD_BASE_DN=${AD_BASE_DN}
      - FORCE_HTTPS=true
    volumes:
      - ad-logs:/app/logs
      - ad-data:/app/data
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.ad-web.rule=Host(`ad.example.com`)"
      - "traefik.http.routers.ad-web.entrypoints=websecure"
      - "traefik.http.routers.ad-web.tls.certresolver=letsencrypt"
      - "traefik.http.services.ad-web.loadbalancer.server.port=5000"
    networks:
      - traefik

volumes:
  ad-logs:
  ad-data:

networks:
  traefik:
    external: true
```

## Commandes utiles

```bash
# Voir les logs
docker-compose logs -f

# Redemarrer
docker-compose restart

# Arreter
docker-compose down

# Mise a jour
docker-compose pull
docker-compose up -d

# Executer une commande dans le container
docker exec -it ad-web-interface bash

# Verifier le statut
docker exec ad-web-interface curl -s http://localhost:5000/api/health
```

## Healthcheck

L'image inclut un healthcheck automatique sur `/api/health`.

```bash
# Verifier manuellement
curl http://localhost:5000/api/health
```

Reponse attendue:
```json
{
  "status": "healthy",
  "version": "1.13.0",
  "platform": "Linux"
}
```

## Volumes et persistance

| Volume | Chemin | Description |
|--------|--------|-------------|
| `ad-logs` | `/app/logs` | Journaux d'audit |
| `ad-data` | `/app/data` | Donnees (sauvegardes, cache, etc.) |

### Sauvegarder les donnees

```bash
# Backup
docker run --rm -v ad-data:/data -v $(pwd):/backup alpine tar czf /backup/ad-data-backup.tar.gz -C /data .

# Restore
docker run --rm -v ad-data:/data -v $(pwd):/backup alpine tar xzf /backup/ad-data-backup.tar.gz -C /data
```

## Construire l'image localement

```bash
# Build
docker build -t ad-web-interface:local .

# Test
docker run --rm -p 5000:5000 -e SECRET_KEY=test-key -e FLASK_DEBUG=true ad-web-interface:local
```

## Troubleshooting

### Le container ne demarre pas

```bash
# Verifier les logs
docker logs ad-web-interface

# Causes frequentes:
# - SECRET_KEY non definie ou trop courte
# - Port 5000 deja utilise
# - Erreur de syntaxe dans .env
```

### Impossible de se connecter a AD

```bash
# Tester la connectivite depuis le container
docker exec ad-web-interface python -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex(('dc.example.com', 389))
print('OK' if result == 0 else 'ECHEC')
"
```

### Probleme de permissions

```bash
# Verifier les permissions des volumes
docker exec ad-web-interface ls -la /app/logs /app/data
```

## Support

- Issues: https://github.com/fred-selest/microsoft-active-directory/issues
- Documentation: https://github.com/fred-selest/microsoft-active-directory

## Licence

MIT License
