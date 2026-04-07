"""
Module de detection automatique du serveur Active Directory.
Detecte le domaine, le serveur LDAP et la base DN automatiquement.
"""

import socket
import struct
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def get_local_domain() -> Optional[str]:
    """
    Obtenir le domaine local depuis le nom d'hôte ou DNS.
    
    Returns:
        Nom de domaine ou None
    """
    try:
        # Obtenir le nom d'hôte complet
        hostname = socket.getfqdn()
        parts = hostname.split('.', 1)
        if len(parts) > 1:
            return parts[1]
    except Exception as e:
        logger.warning(f"Impossible de detecter le domaine local: {e}")
    return None


def detect_dns_server(domain: str) -> Optional[str]:
    """
    Detecter le serveur DNS (souvent le DC) pour un domaine donné.
    
    Args:
        domain: Nom de domaine à rechercher
        
    Returns:
        Adresse IP du serveur ou None
    """
    try:
        # Rechercher l'enregistrement SRV _ldap._tcp.dc._msdcs.<domain>
        query = f"_ldap._tcp.dc._msdcs.{domain}"
        answers = socket.getaddrinfo(query, None, socket.AF_INET, socket.SOCK_STREAM)
        if answers:
            return answers[0][4][0]
    except Exception as e:
        logger.warning(f"Impossible de detecter le serveur LDAP pour {domain}: {e}")
    return None


def detect_ldap_servers(domain: str) -> list:
    """
    Detecter les serveurs LDAP pour un domaine donné.
    
    Args:
        domain: Nom de domaine
        
    Returns:
        Liste des adresses IP des serveurs LDAP
    """
    servers = []
    
    try:
        # Méthode 1: DNS SRV records
        srv_records = [
            f"_ldap._tcp.{domain}",
            f"_ldap._tcp.dc._msdcs.{domain}",
            f"_gc._tcp.{domain}"
        ]
        
        for record in srv_records:
            try:
                answers = socket.getaddrinfo(record, None, socket.AF_INET, socket.SOCK_STREAM)
                for answer in answers:
                    ip = answer[4][0]
                    if ip not in servers:
                        servers.append(ip)
            except:
                continue
                
    except Exception as e:
        logger.warning(f"Erreur detection serveurs LDAP: {e}")
    
    # Méthode 2: Résolution simple du domaine
    if not servers:
        try:
            ip = socket.gethostbyname(domain)
            servers.append(ip)
        except:
            pass
    
    return servers


def domain_to_base_dn(domain: str) -> str:
    """
    Convertir un nom de domaine en Base DN.
    
    Args:
        domain: Nom de domaine (ex: exemple.com)
        
    Returns:
        Base DN (ex: DC=exemple,DC=com)
    """
    if not domain:
        return ""
    
    parts = domain.split('.')
    return ','.join([f"DC={part}" for part in parts])


def detect_ad_config() -> dict:
    """
    Detecter automatiquement la configuration AD.
    
    Returns:
        Dictionnaire avec:
        - server: Adresse du serveur AD
        - port: Port (389 ou 636)
        - use_ssl: False par défaut
        - base_dn: Base DN détecté
        - domain: Domaine détecté
        - auto_detected: True
    """
    result = {
        'server': '',
        'port': 389,
        'use_ssl': False,
        'base_dn': '',
        'domain': '',
        'auto_detected': False,
        'servers_found': []
    }
    
    # 1. Détecter le domaine local
    domain = get_local_domain()
    if not domain:
        logger.info("Aucun domaine local detecte")
        return result
    
    result['domain'] = domain
    result['base_dn'] = domain_to_base_dn(domain)
    result['auto_detected'] = True
    
    # 2. Détecter les serveurs LDAP
    servers = detect_ldap_servers(domain)
    result['servers_found'] = servers
    
    if servers:
        result['server'] = servers[0]
        logger.info(f"Serveur AD detecte: {result['server']} (domaine: {domain})")
    else:
        logger.info(f"Domaine detecte: {domain}, aucun serveur LDAP trouve")
    
    return result


def test_ldap_connection(server: str, port: int = 389, timeout: int = 2) -> bool:
    """
    Tester rapidement si un port LDAP est ouvert.
    
    Args:
        server: Adresse du serveur
        port: Port à tester
        timeout: Délai d'attente en secondes
        
    Returns:
        True si le port est ouvert
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((server, port))
        sock.close()
        return result == 0
    except:
        return False


def find_working_server(servers: list) -> Optional[str]:
    """
    Trouver le premier serveur LDAP fonctionnel.
    
    Args:
        servers: Liste des adresses IP à tester
        
    Returns:
        Adresse du premier serveur fonctionnel ou None
    """
    for server in servers:
        # Tester port 389 (LDAP)
        if test_ldap_connection(server, 389):
            return server
        # Tester port 636 (LDAPS)
        if test_ldap_connection(server, 636):
            return server
    
    return None
