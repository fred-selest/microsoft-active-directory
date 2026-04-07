#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Agent de surveillance des logs AD Web Interface - Version simplifiee
"""

import os
import time
import re
from datetime import datetime

LOG_FILE = r'C:\AD-WebInterface\logs\server.log'
ALERT_FILE = r'C:\AD-WebInterface\logs\live_alerts.txt'

def get_last_lines(filepath, n=50):
    """Lire les n dernieres lignes d'un fichier."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            return lines[-n:] if lines else []
    except:
        return []

def extract_alerts(lines):
    """Extraire les alertes des lignes."""
    alerts = []
    patterns = ['ERROR', 'WARNING', 'Exception', 'echou', 'refuse', 'failed']
    
    for line in lines:
        line_lower = line.lower()
        for pattern in patterns:
            if pattern.lower() in line_lower:
                alerts.append(line.strip())
                break
    
    return alerts

def main():
    print("=" * 60)
    print("  Agent de surveillance des logs")
    print("=" * 60)
    
    last_size = 0
    
    while True:
        try:
            # Verifier la taille du fichier
            current_size = os.path.getsize(LOG_FILE)
            
            if current_size != last_size:
                # Lire les nouvelles lignes
                lines = get_last_lines(LOG_FILE, 30)
                alerts = extract_alerts(lines)
                
                if alerts:
                    # Ecrire les alertes dans le fichier
                    with open(ALERT_FILE, 'w', encoding='utf-8') as f:
                        for alert in alerts:
                            f.write(alert + '\n')
                    
                    # Afficher les alertes
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {len(alerts)} alerte(s) detectee(s):")
                    for alert in alerts[-5:]:  # Afficher les 5 dernieres
                        if 'ERROR' in alert:
                            print(f"  ERROR: {alert[:100]}")
                        elif 'WARNING' in alert:
                            print(f"  WARNING: {alert[:100]}")
                        else:
                            print(f"  ALERT: {alert[:100]}")
                
                last_size = current_size
            
            time.sleep(3)
            
        except KeyboardInterrupt:
            print("\nSurveillance arretee")
            break
        except Exception as e:
            print(f"Erreur: {e}")
            time.sleep(5)

if __name__ == '__main__':
    main()