#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Agent de surveillance des logs AD Web Interface
Surveille server.log et affiche les erreurs/warnings en temps reel
"""

import os
import time
import re
from datetime import datetime

LOG_FILE = r'C:\AD-WebInterface\logs\server.log'
PATTERNS = [
    r'ERROR',
    r'WARNING',
    r'Exception',
    r'failed',
    r'echou',
    r'refuse',
]

def tail_file(filepath, callback, interval=2):
    """Surveille un fichier comme `tail -f`."""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        # Aller a la fin du fichier
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            if line:
                callback(line.strip())
            else:
                time.sleep(interval)

def should_alert(line):
    """Verifier si la ligne contient une alerte."""
    line_lower = line.lower()
    for pattern in PATTERNS:
        if pattern.lower() in line_lower:
            return True
    return False

def format_alert(line):
    """Formater une alerte pour l'affichage."""
    timestamp = datetime.now().strftime('%H:%M:%S')
    
    if 'ERROR' in line or 'Exception' in line:
        return f"[{timestamp}] ❌ {line}"
    elif 'WARNING' in line:
        return f"[{timestamp}] ⚠️ {line}"
    else:
        return f"[{timestamp}] 🔔 {line}"

def main():
    print("=" * 60)
    print("  🔍 Agent de surveillance des logs AD Web Interface")
    print("=" * 60)
    print(f"  Fichier: {LOG_FILE}")
    print(f"  Patterns: {', '.join(PATTERNS)}")
    print("=" * 60)
    print("  Appuyez sur Ctrl+C pour arreter")
    print("=" * 60)
    print()
    
    def process_line(line):
        if should_alert(line):
            print(format_alert(line))
    
    try:
        tail_file(LOG_FILE, process_line, interval=1)
    except KeyboardInterrupt:
        print("\n\n🛑 Surveillance arretee par l'utilisateur")
    except FileNotFoundError:
        print(f"❌ Fichier non trouve: {LOG_FILE}")
    except Exception as e:
        print(f"❌ Erreur: {e}")

if __name__ == '__main__':
    main()