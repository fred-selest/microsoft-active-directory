"""
Historique des Audits - Stockage et récupération des audits précédents
"""
import json
import os
from datetime import datetime
from pathlib import Path

# Répertoire de stockage
HISTORY_DIR = Path('data/audit_history')
HISTORY_DIR.mkdir(parents=True, exist_ok=True)


def save_audit(audit_result, domain_name='Unknown'):
    """
    Sauvegarder un résultat d'audit dans l'historique.
    
    Args:
        audit_result: Dictionnaire contenant les résultats de l'audit
        domain_name: Nom du domaine AD
    
    Returns:
        str: ID de l'audit sauvegardé
    """
    timestamp = datetime.now()
    audit_id = timestamp.strftime('%Y%m%d_%H%M%S')
    
    audit_data = {
        'id': audit_id,
        'timestamp': timestamp.isoformat(),
        'domain_name': domain_name,
        'score': audit_result.get('summary', {}).get('global_score', 0),
        'score_color': audit_result.get('summary', {}).get('score_color', 'unknown'),
        'total_issues': audit_result.get('summary', {}).get('total_issues', 0),
        'critical_issues': audit_result.get('summary', {}).get('critical_issues', 0),
        'warning_issues': audit_result.get('summary', {}).get('warning_issues', 0),
        'accounts_audited': audit_result.get('summary', {}).get('accounts_audited', 0),
        'policy_compliant': audit_result.get('summary', {}).get('policy_compliant', False),
        'recommendations_count': len(audit_result.get('recommendations', [])),
    }
    
    # Sauvegarder dans un fichier JSON
    filepath = HISTORY_DIR / f'{audit_id}.json'
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(audit_data, f, indent=2, ensure_ascii=False)
    
    return audit_id


def get_audit_history(limit=20):
    """
    Récupérer l'historique des audits.
    
    Args:
        limit: Nombre maximum d'audits à retourner
    
    Returns:
        list: Liste des audits triés par date (plus récent en premier)
    """
    audits = []
    
    for filepath in HISTORY_DIR.glob('*.json'):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                audit = json.load(f)
                audits.append(audit)
        except Exception:
            continue
    
    # Trier par date (décroissant)
    audits.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return audits[:limit]


def get_audit_by_id(audit_id):
    """
    Récupérer un audit spécifique par son ID.
    
    Args:
        audit_id: ID de l'audit
    
    Returns:
        dict: Données de l'audit ou None si non trouvé
    """
    filepath = HISTORY_DIR / f'{audit_id}.json'
    
    if not filepath.exists():
        return None
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def get_audit_evolution(days=90):
    """
    Obtenir l'évolution du score sur une période.
    
    Args:
        days: Nombre de jours à analyser
    
    Returns:
        dict: Données pour graphique d'évolution
    """
    from datetime import timedelta
    
    cutoff_date = datetime.now() - timedelta(days=days)
    audits = get_audit_history(limit=100)  # Récupérer plus pour filtrer ensuite
    
    # Filtrer par date
    filtered = []
    for audit in audits:
        try:
            audit_date = datetime.fromisoformat(audit.get('timestamp', ''))
            if audit_date >= cutoff_date:
                filtered.append(audit)
        except Exception:
            continue
    
    # Préparer les données pour le graphique
    evolution_data = {
        'dates': [],
        'scores': [],
        'critical': [],
        'warnings': [],
        'labels': []
    }
    
    # Inverser pour avoir du plus ancien au plus récent
    filtered.reverse()
    
    for audit in filtered:
        try:
            audit_date = datetime.fromisoformat(audit.get('timestamp', ''))
            evolution_data['dates'].append(audit_date.strftime('%d/%m'))
            evolution_data['scores'].append(audit.get('score', 0))
            evolution_data['critical'].append(audit.get('critical_issues', 0))
            evolution_data['warnings'].append(audit.get('warning_issues', 0))
            evolution_data['labels'].append(f"Score: {audit.get('score', 0)}")
        except Exception:
            continue
    
    return evolution_data


def compare_audits(audit_id_1, audit_id_2):
    """
    Comparer deux audits.
    
    Args:
        audit_id_1: Premier audit (plus récent)
        audit_id_2: Deuxième audit (plus ancien)
    
    Returns:
        dict: Comparaison des deux audits
    """
    audit_1 = get_audit_by_id(audit_id_1)
    audit_2 = get_audit_by_id(audit_id_2)
    
    if not audit_1 or not audit_2:
        return {'error': 'Audits non trouvés'}
    
    score_1 = audit_1.get('score', 0)
    score_2 = audit_2.get('score', 0)
    score_diff = score_1 - score_2
    
    return {
        'audit_1': audit_1,
        'audit_2': audit_2,
        'score_diff': score_diff,
        'score_improved': score_diff > 0,
        'score_degraded': score_diff < 0,
        'score_unchanged': score_diff == 0,
        'critical_diff': audit_1.get('critical_issues', 0) - audit_2.get('critical_issues', 0),
        'warning_diff': audit_1.get('warning_issues', 0) - audit_2.get('warning_issues', 0),
        'issues_diff': audit_1.get('total_issues', 0) - audit_2.get('total_issues', 0),
    }


def delete_audit(audit_id):
    """
    Supprimer un audit de l'historique.
    
    Args:
        audit_id: ID de l'audit à supprimer
    
    Returns:
        bool: True si supprimé, False sinon
    """
    filepath = HISTORY_DIR / f'{audit_id}.json'
    
    if filepath.exists():
        try:
            filepath.unlink()
            return True
        except Exception:
            return False
    
    return False


def get_history_stats():
    """
    Obtenir des statistiques sur l'historique.
    
    Returns:
        dict: Statistiques de l'historique
    """
    audits = get_audit_history(limit=100)
    
    if not audits:
        return {
            'total_audits': 0,
            'avg_score': 0,
            'best_score': 0,
            'worst_score': 0,
            'trend': 'stable'
        }
    
    scores = [a.get('score', 0) for a in audits]
    
    # Calculer la tendance (comparer les 5 derniers aux 5 précédents)
    trend = 'stable'
    if len(audits) >= 10:
        recent_avg = sum(scores[:5]) / 5
        older_avg = sum(scores[5:10]) / 5
        
        if recent_avg > older_avg + 5:
            trend = 'improving'
        elif recent_avg < older_avg - 5:
            trend = 'degrading'
    
    return {
        'total_audits': len(audits),
        'avg_score': sum(scores) / len(scores) if scores else 0,
        'best_score': max(scores) if scores else 0,
        'worst_score': min(scores) if scores else 0,
        'trend': trend,
        'first_audit': audits[-1].get('timestamp') if audits else None,
        'last_audit': audits[0].get('timestamp') if audits else None,
    }
