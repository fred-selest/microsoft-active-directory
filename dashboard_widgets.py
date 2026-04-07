"""
Widgets pour le Dashboard - Données en temps réel
"""
from datetime import datetime, timedelta
from audit_history import get_audit_history, get_history_stats
from alerts import get_alerts, get_alert_counts


def get_dashboard_widgets():
    """
    Obtenir les données pour les widgets du dashboard.
    
    Returns:
        dict: Données pour les widgets
    """
    widgets = {
        'alerts': [],
        'score_evolution': [],
        'quick_stats': {},
        'recent_actions': []
    }
    
    # 1. Alertes critiques
    try:
        alerts = get_alerts(limit=5)
        widgets['alerts'] = alerts[:5] if alerts else []
        
        audits = get_audit_history(limit=1)
        if audits:
            audit = audits[0]
            widgets['score_evolution'] = {
                'current': audit.get('score', 0),
                'trend': 'stable',
                'last_audit': audit.get('timestamp', '')
            }
    except Exception:
        pass
    
    # 2. Statistiques rapides
    try:
        stats = get_history_stats()
        widgets['quick_stats'] = {
            'total_audits': stats.get('total_audits', 0),
            'avg_score': round(stats.get('avg_score', 0), 1),
            'best_score': stats.get('best_score', 0),
            'trend': stats.get('trend', 'stable'),
            'critical_count': 0,
            'warning_count': 0
        }
        
        # Compter critiques et warnings depuis les alertes
        if widgets['alerts']:
            widgets['quick_stats']['critical_count'] = len([a for a in widgets['alerts'] if a.get('severity') == 'critical'])
            widgets['quick_stats']['warning_count'] = len([a for a in widgets['alerts'] if a.get('severity') == 'high'])
    except Exception:
        widgets['quick_stats'] = {
            'total_audits': 0,
            'avg_score': 0,
            'best_score': 0,
            'trend': 'stable',
            'critical_count': 0,
            'warning_count': 0
        }
    
    # 3. Actions récentes
    try:
        from audit import get_audit_logs
        widgets['recent_actions'] = get_audit_logs(limit=5)
    except Exception:
        pass
    
    return widgets


def get_action_required_count():
    """
    Obtenir le nombre d'actions requises.
    
    Returns:
        int: Nombre d'actions critiques
    """
    count = 0
    
    try:
        audits = get_audit_history(limit=1)
        if audits:
            audit = audits[0]
            count = audit.get('critical_issues', 0)
    except Exception:
        pass
    
    return count
