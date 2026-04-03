"""Export des résultats d'audit (CSV, JSON)."""
import csv
import json
from io import StringIO


def export_audit_to_csv(audit_result, filename='password_audit.csv'):
    """Exporter les résultats de l'audit en CSV."""
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Type', 'Utilisateur', 'Nom affiché', 'Email', 'Problème', 'Sévérité', 'Remède'])

    for acc in audit_result.get('weak_accounts', []):
        writer.writerow([acc.get('type', ''), acc.get('username', ''), acc.get('display_name', ''),
                         acc.get('mail', ''), acc.get('issue', ''), acc.get('severity', ''),
                         acc.get('remediation', '')])

    for pwd in audit_result.get('old_passwords', []):
        writer.writerow(['old_password', pwd.get('username', ''), pwd.get('display_name', ''),
                         pwd.get('mail', ''),
                         f"Mot de passe ancien ({pwd.get('days_old', 0)} jours)",
                         pwd.get('severity', ''), pwd.get('remediation', '')])

    output.seek(0)
    return output.getvalue()


def export_audit_to_json(audit_result, filename='password_audit.json'):
    """Exporter les résultats de l'audit en JSON."""
    return json.dumps(audit_result, indent=2, default=str)
