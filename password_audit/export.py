"""Export des résultats d'audit (CSV, JSON)."""
import csv
import json
from io import StringIO
from datetime import datetime


def export_audit_to_csv(audit_result, filename='password_audit.csv'):
    """Exporter les résultats de l'audit en CSV (format Specops Password Auditor)."""
    output = StringIO()
    writer = csv.writer(output, delimiter=';')
    
    # En-tête style Specops
    writer.writerow([
        'Compte',
        'SamAccountName',
        'Dn',
        'Admin [Brutes]',
        'Admin',
        'Mot de passe modifié [Brutes]',
        'Mot de passe modifié',
        'Vieillissement basé sur la longueur [Brutes]',
        'Vieillissement basé sur la longueur',
        'Remarque',
        'Politique de mot de passe'
    ])
    
    # Collecter tous les comptes dans un dictionnaire unique
    all_accounts = {}
    
    # Comptes avec configurations faibles
    for acc in audit_result.get('weak_accounts', []):
        sam = acc.get('username', acc.get('sAMAccountName', ''))
        if sam and sam not in all_accounts:
            all_accounts[sam] = {
                'displayName': acc.get('display_name', sam),
                'dn': acc.get('dn', ''),
                'is_admin': acc.get('is_admin', False),
                'pwd_last_set': acc.get('pwd_last_set', None),
                'password_never_expires': acc.get('password_never_expires', False),
                'type': acc.get('type', '')
            }
    
    # Comptes admin
    for acc in audit_result.get('admin_weak_accounts', []):
        sam = acc.get('username', '')
        if sam and sam not in all_accounts:
            all_accounts[sam] = {
                'displayName': acc.get('display_name', sam),
                'dn': acc.get('dn', ''),
                'is_admin': True,
                'pwd_last_set': acc.get('pwd_last_set', None),
                'password_never_expires': acc.get('password_never_expires', False),
                'type': acc.get('type', '')
            }
        elif sam:
            all_accounts[sam]['is_admin'] = True
    
    # Comptes de service
    for acc in audit_result.get('service_accounts', []):
        sam = acc.get('username', '')
        if sam and sam not in all_accounts:
            all_accounts[sam] = {
                'displayName': acc.get('display_name', sam),
                'dn': acc.get('dn', ''),
                'is_admin': False,
                'pwd_last_set': acc.get('pwd_last_set', None),
                'password_never_expires': acc.get('password_never_expires', False),
                'type': acc.get('type', '')
            }
    
    # Mots de passe anciens
    for acc in audit_result.get('old_passwords', []):
        sam = acc.get('username', acc.get('sAMAccountName', ''))
        if sam and sam not in all_accounts:
            all_accounts[sam] = {
                'displayName': acc.get('display_name', sam),
                'dn': acc.get('dn', ''),
                'is_admin': False,
                'pwd_last_set': acc.get('pwdLastSet', None),
                'password_never_expires': False,
                'type': 'old_password'
            }
        elif sam:
            if acc.get('pwdLastSet'):
                all_accounts[sam]['pwd_last_set'] = acc.get('pwdLastSet')
    
    # Écrire les données
    now = datetime.now()
    policy = audit_result.get('policy', {})
    policy_name = f"{policy.get('domain', 'SELEST')}.local"
    
    for sam, acc in sorted(all_accounts.items()):
        display_name = acc.get('displayName', sam)
        dn = acc.get('dn', '')
        is_admin = acc.get('is_admin', False)
        pwd_last_set = acc.get('pwd_last_set')
        
        # Formatage de la date
        if pwd_last_set:
            if isinstance(pwd_last_set, datetime):
                pwd_date = pwd_last_set
            else:
                try:
                    pwd_date = datetime.strptime(str(pwd_last_set)[:19], '%Y-%m-%d %H:%M:%S')
                except:
                    pwd_date = now
        else:
            pwd_date = datetime(2000, 1, 1)
        
        pwd_date_str = pwd_date.strftime('%Y-%m-%d %H:%M')
        days_old = (now - pwd_date).days
        pwd_modified = f"{pwd_date_str};{days_old} il y a quelques jours"
        
        # Admin
        admin_brutes = str(is_admin)
        admin_text = 'Oui' if is_admin else 'Non'
        
        # Vieillissement basé sur la longueur (si mot de passe > 90 jours)
        aging = days_old > 90
        aging_brutes = str(aging)
        aging_text = 'Oui' if aging else 'Non'
        
        # Remarque
        remarks = []
        if acc.get('password_never_expires'):
            remarks.append('Mot de passe n\'expire jamais')
        if is_admin:
            remarks.append('Compte administrateur')
        if 'service' in acc.get('type', ''):
            remarks.append('Compte de service')
        if days_old > 365:
            remarks.append(f'Mot de passe ancien ({days_old} jours)')
        remark = ';'.join(remarks) if remarks else 'Normal'
        
        writer.writerow([
            display_name,
            sam,
            dn,
            admin_brutes,
            admin_text,
            pwd_modified,
            pwd_modified,
            aging_brutes,
            aging_text,
            remark,
            policy_name
        ])
    
    output.seek(0)
    return output.getvalue()


def export_audit_to_json(audit_result, filename='password_audit.json'):
    """Exporter les résultats de l'audit en JSON."""
    return json.dumps(audit_result, indent=2, default=str)
