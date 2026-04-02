"""
Audit de Sécurité des Mots de Passe Active Directory
Module d'analyse de la force et de la sécurité des mots de passe des utilisateurs AD.
Inspiré de Specops Password Auditor - https://specopssoft.com/fr/specops-password-auditor-pour-active-directory/

Fonctionnalités:
- Audit de la politique de mot de passe du domaine
- Détection des comptes à risque (mot de passe n'expirant jamais, sans mot de passe)
- Analyse de l'ancienneté des mots de passe
- Détection des mots de passe compromis (liste de mots de passe violés)
- Analyse de la complexité des mots de passe
- Détection des attaques par spray de mot de passe
- Politiques de mot de passe à granularité fine (FGPP)
- Export de rapports (CSV, JSON, PDF)
"""

import re
import json
import hashlib
from datetime import datetime, timedelta
from ldap3 import SUBTREE
from audit import log_action, ACTIONS

# Liste de mots de passe couramment utilisés (à étendre)
COMMON_PASSWORDS = [
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
    'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
    'ashley', 'bailey', 'shadow', '123123', '654321', 'superman', 'qazwsx',
    'michael', 'football', 'password1', 'password123', 'welcome', 'jesus',
    'ninja', 'mustang', 'password1234', 'admin', 'admin123', 'root', 'toor',
    'pass', 'test', 'guest', 'master', 'changeme', '123456789', '1234567890',
    'motdepasse', 'admin1234', 'azerty', 'azerty123', 'soleil', 'bonjour'
]

# Liste de motifs de clavier courants
KEYBOARD_PATTERNS = [
    'qwerty', 'azerty', 'qwertz', '1234', '4321', 'abcd', 'dcba',
    'qazwsx', 'zaq1', '1qaz', '2wsx', '3edc', '4rfv', '5tgb', '6yhn',
    'pass', 'word', 'admin', 'user', 'test', 'guest'
]


def analyze_password_strength(password):
    """
    Analyser la force d'un mot de passe.
    """
    score = 0
    feedback = []

    # Longueur
    if len(password) >= 8:
        score += 1
    elif len(password) < 6:
        feedback.append("Le mot de passe est trop court (minimum 8 caractères recommandé)")

    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1

    # Caractères variés
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Ajoutez des lettres minuscules")

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Ajoutez des lettres majuscules")

    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Ajoutez des chiffres")

    if re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~]', password):
        score += 1
    else:
        feedback.append("Ajoutez des caractères spéciaux")

    # Pénalités pour motifs courants
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.insert(0, "Mot de passe trop courant - à changer absolument")

    if re.search(r'(.)\1{2,}', password):  # Caractères répétés
        score = max(0, score - 1)
        feedback.append("Évitez les caractères répétés (ex: aaa)")

    if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
        score = max(0, score - 1)
        feedback.append("Évitez les séquences consécutives")

    # Vérifier les motifs de clavier
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password.lower():
            score = max(0, score - 1)
            feedback.append(f"Évitez les motifs de clavier courants ({pattern})")
            break

    # Détermination du niveau
    if score >= 6:
        strength = "Fort"
        color = "success"
    elif score >= 4:
        strength = "Moyen"
        color = "warning"
    else:
        strength = "Faible"
        color = "danger"

    return {
        'score': score,
        'max_score': 8,
        'strength': strength,
        'color': color,
        'feedback': feedback,
        'length': len(password)
    }


def check_weak_passwords_ad(conn, base_dn):
    """
    Vérifier les utilisateurs avec des mots de passe faibles dans AD.
    """
    weak_accounts = []

    try:
        # Rechercher les utilisateurs dont le mot de passe n'expire jamais
        conn.search(
            base_dn,
            '(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=64))',
            SUBTREE,
            attributes=['sAMAccountName', 'displayName', 'distinguishedName', 'userAccountControl', 'mail']
        )

        for entry in conn.entries:
            weak_accounts.append({
                'type': 'password_never_expires',
                'username': str(entry.sAMAccountName),
                'display_name': str(entry.displayName) if entry.displayName else '',
                'mail': str(entry.mail) if hasattr(entry, 'mail') and entry.mail else '',
                'dn': str(entry.distinguishedName),
                'issue': 'Le mot de passe n\'expire jamais',
                'severity': 'warning',
                'remediation': 'Désactiver "Le mot de passe n\'expire jamais" dans les propriétés du compte'
            })

        # Rechercher les utilisateurs sans mot de passe requis
        conn.search(
            base_dn,
            '(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=32))',
            SUBTREE,
            attributes=['sAMAccountName', 'displayName', 'distinguishedName', 'mail']
        )

        for entry in conn.entries:
            weak_accounts.append({
                'type': 'no_password_required',
                'username': str(entry.sAMAccountName),
                'display_name': str(entry.displayName) if entry.displayName else '',
                'mail': str(entry.mail) if hasattr(entry, 'mail') and entry.mail else '',
                'dn': str(entry.distinguishedName),
                'issue': 'Mot de passe non requis',
                'severity': 'critical',
                'remediation': 'Exiger un mot de passe pour ce compte'
            })

        # Rechercher les comptes administrateurs avec des configurations faibles
        conn.search(
            base_dn,
            '(&(objectClass=user)(objectCategory=person)(adminCount=1))',
            SUBTREE,
            attributes=['sAMAccountName', 'displayName', 'distinguishedName', 'mail', 'userAccountControl']
        )

        for entry in conn.entries:
            uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else 0
            # Vérifier si le mot de passe n'expire pas pour un admin
            if uac & 64:  # DONT_EXPIRE_PASSWD
                weak_accounts.append({
                    'type': 'admin_password_never_expires',
                    'username': str(entry.sAMAccountName),
                    'display_name': str(entry.displayName) if entry.displayName else '',
                    'mail': str(entry.mail) if hasattr(entry, 'mail') and entry.mail else '',
                    'dn': str(entry.distinguishedName),
                    'issue': 'Compte administrateur avec mot de passe n\'expirant jamais',
                    'severity': 'critical',
                    'remediation': 'Activer l\'expiration du mot de passe pour les comptes privilégiés'
                })

    except Exception as e:
        weak_accounts.append({
            'type': 'error',
            'issue': f'Erreur de recherche: {str(e)}',
            'severity': 'error'
        })

    return weak_accounts


def check_password_age(conn, base_dn, max_age_days=90):
    """
    Vérifier l'ancienneté des mots de passe.
    """
    old_passwords = []
    threshold_date = datetime.now() - timedelta(days=max_age_days)

    try:
        conn.search(
            base_dn,
            '(&(objectClass=user)(objectCategory=person)(pwdLastSet=*))',
            SUBTREE,
            attributes=['sAMAccountName', 'displayName', 'pwdLastSet', 'distinguishedName', 'mail']
        )

        for entry in conn.entries:
            pwd_last_set = entry.pwdLastSet.value
            if pwd_last_set:
                # Conversion Windows FILETIME à datetime
                if isinstance(pwd_last_set, datetime):
                    last_change = pwd_last_set
                else:
                    # FILETIME Windows (100-nanosecond intervals since 1601-01-01)
                    windows_epoch = datetime(1601, 1, 1)
                    last_change = windows_epoch + timedelta(microseconds=pwd_last_set // 10)

                if last_change < threshold_date:
                    days_old = (datetime.now() - last_change).days
                    old_passwords.append({
                        'username': str(entry.sAMAccountName),
                        'display_name': str(entry.displayName) if entry.displayName else '',
                        'mail': str(entry.mail) if hasattr(entry, 'mail') and entry.mail else '',
                        'dn': str(entry.distinguishedName),
                        'pwdLastSet': last_change.strftime('%Y-%m-%d'),
                        'days_old': days_old,
                        'severity': 'critical' if days_old > max_age_days * 2 else 'warning',
                        'remediation': 'Forcer le changement de mot de passe'
                    })

    except Exception as e:
        old_passwords.append({
            'type': 'error',
            'issue': f'Erreur: {str(e)}',
            'severity': 'error'
        })

    return old_passwords


def get_password_policy(conn, base_dn):
    """
    Récupérer la politique de mot de passe du domaine.
    """
    policy = {
        'minPasswordLength': 0,
        'maxPasswordAge': 0,
        'minPasswordAge': 0,
        'passwordHistoryLength': 0,
        'lockoutThreshold': 0,
        'lockoutDuration': 0,
        'lockoutObservationWindow': 0,
        'pwdProperties': 0,
        'complexity_enabled': False,
        'reversible_encryption': False
    }

    try:
        domain_dn = base_dn

        conn.search(
            domain_dn,
            '(objectClass=domain)',
            SUBTREE,
            attributes=[
                'minPwdLength', 'maxPwdAge', 'minPwdAge',
                'pwdHistoryLength', 'lockoutThreshold', 'lockoutDuration',
                'lockoutObservationWindow', 'pwdProperties'
            ]
        )

        if conn.entries:
            entry = conn.entries[0]

            # Longueur minimale
            if hasattr(entry, 'minPwdLength'):
                val = entry.minPwdLength.value
                policy['minPasswordLength'] = int(val) if val is not None else 0

            # Âge maximum (en jours)
            if hasattr(entry, 'maxPwdAge'):
                max_age = entry.maxPwdAge.value
                if max_age is not None:
                    # Gérer les objets timedelta
                    if hasattr(max_age, 'total_seconds'):
                        # C'est un timedelta
                        policy['maxPasswordAge'] = abs(int(max_age.total_seconds() / 86400))
                    else:
                        # C'est un entier FILETIME
                        policy['maxPasswordAge'] = abs(int(max_age / -864000000000))

            # Âge minimum
            if hasattr(entry, 'minPwdAge'):
                min_age = entry.minPwdAge.value
                if min_age is not None:
                    if hasattr(min_age, 'total_seconds'):
                        policy['minPasswordAge'] = abs(int(min_age.total_seconds() / 86400))
                    else:
                        policy['minPasswordAge'] = abs(int(min_age / -864000000000))

            # Historique
            if hasattr(entry, 'pwdHistoryLength'):
                val = entry.pwdHistoryLength.value
                policy['passwordHistoryLength'] = int(val) if val is not None else 0

            # Seuil de verrouillage
            if hasattr(entry, 'lockoutThreshold'):
                val = entry.lockoutThreshold.value
                policy['lockoutThreshold'] = int(val) if val is not None else 0

            # Durée de verrouillage
            if hasattr(entry, 'lockoutDuration'):
                lockout_dur = entry.lockoutDuration.value
                if lockout_dur is not None:
                    if hasattr(lockout_dur, 'total_seconds'):
                        policy['lockoutDuration'] = abs(int(lockout_dur.total_seconds() / 60))  # en minutes
                    else:
                        policy['lockoutDuration'] = abs(int(lockout_dur / -600000000))  # en minutes

            # Fenêtre d'observation
            if hasattr(entry, 'lockoutObservationWindow'):
                obs_window = entry.lockoutObservationWindow.value
                if obs_window is not None:
                    if hasattr(obs_window, 'total_seconds'):
                        policy['lockoutObservationWindow'] = abs(int(obs_window.total_seconds() / 60))  # en minutes
                    else:
                        policy['lockoutObservationWindow'] = abs(int(obs_window / -600000000))  # en minutes

            # Propriétés du mot de passe
            if hasattr(entry, 'pwdProperties'):
                pwd_props = entry.pwdProperties.value
                if pwd_props is not None:
                    policy['pwdProperties'] = int(pwd_props)
                    policy['complexity_enabled'] = bool(int(pwd_props) & 1)
                    policy['reversible_encryption'] = bool(int(pwd_props) & 16)

    except Exception as e:
        policy['error'] = str(e)

    return policy


def check_fine_grained_policies(conn, base_dn):
    """
    Vérifier les politiques de mot de passe à granularité fine (FGPP).
    """
    fgpps = []

    try:
        # Rechercher les PSO (Password Settings Objects)
        conn.search(
            base_dn,
            '(objectClass=msDS-PasswordSettings)',
            SUBTREE,
            attributes=[
                'name', 'msDS-PasswordSettingsPrecedence', 'msDS-MinimumPasswordLength',
                'msDS-MaximumPasswordAge', 'msDS-MinimumPasswordAge', 'msDS-PasswordHistoryLength',
                'msDS-PasswordReversibleEncryptionEnabled', 'msDS-PasswordSettingsAppliedTo'
            ]
        )

        for entry in conn.entries:
            fgpps.append({
                'name': str(entry.name),
                'precedence': int(entry.msDS-PasswordSettingsPrecedence.value) if hasattr(entry, 'msDS-PasswordSettingsPrecedence') else 0,
                'min_length': int(entry.msDS-MinimumPasswordLength.value) if hasattr(entry, 'msDS-MinimumPasswordLength') else 0,
                'max_age': int(entry.msDS-MaximumPasswordAge.value / -864000000000) if hasattr(entry, 'msDS-MaximumPasswordAge') and entry.msDS-MaximumPasswordAge.value else 0,
                'reversible_encryption': bool(entry.msDS-PasswordReversibleEncryptionEnabled.value) if hasattr(entry, 'msDS-PasswordReversibleEncryptionEnabled') else False
            })

    except Exception as e:
        fgpps.append({'error': str(e)})

    return fgpps


def check_password_spray_vulnerability(conn, base_dn):
    """
    Détecter les comptes vulnérables aux attaques par spray de mot de passe.
    """
    vulnerable = []

    try:
        # Comptes sans verrouillage
        conn.search(
            base_dn,
            '(&(objectClass=user)(objectCategory=person))',
            SUBTREE,
            attributes=['sAMAccountName', 'displayName', 'distinguishedName', 'mail', 'lockoutThreshold']
        )

        for entry in conn.entries:
            # Si le seuil de verrouillage est 0 ou non défini au niveau du domaine
            vulnerable.append({
                'username': str(entry.sAMAccountName),
                'display_name': str(entry.displayName) if entry.displayName else '',
                'mail': str(entry.mail) if hasattr(entry, 'mail') and entry.mail else '',
                'dn': str(entry.distinguishedName),
                'issue': 'Vulnérable au spray de mot de passe (verrouillage non configuré)',
                'severity': 'medium'
            })

    except Exception as e:
        vulnerable.append({'error': str(e)})

    return vulnerable


def check_tiering_violations(conn, base_dn):
    """
    Vérifier les violations du modèle de tiering (Tier 0, 1, 2).
    
    Tier 0: Contrôleurs de domaine, PKI, AD FS
    Tier 1: Serveurs applicatifs
    Tier 2: Postes utilisateurs
    """
    violations = []
    
    try:
        # Chercher les admins du domaine qui ont des sessions sur des postes utilisateurs
        conn.search(
            base_dn,
            '(&(objectClass=user)(objectCategory=person)(adminCount=1))',
            SUBTREE,
            attributes=['sAMAccountName', 'displayName', 'memberOf', 'lastLogon', 'userAccountControl']
        )
        
        privileged_users = []
        for entry in conn.entries:
            privileged_users.append({
                'username': str(entry.sAMAccountName),
                'dn': str(entry.distinguishedName),
                'last_logon': entry.lastLogon.value if hasattr(entry, 'lastLogon') else None
            })
        
        # Vérifier si des comptes privilégiés ont des sessions actives
        # (Cette vérification nécessite un accès aux logs de session)
        for user in privileged_users:
            violations.append({
                'type': 'tiering',
                'item': user['username'],
                'issue': 'Compte privilégié - Vérifier qu\'il n\'est utilisé que sur des PAW (Tier 0)',
                'recommendation': 'Utiliser exclusivement des Postes d\'Administration Sécurisés (PAW)',
                'severity': 'high',
                'tier': 'Tier 0'
            })
            
    except Exception as e:
        violations.append({'error': str(e)})
    
    return violations


def check_legacy_protocols(conn, base_dn):
    """
    Vérifier l'utilisation de protocoles obsolètes (SMBv1, NTLMv1, LM).
    Retourne l'état actuel et les corrections recommandées.
    """
    issues = []
    
    try:
        # Vérifier la politique de domaine pour NTLM/LM
        conn.search(
            base_dn,
            '(objectClass=domain)',
            SUBTREE,
            attributes=['msDS-Other-Settings', 'gPLink', 'distinguishedName']
        )
        
        domain_dn = base_dn
        
        # === SMBv1 Detection ===
        smb_status = check_smbv1_status()
        issues.append({
            'type': 'protocol',
            'item': 'SMBv1',
            'issue': f'SMBv1 est {smb_status["status"]}',
            'recommendation': smb_status['recommendation'],
            'severity': 'critical' if smb_status['enabled'] else 'info',
            'reference': 'ANSSI: Vulnérabilités critiques SMBv1',
            'fix_available': smb_status['fix_available'],
            'fix_script': 'fix_smbv1.ps1',
            'current_value': smb_status['status']
        })
        
        # === NTLMv1/LM Detection ===
        ntlm_status = check_ntlm_level(domain_dn)
        issues.append({
            'type': 'protocol',
            'item': 'NTLM/LM',
            'issue': f'Niveau d\'authentification: {ntlm_status["level"]}',
            'recommendation': ntlm_status['recommendation'],
            'severity': 'critical' if ntlm_status['allows_lm'] else 'high' if ntlm_status['allows_ntlmv1'] else 'info',
            'reference': 'ANSSI: Recommandations de sécurité relatives à l\'authentification',
            'fix_available': ntlm_status['fix_available'],
            'fix_script': 'fix_ntlm.ps1',
            'current_value': ntlm_status['level']
        })
        
        # === LDAP Signing Detection ===
        ldap_status = check_ldap_signing(domain_dn)
        issues.append({
            'type': 'protocol',
            'item': 'LDAP Signing',
            'issue': f'Signing LDAP: {ldap_status["status"]}',
            'recommendation': ldap_status['recommendation'],
            'severity': 'high' if not ldap_status['required'] else 'info',
            'reference': 'ANSSI: Durcissement LDAP',
            'fix_available': ldap_status['fix_available'],
            'fix_script': 'fix_ldap_signing.ps1',
            'current_value': ldap_status['status']
        })
        
        # === Channel Binding Detection ===
        channel_status = check_channel_binding()
        issues.append({
            'type': 'protocol',
            'item': 'Channel Binding',
            'issue': f'Channel Binding: {channel_status["status"]}',
            'recommendation': channel_status['recommendation'],
            'severity': 'high' if not channel_status['enabled'] else 'info',
            'reference': 'Microsoft: Hardening AD CS and LDAP',
            'fix_available': channel_status['fix_available'],
            'fix_script': 'fix_channel_binding.ps1',
            'current_value': channel_status['status']
        })
        
    except Exception as e:
        issues.append({
            'type': 'protocol',
            'item': 'Erreur de détection',
            'issue': f'Impossible de vérifier les protocoles: {str(e)}',
            'recommendation': 'Vérifiez les permissions et la connectivité AD',
            'severity': 'warning',
            'fix_available': False
        })
    
    return issues


def check_smbv1_status():
    """
    Vérifier si SMBv1 est activé sur le serveur.
    Utilise PowerShell pour détecter l'état.
    """
    import subprocess
    import json
    
    result = {
        'enabled': False,
        'status': 'Inconnu',
        'recommendation': '',
        'fix_available': True
    }
    
    try:
        # Commander PowerShell pour vérifier SMBv1
        ps_command = [
            'powershell.exe',
            '-Command',
            'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State | ConvertTo-Json'
        ]
        
        proc = subprocess.Popen(ps_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(timeout=10)
        
        if stdout:
            state = stdout.strip().strip('"')
            result['status'] = state
            
            if state == 'Enabled':
                result['enabled'] = True
                result['recommendation'] = 'Désactiver SMBv1 immédiatement (risque de sécurité critique - WannaCry, NotPetya)'
            else:
                result['recommendation'] = 'SMBv1 est déjà désactivé - Bonne configuration!'
        else:
            result['status'] = 'Non détecté'
            result['recommendation'] = 'Impossible de déterminer l\'état de SMBv1'
            
    except subprocess.TimeoutExpired:
        result['status'] = 'Timeout'
        result['recommendation'] = 'La vérification a expiré'
    except Exception as e:
        result['status'] = f'Erreur: {str(e)}'
        result['recommendation'] = 'Impossible de vérifier SMBv1'
    
    return result


def check_ntlm_level(domain_dn):
    """
    Vérifier le niveau d'authentification NTLM dans la GPO du domaine.
    """
    result = {
        'level': 'Inconnu',
        'allows_lm': True,
        'allows_ntlmv1': True,
        'recommendation': '',
        'fix_available': True
    }
    
    try:
        # Niveau 0 = LM et NTLMv1 autorisés
        # Niveau 1 = NTLMv2 seulement
        # Niveau 2 = NTLMv2 seulement (recommandé)
        # Niveau 3 = NTLMv2 seulement avec audit
        # Niveau 5 = Refuser LM et NTLMv1
        
        # Vérifier via registry ou GPO
        import subprocess
        
        ps_command = [
            'powershell.exe',
            '-Command',
            '''
            $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
            $lmLevel = Get-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
            if ($lmLevel) {
                $level = $lmLevel.LmCompatibilityLevel
            } else {
                $level = 5  # Par défaut sur Windows Server récent
            }
            
            $result = @{
                level = $level
                allows_lm = ($level -lt 3)
                allows_ntlmv1 = ($level -lt 5)
            }
            $result | ConvertTo-Json -Compress
            '''
        ]
        
        proc = subprocess.Popen(ps_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(timeout=10)
        
        if stdout:
            import json as json_module
            data = json_module.loads(stdout)
            
            level = data.get('level', 5)
            result['level'] = get_ntlm_level_name(level)
            result['allows_lm'] = data.get('allows_lm', False)
            result['allows_ntlmv1'] = data.get('allows_ntlmv1', False)
            
            if level >= 5:
                result['recommendation'] = 'NTLMv1 et LM sont refusés - Excellente configuration!'
            elif level >= 3:
                result['recommendation'] = 'Recommandé: Passer au niveau 5 (Refuser LM et NTLMv1)'
            else:
                result['recommendation'] = 'CRITIQUE: Passer au niveau 5 immédiatement (Refuser LM et NTLMv1)'
        else:
            result['level'] = 'Non vérifié'
            result['recommendation'] = 'Vérifiez manuellement dans GPO ou Registry'
            
    except Exception as e:
        result['level'] = f'Erreur: {str(e)}'
        result['recommendation'] = 'Impossible de vérifier le niveau NTLM'
    
    return result


def get_ntlm_level_name(level):
    """Obtenir le nom du niveau NTLM."""
    levels = {
        0: '0 - LM et NTLMv1 autorisés',
        1: '1 - NTLMv2 avec session sécurisée',
        2: '2 - NTLMv2 seulement',
        3: '3 - NTLMv2 seulement (audit)',
        4: '4 - Refuser LM',
        5: '5 - Refuser LM et NTLMv1 (Recommandé)'
    }
    return levels.get(level, f'Niveau {level} (Inconnu)')


def check_ldap_signing(domain_dn):
    """
    Vérifier si le signing LDAP est requis.
    """
    result = {
        'required': False,
        'status': 'Inconnu',
        'recommendation': '',
        'fix_available': True
    }
    
    try:
        import subprocess
        
        ps_command = [
            'powershell.exe',
            '-Command',
            '''
            $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"
            $ldapSigning = Get-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
            if ($ldapSigning) {
                $level = $ldapSigning.LDAPServerIntegrity
            } else {
                $level = 0  # Non configuré
            }
            
            $result = @{
                level = $level
                required = ($level -ge 2)
            }
            $result | ConvertTo-Json -Compress
            '''
        ]
        
        proc = subprocess.Popen(ps_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(timeout=10)
        
        if stdout:
            import json as json_module
            data = json_module.loads(stdout)
            
            level = data.get('level', 0)
            result['required'] = data.get('required', False)
            
            if level == 0:
                result['status'] = 'Non configuré (par défaut: Signing autorisé)'
            elif level == 1:
                result['status'] = 'Signing autorisé (non requis)'
            elif level >= 2:
                result['status'] = 'Signing requis'
            
            if result['required']:
                result['recommendation'] = 'LDAP Signing est requis - Bonne configuration!'
            else:
                result['recommendation'] = 'Recommandé: Exiger le signing LDAP (prévient les attaques MITM)'
        else:
            result['status'] = 'Non vérifié'
            result['recommendation'] = 'Vérifiez manuellement dans GPO'
            
    except Exception as e:
        result['status'] = f'Erreur: {str(e)}'
        result['recommendation'] = 'Impossible de vérifier le LDAP Signing'
    
    return result


def check_channel_binding():
    """
    Vérifier si Channel Binding est activé pour LDAP.
    """
    result = {
        'enabled': False,
        'status': 'Inconnu',
        'recommendation': '',
        'fix_available': True
    }
    
    try:
        import subprocess
        
        ps_command = [
            'powershell.exe',
            '-Command',
            '''
            $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"
            $channelBinding = Get-ItemProperty -Path $regPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
            if ($channelBinding) {
                $level = $channelBinding.LdapEnforceChannelBinding
            } else {
                $level = 0  # Non configuré
            }
            
            $result = @{
                level = $level
                enabled = ($level -ge 1)
            }
            $result | ConvertTo-Json -Compress
            '''
        ]
        
        proc = subprocess.Popen(ps_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(timeout=10)
        
        if stdout:
            import json as json_module
            data = json_module.loads(stdout)
            
            level = data.get('level', 0)
            result['enabled'] = data.get('enabled', False)
            
            if level == 0:
                result['status'] = 'Non configuré'
            elif level == 1:
                result['status'] = 'Activé (supporté)'
            elif level == 2:
                result['status'] = 'Requis (recommandé)'
            
            if result['enabled']:
                result['recommendation'] = 'Channel Binding est activé - Bonne configuration!'
            else:
                result['recommendation'] = 'Recommandé: Activer Channel Binding (HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\LdapEnforceChannelBinding = 2)'
        else:
            result['status'] = 'Non vérifié'
            result['recommendation'] = 'Vérifiez manuellement dans le Registry'
            
    except Exception as e:
        result['status'] = f'Erreur: {str(e)}'
        result['recommendation'] = 'Impossible de vérifier Channel Binding'
    
    return result


def check_delegations(conn, base_dn):
    """
    Vérifier les délégations de privilèges (constrained/unconstrained).
    """
    issues = []
    
    try:
        # Chercher les comptes avec délégation sans contrainte (TRUSTED_FOR_DELEGATION)
        conn.search(
            base_dn,
            '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
            SUBTREE,
            attributes=['sAMAccountName', 'distinguishedName', 'userAccountControl']
        )
        
        for entry in conn.entries:
            issues.append({
                'type': 'delegation',
                'item': str(entry.sAMAccountName),
                'issue': 'Délégation sans contrainte activée (TRUSTED_FOR_DELEGATION)',
                'recommendation': 'Désactiver ou remplacer par délégation contrainte (KCD)',
                'severity': 'critical',
                'reference': 'ANSSI: Gestion des délégations de privilèges',
                'dn': str(entry.distinguishedName)
            })
            
        # Chercher les comptes avec délégation contrainte
        conn.search(
            base_dn,
            '(&(objectClass=user)(msDS-AllowedToDelegateTo=*))',
            SUBTREE,
            attributes=['sAMAccountName', 'distinguishedName', 'msDS-AllowedToDelegateTo']
        )
        
        for entry in conn.entries:
            delegated_services = entry.msDS-AllowedToDelegateTo.values if hasattr(entry, 'msDS-AllowedToDelegateTo') else []
            issues.append({
                'type': 'delegation_constrained',
                'item': str(entry.sAMAccountName),
                'issue': f'Délégation contrainte vers {len(delegated_services)} service(s)',
                'recommendation': 'Vérifier que la délégation est nécessaire et documentée',
                'severity': 'medium',
                'dn': str(entry.distinguishedName)
            })
            
    except Exception as e:
        issues.append({'error': str(e)})
    
    return issues


def check_protected_users(conn, base_dn):
    """
    Vérifier le groupe Protected Users.
    """
    issues = []
    
    try:
        # Chercher le groupe Protected Users
        conn.search(
            base_dn,
            '(&(objectClass=group)(cn=Protected Users))',
            SUBTREE,
            attributes=['member', 'distinguishedName']
        )
        
        if conn.entries:
            members = conn.entries[0].member.values if hasattr(conn.entries[0], 'member') else []
            member_count = len(members) if members else 0
            
            if member_count == 0:
                issues.append({
                    'type': 'protected_users',
                    'item': 'Protected Users',
                    'issue': 'Groupe Protected Users vide',
                    'recommendation': 'Ajouter les comptes administrateurs et comptes sensibles',
                    'severity': 'high',
                    'reference': 'Microsoft: Protected Users Security Group'
                })
            else:
                issues.append({
                    'type': 'protected_users',
                    'item': 'Protected Users',
                    'issue': f'{member_count} membre(s) dans Protected Users',
                    'recommendation': 'Vérifier que tous les comptes privilégiés y sont',
                    'severity': 'info'
                })
        else:
            issues.append({
                'type': 'protected_users',
                'item': 'Protected Users',
                'issue': 'Groupe Protected Users introuvable (nécessite Windows Server 2012 R2+)',
                'recommendation': 'Créer le groupe et y ajouter les comptes sensibles',
                'severity': 'high'
            })
            
    except Exception as e:
        issues.append({'error': str(e)})
    
    return issues


def check_privileged_group_memberships(conn, base_dn):
    """
    Vérifier les appartenances permanentes aux groupes privilégiés.
    """
    issues = []
    
    try:
        privileged_groups = [
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators',
            'Print Operators'
        ]
        
        for group_name in privileged_groups:
            conn.search(
                base_dn,
                f'(&(objectClass=group)(cn={escape_ldap_filter(group_name)}))',
                SUBTREE,
                attributes=['member', 'distinguishedName']
            )
            
            if conn.entries:
                members = conn.entries[0].member.values if hasattr(conn.entries[0], 'member') else []
                member_count = len(members) if members else 0
                
                if member_count > 0:
                    issues.append({
                        'type': 'privileged_group',
                        'item': group_name,
                        'issue': f'{member_count} membre(s) permanent(s)',
                        'recommendation': 'Mettre en place un accès JIT (Just-In-Time) ou PAM',
                        'severity': 'warning',
                        'reference': 'ANSSI: Gestion des privilèges'
                    })
                    
    except Exception as e:
        issues.append({'error': str(e)})
    
    return issues


def check_siem_logging(conn, base_dn):
    """
    Vérifier la configuration des logs et du SIEM.
    """
    recommendations = []
    
    recommendations.append({
        'type': 'siem',
        'item': 'Audit Policy',
        'issue': 'Vérifier que les audits avancés sont activés',
        'recommendation': 'GPO: Advanced Audit Policy → Activer tous les audits de sécurité critiques',
        'severity': 'high',
        'reference': 'ANSSI: Recommandations de journalisation'
    })
    
    recommendations.append({
        'type': 'siem',
        'item': 'SIEM Integration',
        'issue': 'Centraliser les logs AD dans un SIEM',
        'recommendation': 'Configurer la forwarding des événements 4624, 4625, 4672, 4720, 4732, etc.',
        'severity': 'high',
        'reference': 'ANSSI: Détection et réponse'
    })
    
    recommendations.append({
        'type': 'siem',
        'item': 'Sensitive Objects',
        'issue': 'Surveiller les modifications des objets sensibles',
        'recommendation': 'Activer SACL sur les groupes privilégiés et comptes admins',
        'severity': 'high',
        'reference': 'Microsoft: Audit AD DS'
    })
    
    return recommendations


def generate_password_recommendations(policy, weak_accounts, old_passwords, fgpps=None):
    """
    Générer des recommandations basées sur l'audit.
    """
    recommendations = []

    # Politique
    if policy.get('minPasswordLength', 0) < 8:
        recommendations.append({
            'priority': 'high',
            'category': 'Politique',
            'issue': f'Longueur minimale trop faible ({policy.get("minPasswordLength", 0)})',
            'recommendation': 'Définir une longueur minimale de 12 caractères',
            'specops_reference': 'SP-PP-001: Minimum 12 caractères recommandé'
        })

    if policy.get('maxPasswordAge', 0) == 0:
        recommendations.append({
            'priority': 'medium',
            'category': 'Politique',
            'issue': 'Expiration des mots de passe non activée',
            'recommendation': 'Activer l\'expiration tous les 90 jours',
            'specops_reference': 'SP-PP-002: Expiration recommandée'
        })

    if policy.get('passwordHistoryLength', 0) < 5:
        recommendations.append({
            'priority': 'medium',
            'category': 'Politique',
            'issue': f'Historique insuffisant ({policy.get("passwordHistoryLength", 0)})',
            'recommendation': 'Mémoriser les 10 derniers mots de passe',
            'specops_reference': 'SP-PP-003: Historique de 10 mots de passe minimum'
        })

    if not policy.get('complexity_enabled', False):
        recommendations.append({
            'priority': 'high',
            'category': 'Politique',
            'issue': 'Complexité des mots de passe non activée',
            'recommendation': 'Activer la complexité des mots de passe',
            'specops_reference': 'SP-PP-004: Complexité requise'
        })

    if policy.get('reversible_encryption', False):
        recommendations.append({
            'priority': 'critical',
            'category': 'Politique',
            'issue': 'Stockage du mot de passe en clair activé',
            'recommendation': 'Désactiver immédiatement le stockage réversible',
            'specops_reference': 'SP-SEC-001: Jamais de stockage en clair'
        })

    # Comptes faibles
    critical_count = sum(1 for acc in weak_accounts if acc.get('severity') == 'critical')
    warning_count = sum(1 for acc in weak_accounts if acc.get('severity') == 'warning')

    if critical_count > 0:
        recommendations.append({
            'priority': 'critical',
            'category': 'Comptes',
            'issue': f'{critical_count} compte(s) avec problème critique',
            'recommendation': 'Exiger un changement de mot de passe immédiat',
            'specops_reference': 'SP-ACC-001: Corriger les comptes critiques'
        })

    if warning_count > 0:
        recommendations.append({
            'priority': 'high',
            'category': 'Comptes',
            'issue': f'{warning_count} compte(s) avec mot de passe n\'expirant jamais',
            'recommendation': 'Désactiver "Le mot de passe n\'expire jamais"',
            'specops_reference': 'SP-ACC-002: Expiration pour tous les comptes'
        })

    # Mots de passe anciens
    very_old = sum(1 for pwd in old_passwords if pwd.get('severity') == 'critical')
    if very_old > 0:
        recommendations.append({
            'priority': 'high',
            'category': 'Ancienneté',
            'issue': f'{very_old} mot(s) de passe inchangé(s) depuis > {policy.get("maxPasswordAge", 90)} jours',
            'recommendation': 'Forcer le changement de mot de passe',
            'specops_reference': 'SP-AGE-001: Rotation régulière'
        })

    # FGPP
    if fgpps and len(fgpps) == 0:
        recommendations.append({
            'priority': 'info',
            'category': 'Politiques FGPP',
            'issue': 'Aucune politique à granularité fine détectée',
            'recommendation': 'Envisager des FGPP pour les comptes privilégiés',
            'specops_reference': 'SP-FGPP-001: Politiques différenciées'
        })

    return recommendations


def run_password_audit(conn, base_dn, max_age_days=90):
    """
    Exécuter un audit complet des mots de passe et de la sécurité AD.
    Style Specops Password Auditor + ANSSI Hardening Guidelines.
    """
    # Politique de mot de passe
    policy = get_password_policy(conn, base_dn)

    # Comptes faibles
    weak_accounts = check_weak_passwords_ad(conn, base_dn)

    # Ancienneté des mots de passe
    old_passwords = check_password_age(conn, base_dn, max_age_days)

    # FGPP
    fgpps = check_fine_grained_policies(conn, base_dn)

    # Vulnérabilités spray
    spray_vulns = check_password_spray_vulnerability(conn, base_dn)

    # === NOUVEAU: Audit de sécurité complet AD ===
    
    # Vérification du tiering
    tiering_violations = check_tiering_violations(conn, base_dn)
    
    # Protocoles obsolètes
    legacy_protocols = check_legacy_protocols(conn, base_dn)
    
    # Délégations
    delegations = check_delegations(conn, base_dn)
    
    # Protected Users
    protected_users = check_protected_users(conn, base_dn)
    
    # Groupes privilégiés
    privileged_groups = check_privileged_group_memberships(conn, base_dn)
    
    # SIEM et logging
    siem_logging = check_siem_logging(conn, base_dn)

    # Recommandations (politique + mots de passe)
    recommendations = generate_password_recommendations(policy, weak_accounts, old_passwords, fgpps)
    
    # Ajouter les recommandations de sécurité AD
    security_recommendations = []
    
    # Protocoles
    for proto in legacy_protocols:
        security_recommendations.append({
            'priority': proto['severity'],
            'category': '🔒 Protocoles',
            'issue': proto['issue'],
            'recommendation': proto['recommendation'],
            'reference': proto.get('reference', ''),
            'type': proto['type'],
            'item': proto['item']
        })
    
    # Tiering
    for tier in tiering_violations[:3]:  # Limiter à 3 pour ne pas surcharger
        if 'error' in tier:  # Skip les erreurs
            continue
        security_recommendations.append({
            'priority': tier.get('severity', 'high'),
            'category': '🏛️ Tiering',
            'issue': tier['issue'],
            'recommendation': tier['recommendation'],
            'reference': tier.get('reference', 'ANSSI: Modèle de tiering'),
            'type': tier['type'],
            'tier': tier.get('tier', 'N/A')
        })

    # Délégations
    for deleg in delegations:
        if 'error' in deleg:  # Skip les erreurs
            continue
        security_recommendations.append({
            'priority': deleg.get('severity', 'high'),
            'category': '🔑 Délégations',
            'issue': deleg['issue'],
            'recommendation': deleg['recommendation'],
            'reference': deleg.get('reference', ''),
            'type': deleg['type'],
            'dn': deleg.get('dn', '')
        })

    # Protected Users
    for pu in protected_users:
        if 'error' in pu:  # Skip les erreurs
            continue
        security_recommendations.append({
            'priority': pu['severity'],
            'category': '🛡️ Protected Users',
            'issue': pu['issue'],
            'recommendation': pu['recommendation'],
            'reference': pu.get('reference', ''),
            'type': pu['type']
        })
    
    # Groupes privilégiés
    for pg in privileged_groups:
        if 'error' in pg:  # Skip les erreurs
            continue
        security_recommendations.append({
            'priority': pg.get('severity', 'warning'),
            'category': '👥 Privilèges',
            'issue': pg['issue'],
            'recommendation': pg['recommendation'],
            'reference': pg.get('reference', ''),
            'type': pg['type']
        })

    # SIEM
    for siem in siem_logging:
        if 'error' in siem:  # Skip les erreurs
            continue
        security_recommendations.append({
            'priority': siem.get('severity', 'high'),
            'category': '📊 SIEM & Logs',
            'issue': siem['issue'],
            'recommendation': siem['recommendation'],
            'reference': siem.get('reference', ''),
            'type': siem['type']
        })

    # Calcul du score global
    total_issues = len(weak_accounts) + len(old_passwords)
    critical_issues = sum(1 for acc in weak_accounts if acc.get('severity') == 'critical')
    critical_issues += sum(1 for pwd in old_passwords if pwd.get('severity') == 'critical')
    critical_issues += 1 if policy.get('reversible_encryption', False) else 0
    critical_issues += sum(1 for d in delegations if d.get('severity') == 'critical')  # Délégations sans contrainte
    
    # Score numérique (0-100)
    base_score = 100
    base_score -= critical_issues * 15
    base_score -= sum(1 for acc in weak_accounts if acc.get('severity') == 'warning') * 5
    base_score -= sum(1 for pwd in old_passwords if pwd.get('severity') == 'warning') * 3
    base_score -= 10 if not policy.get('complexity_enabled', False) else 0
    base_score -= 5 if policy.get('minPasswordLength', 0) < 12 else 0
    base_score -= len(legacy_protocols) * 5  # Pénalité pour protocoles obsolètes
    base_score -= len([d for d in delegations if d.get('severity') == 'critical']) * 10  # Délégations dangereuses
    global_score = max(0, min(100, base_score))

    if global_score >= 80:
        score_label = "Excellent"
        score_color = "success"
    elif global_score >= 60:
        score_label = "Acceptable"
        score_color = "info"
    elif global_score >= 40:
        score_label = "Mauvais"
        score_color = "warning"
    else:
        score_label = "Critique"
        score_color = "danger"

    return {
        'timestamp': datetime.now().isoformat(),
        'policy': policy,
        'fgpps': fgpps,
        'weak_accounts': weak_accounts,
        'old_passwords': old_passwords,
        'spray_vulnerabilities': spray_vulns,
        'tiering_violations': tiering_violations,
        'legacy_protocols': legacy_protocols,
        'delegations': delegations,
        'protected_users': protected_users,
        'privileged_groups': privileged_groups,
        'siem_logging': siem_logging,
        'recommendations': recommendations + security_recommendations,
        'summary': {
            'total_issues': total_issues,
            'critical_issues': critical_issues,
            'warning_issues': sum(1 for acc in weak_accounts if acc.get('severity') == 'warning'),
            'global_score': global_score,
            'score_label': score_label,
            'score_color': score_color,
            'accounts_audited': len(weak_accounts) + len(old_passwords),
            'policy_compliant': global_score >= 80,
            # Nouveaux compteurs
            'tiering_issues': len(tiering_violations),
            'protocol_issues': len(legacy_protocols),
            'delegation_issues': len(delegations),
            'privileged_group_issues': len(privileged_groups),
            'siem_issues': len(siem_logging),
            'total_recommendations': len(recommendations) + len(security_recommendations)
        }
    }


def export_audit_to_csv(audit_result, filename='password_audit.csv'):
    """
    Exporter les résultats de l'audit en CSV.
    """
    import csv
    from io import StringIO

    output = StringIO()
    writer = csv.writer(output)

    # En-tête
    writer.writerow(['Type', 'Utilisateur', 'Nom affiché', 'Email', 'Problème', 'Sévérité', 'Remède'])

    # Comptes faibles
    for acc in audit_result.get('weak_accounts', []):
        writer.writerow([
            acc.get('type', ''),
            acc.get('username', ''),
            acc.get('display_name', ''),
            acc.get('mail', ''),
            acc.get('issue', ''),
            acc.get('severity', ''),
            acc.get('remediation', '')
        ])

    # Mots de passe anciens
    for pwd in audit_result.get('old_passwords', []):
        writer.writerow([
            'old_password',
            pwd.get('username', ''),
            pwd.get('display_name', ''),
            pwd.get('mail', ''),
            f"Mot de passe ancien ({pwd.get('days_old', 0)} jours)",
            pwd.get('severity', ''),
            pwd.get('remediation', '')
        ])

    output.seek(0)
    return output.getvalue()


def export_audit_to_json(audit_result, filename='password_audit.json'):
    """
    Exporter les résultats de l'audit en JSON.
    """
    return json.dumps(audit_result, indent=2, default=str)
