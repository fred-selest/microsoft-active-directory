"""Vérification des protocoles obsolètes : SMBv1, NTLM, LDAP Signing, Channel Binding."""
import subprocess
import json
from ldap3 import SUBTREE


def check_smbv1_status():
    """Vérifier si SMBv1 est activé (via PowerShell)."""
    result = {'enabled': False, 'status': 'Inconnu', 'recommendation': '', 'fix_available': True}
    try:
        proc = subprocess.Popen(
            ['powershell.exe', '-Command',
             'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State | ConvertTo-Json'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _ = proc.communicate(timeout=10)
        if stdout:
            state = stdout.strip().strip('"')
            result['status'] = state
            if state == 'Enabled':
                result['enabled'] = True
                result['recommendation'] = 'Désactiver SMBv1 immédiatement (risque critique - WannaCry, NotPetya)'
            else:
                result['recommendation'] = 'SMBv1 est déjà désactivé - Bonne configuration!'
        else:
            result['status'] = 'Non détecté'
            result['recommendation'] = "Impossible de déterminer l'état de SMBv1"
    except subprocess.TimeoutExpired:
        result['status'] = 'Timeout'
        result['recommendation'] = 'La vérification a expiré'
    except Exception as ex:
        result['status'] = f'Erreur: {ex}'
        result['recommendation'] = 'Impossible de vérifier SMBv1'
    return result


def get_ntlm_level_name(level):
    """Obtenir le nom du niveau NTLM."""
    levels = {
        0: '0 - LM et NTLMv1 autorisés',
        1: '1 - NTLMv2 avec session sécurisée',
        2: '2 - NTLMv2 seulement',
        3: '3 - NTLMv2 seulement (audit)',
        4: '4 - Refuser LM',
        5: '5 - Refuser LM et NTLMv1 (Recommandé)',
    }
    return levels.get(level, f'Niveau {level} (Inconnu)')


def check_ntlm_level(domain_dn):
    """Vérifier le niveau d'authentification NTLM via le registre."""
    result = {'level': 'Inconnu', 'allows_lm': True, 'allows_ntlmv1': True,
              'recommendation': '', 'fix_available': True}
    try:
        ps = r'''
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lmLevel = Get-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
$level = if ($lmLevel) { $lmLevel.LmCompatibilityLevel } else { 5 }
@{ level=$level; allows_lm=($level -lt 3); allows_ntlmv1=($level -lt 5) } | ConvertTo-Json -Compress
'''
        proc = subprocess.Popen(['powershell.exe', '-Command', ps],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _ = proc.communicate(timeout=10)
        if stdout:
            data = json.loads(stdout)
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
    except Exception as ex:
        result['level'] = f'Erreur: {ex}'
        result['recommendation'] = 'Impossible de vérifier le niveau NTLM'
    return result


def check_ldap_signing(domain_dn):
    """Vérifier si le signing LDAP est requis."""
    result = {'required': False, 'status': 'Inconnu', 'recommendation': '', 'fix_available': True}
    try:
        ps = r'''
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$v = Get-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
$level = if ($v) { $v.LDAPServerIntegrity } else { 0 }
@{ level=$level; required=($level -ge 2) } | ConvertTo-Json -Compress
'''
        proc = subprocess.Popen(['powershell.exe', '-Command', ps],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _ = proc.communicate(timeout=10)
        if stdout:
            data = json.loads(stdout)
            level = data.get('level', 0)
            result['required'] = data.get('required', False)
            result['status'] = {0: 'Non configuré', 1: 'Signing autorisé (non requis)'}.get(level, 'Signing requis')
            result['recommendation'] = ('LDAP Signing est requis - Bonne configuration!' if result['required']
                                        else 'Recommandé: Exiger le signing LDAP (prévient les attaques MITM)')
        else:
            result['status'] = 'Non vérifié'
            result['recommendation'] = 'Vérifiez manuellement dans GPO'
    except Exception as ex:
        result['status'] = f'Erreur: {ex}'
        result['recommendation'] = 'Impossible de vérifier le LDAP Signing'
    return result


def check_channel_binding():
    """Vérifier si Channel Binding est activé pour LDAP."""
    result = {'enabled': False, 'status': 'Inconnu', 'recommendation': '', 'fix_available': True}
    try:
        ps = r'''
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$v = Get-ItemProperty -Path $regPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
$level = if ($v) { $v.LdapEnforceChannelBinding } else { 0 }
@{ level=$level; enabled=($level -ge 1) } | ConvertTo-Json -Compress
'''
        proc = subprocess.Popen(['powershell.exe', '-Command', ps],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _ = proc.communicate(timeout=10)
        if stdout:
            data = json.loads(stdout)
            level = data.get('level', 0)
            result['enabled'] = data.get('enabled', False)
            result['status'] = {0: 'Non configuré', 1: 'Activé (supporté)', 2: 'Requis (recommandé)'}.get(level, f'Niveau {level}')
            result['recommendation'] = ('Channel Binding est activé - Bonne configuration!' if result['enabled']
                                        else r'Recommandé: Activer Channel Binding (LdapEnforceChannelBinding = 2)')
        else:
            result['status'] = 'Non vérifié'
            result['recommendation'] = 'Vérifiez manuellement dans le Registry'
    except Exception as ex:
        result['status'] = f'Erreur: {ex}'
        result['recommendation'] = 'Impossible de vérifier Channel Binding'
    return result


def check_legacy_protocols(conn, base_dn):
    """Vérifier l'utilisation de protocoles obsolètes (SMBv1, NTLMv1, LM, LDAP signing)."""
    issues = []
    try:
        conn.search(base_dn, '(objectClass=domain)', SUBTREE,
                    attributes=['msDS-Other-Settings', 'distinguishedName'])
        domain_dn = base_dn

        smb = check_smbv1_status()
        issues.append({'type': 'protocol', 'item': 'SMBv1',
            'issue': f'SMBv1 est {smb["status"]}',
            'recommendation': smb['recommendation'],
            'severity': 'critical' if smb['enabled'] else 'info',
            'reference': 'ANSSI: Vulnérabilités critiques SMBv1',
            'fix_available': smb['fix_available'], 'fix_script': 'fix_smbv1.ps1',
            'current_value': smb['status']})

        ntlm = check_ntlm_level(domain_dn)
        issues.append({'type': 'protocol', 'item': 'NTLM/LM',
            'issue': f"Niveau d'authentification: {ntlm['level']}",
            'recommendation': ntlm['recommendation'],
            'severity': 'critical' if ntlm['allows_lm'] else 'high' if ntlm['allows_ntlmv1'] else 'info',
            'reference': 'ANSSI: Recommandations relatives à l\'authentification',
            'fix_available': ntlm['fix_available'], 'fix_script': 'fix_ntlm.ps1',
            'current_value': ntlm['level']})

        ldap = check_ldap_signing(domain_dn)
        issues.append({'type': 'protocol', 'item': 'LDAP Signing',
            'issue': f'Signing LDAP: {ldap["status"]}',
            'recommendation': ldap['recommendation'],
            'severity': 'high' if not ldap['required'] else 'info',
            'reference': 'ANSSI: Durcissement LDAP',
            'fix_available': ldap['fix_available'], 'fix_script': 'fix_ldap_signing.ps1',
            'current_value': ldap['status']})

        cb = check_channel_binding()
        issues.append({'type': 'protocol', 'item': 'Channel Binding',
            'issue': f'Channel Binding: {cb["status"]}',
            'recommendation': cb['recommendation'],
            'severity': 'high' if not cb['enabled'] else 'info',
            'reference': 'Microsoft: Hardening AD CS and LDAP',
            'fix_available': cb['fix_available'], 'fix_script': 'fix_channel_binding.ps1',
            'current_value': cb['status']})

    except Exception as ex:
        issues.append({'type': 'protocol', 'item': 'Erreur de détection',
            'issue': f'Impossible de vérifier les protocoles: {ex}',
            'recommendation': 'Vérifiez les permissions et la connectivité AD',
            'severity': 'warning', 'fix_available': False})
    return issues
