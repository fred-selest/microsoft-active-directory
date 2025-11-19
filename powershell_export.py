"""
Module pour generer les commandes PowerShell equivalentes.
"""


def escape_ps_string(value):
    """Echapper une chaine pour PowerShell."""
    if not value:
        return "''"
    return "'" + str(value).replace("'", "''") + "'"


def generate_create_user_ps(user_data):
    """Generer la commande PowerShell pour creer un utilisateur."""
    ps = f"""# Creer un utilisateur Active Directory
New-ADUser `
    -Name {escape_ps_string(user_data.get('displayName', user_data.get('cn', '')))} `
    -SamAccountName {escape_ps_string(user_data.get('sAMAccountName', ''))} `
    -UserPrincipalName {escape_ps_string(user_data.get('userPrincipalName', ''))} `
    -GivenName {escape_ps_string(user_data.get('givenName', ''))} `
    -Surname {escape_ps_string(user_data.get('sn', ''))} `
    -DisplayName {escape_ps_string(user_data.get('displayName', ''))} `
    -EmailAddress {escape_ps_string(user_data.get('mail', ''))} `
    -Department {escape_ps_string(user_data.get('department', ''))} `
    -Title {escape_ps_string(user_data.get('title', ''))} `
    -Path {escape_ps_string(user_data.get('ou', ''))} `
    -AccountPassword (ConvertTo-SecureString {escape_ps_string(user_data.get('password', 'P@ssw0rd!'))} -AsPlainText -Force) `
    -Enabled $true
"""
    return ps


def generate_modify_user_ps(dn, changes):
    """Generer la commande PowerShell pour modifier un utilisateur."""
    params = []
    for key, value in changes.items():
        if value:
            params.append(f"    -{key} {escape_ps_string(value)}")

    ps = f"""# Modifier un utilisateur Active Directory
Set-ADUser -Identity {escape_ps_string(dn)} `
{chr(10).join(params)}
"""
    return ps


def generate_delete_user_ps(dn):
    """Generer la commande PowerShell pour supprimer un utilisateur."""
    return f"""# Supprimer un utilisateur Active Directory
Remove-ADUser -Identity {escape_ps_string(dn)} -Confirm:$false
"""


def generate_enable_user_ps(dn):
    """Generer la commande PowerShell pour activer un utilisateur."""
    return f"""# Activer un compte utilisateur
Enable-ADAccount -Identity {escape_ps_string(dn)}
"""


def generate_disable_user_ps(dn):
    """Generer la commande PowerShell pour desactiver un utilisateur."""
    return f"""# Desactiver un compte utilisateur
Disable-ADAccount -Identity {escape_ps_string(dn)}
"""


def generate_reset_password_ps(dn, password):
    """Generer la commande PowerShell pour reinitialiser un mot de passe."""
    return f"""# Reinitialiser le mot de passe
Set-ADAccountPassword -Identity {escape_ps_string(dn)} `
    -Reset `
    -NewPassword (ConvertTo-SecureString {escape_ps_string(password)} -AsPlainText -Force)
"""


def generate_create_group_ps(group_data):
    """Generer la commande PowerShell pour creer un groupe."""
    scope_map = {
        'global': 'Global',
        'domain_local': 'DomainLocal',
        'universal': 'Universal'
    }
    scope = scope_map.get(group_data.get('scope', 'global'), 'Global')

    return f"""# Creer un groupe Active Directory
New-ADGroup `
    -Name {escape_ps_string(group_data.get('name', ''))} `
    -GroupScope {scope} `
    -GroupCategory {group_data.get('type', 'Security')} `
    -Description {escape_ps_string(group_data.get('description', ''))} `
    -Path {escape_ps_string(group_data.get('ou', ''))}
"""


def generate_add_member_ps(group_dn, member_dn):
    """Generer la commande PowerShell pour ajouter un membre."""
    return f"""# Ajouter un membre au groupe
Add-ADGroupMember -Identity {escape_ps_string(group_dn)} `
    -Members {escape_ps_string(member_dn)}
"""


def generate_remove_member_ps(group_dn, member_dn):
    """Generer la commande PowerShell pour retirer un membre."""
    return f"""# Retirer un membre du groupe
Remove-ADGroupMember -Identity {escape_ps_string(group_dn)} `
    -Members {escape_ps_string(member_dn)} `
    -Confirm:$false
"""


def generate_move_object_ps(dn, target_ou):
    """Generer la commande PowerShell pour deplacer un objet."""
    return f"""# Deplacer un objet vers une autre OU
Move-ADObject -Identity {escape_ps_string(dn)} `
    -TargetPath {escape_ps_string(target_ou)}
"""


def generate_unlock_account_ps(dn):
    """Generer la commande PowerShell pour deverrouiller un compte."""
    return f"""# Deverrouiller un compte
Unlock-ADAccount -Identity {escape_ps_string(dn)}
"""


def generate_bulk_import_ps(csv_path, ou, default_password):
    """Generer le script PowerShell pour import en masse."""
    return f"""# Import en masse depuis un fichier CSV
$Users = Import-Csv -Path {escape_ps_string(csv_path)}

foreach ($User in $Users) {{
    $Password = ConvertTo-SecureString {escape_ps_string(default_password)} -AsPlainText -Force

    New-ADUser `
        -Name "$($User.givenName) $($User.sn)" `
        -SamAccountName $User.sAMAccountName `
        -GivenName $User.givenName `
        -Surname $User.sn `
        -DisplayName $User.displayName `
        -EmailAddress $User.mail `
        -Department $User.department `
        -Title $User.title `
        -Path {escape_ps_string(ou)} `
        -AccountPassword $Password `
        -Enabled $true

    Write-Host "Utilisateur $($User.sAMAccountName) cree"
}}
"""
