#!/usr/bin/env python3
"""Script pour corriger les decode_ldap_value restants dans users.py"""

with open('routes/users.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

count = 0
replacements = {
    'decode_ldap_value(e.name)': 'str(e.name.value) if e.name else ""',
    'decode_ldap_value(e.distinguishedName)': 'str(e.distinguishedName)',
    'decode_ldap_value(e.cn)': 'str(e.cn.value) if e.cn else ""',
    'decode_ldap_value(e.sAMAccountName)': 'str(e.sAMAccountName.value) if e.sAMAccountName else ""',
    'decode_ldap_value(entry.cn)': 'str(entry.cn.value) if entry.cn else ""',
    'decode_ldap_value(entry.givenName)': 'str(entry.givenName.value) if entry.givenName else ""',
    'decode_ldap_value(entry.sn)': 'str(entry.sn.value) if entry.sn else ""',
    'decode_ldap_value(entry.displayName)': 'str(entry.displayName.value) if entry.displayName else ""',
    'decode_ldap_value(entry.mail)': 'str(entry.mail.value) if entry.mail else ""',
    'decode_ldap_value(entry.telephoneNumber)': 'str(entry.telephoneNumber.value) if entry.telephoneNumber else ""',
    'decode_ldap_value(entry.department)': 'str(entry.department.value) if entry.department else ""',
    'decode_ldap_value(entry.title)': 'str(entry.title.value) if entry.title else ""',
    'decode_ldap_value(entry.description)': 'str(entry.description.value) if entry.description else ""',
    'decode_ldap_value(entry.sAMAccountName)': 'str(entry.sAMAccountName.value) if entry.sAMAccountName else ""',
    'decode_ldap_value(entry.memberOf)': '[str(g) for g in entry.memberOf] if entry.memberOf else []',
    'decode_ldap_value(g) for g in member_of': 'str(g) for g in member_of',
}

for i, line in enumerate(lines):
    if 'decode_ldap_value' in line and 'from .core' not in line:
        for old, new in replacements.items():
            line = line.replace(old, new)
        if 'decode_ldap_value' in line:
            count += 1
    lines[i] = line

with open('routes/users.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)

print(f'✅ Correction terminée. Il reste {count} decode_ldap_value à corriger manuellement.')
