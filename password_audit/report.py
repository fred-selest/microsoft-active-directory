"""Génération du rapport style Specops Password Auditor."""


def _clean_name(name):
    """Nettoyer un nom de compte (décodage Unicode)."""
    if not name:
        return 'Inconnu'
    name = str(name)
    # Si c'est un DN, extraire le CN
    if 'CN=' in name:
        cn = name.split('CN=')[1].split(',')[0]
        # Décoder les séquences Unicode dans le CN
        try:
            return cn.encode('latin-1').decode('unicode_escape').encode('latin-1').decode('utf-8', errors='replace')
        except:
            return cn
    # Décoder les caractères Unicode échappés
    try:
        return name.encode('latin-1').decode('unicode_escape').encode('latin-1').decode('utf-8', errors='replace')
    except:
        return name


def _build_account_data(u, type_default=''):
    """Construire les données complètes d'un compte."""
    # Récupérer toutes les données disponibles
    dn = u.get('dn', u.get('distinguishedName', ''))
    mail = u.get('mail', u.get('email', ''))
    display_name = u.get('display_name', u.get('displayName', ''))
    
    # Si pas de display_name, utiliser username
    if not display_name:
        display_name = u.get('username', u.get('account', u.get('item', 'N/A')))
    
    return {
        'name': _clean_name(u.get('username', u.get('account', u.get('item', '')))),
        'dn': str(dn) if dn else '',
        'mail': str(mail) if mail else '',
        'display_name': str(display_name) if display_name else '',
        'type': u.get('type', type_default),
        'password_age': f"{u.get('password_age_days', u.get('days_old', 'N/A'))} jours",
        'last_login': u.get('last_login', u.get('lastLogon', 'Jamais'))
    }


def generate_auditor_issues(audit_result):
    """
    Générer les issues formatées style Specops Password Auditor.
    Adapté pour la nouvelle structure de données du package password_audit.

    Returns:
        list: Liste des issues avec title, severity, description, remediation, accounts, count, weight
    """
    issues = []

    # 1. Comptes avec mot de passe n'expirant jamais
    never_expires = [u for u in audit_result.get('weak_accounts', [])
                     if u.get('password_never_expires', False)]
    if never_expires:
        issues.append({
            'title': 'Le mot de passe n\'expire jamais',
            'severity': 'ELEVE',
            'description': 'Les mots de passe définis pour ne jamais expirer peuvent être plus vulnérables aux attaques. Un acteur malveillant disposant de plus de temps pour tenter de compromettre ces comptes.',
            'remediation': 'Activez l\'expiration des mots de passe pour tous les comptes. Utilisez des Managed Service Accounts (MSA) pour les comptes de service.',
            'accounts': [_build_account_data(u, 'password_never_expires') for u in never_expires[:10]],
            'count': len(never_expires),
            'weight': 20,
            'show_password_age': True
        })

    # 2. Mots de passe non obligatoires
    no_password_required = [u for u in audit_result.get('weak_accounts', [])
                            if u.get('password_not_required', False)]
    if no_password_required:
        issues.append({
            'title': 'Mots de passe non obligatoires',
            'severity': 'ELEVE',
            'description': 'Les comptes non tenus d\'utiliser un mot de passe peuvent être utilisés comme première étape pour accéder à un système.',
            'remediation': 'Exigez un mot de passe pour tous les comptes et activez les exigences de complexité.',
            'accounts': [_build_account_data(u, 'no_password_required') for u in no_password_required[:10]],
            'count': len(no_password_required),
            'weight': 25,
            'show_last_login': False
        })

    # 3. Délégations non contraintes (comptes délégables)
    delegations = audit_result.get('delegations', [])
    delegable = [d for d in delegations if 'TRUSTED_FOR_DELEGATION' in d.get('issue', '')]
    if delegable:
        issues.append({
            'title': 'Comptes avec délégation non contrainte',
            'severity': 'ELEVE',
            'description': 'La délégation Kerberos non contrainte présente un risque de sécurité important. Un attaquant pourrait exploiter ce privilège pour accéder aux ressources du réseau.',
            'remediation': 'Désactivez la délégation non contrainte ou utilisez la délégation restreinte avec la transition de protocole.',
            'accounts': [{
                'name': _clean_name(d.get('item', d.get('account', d.get('username', '')))),
                'dn': d.get('dn', d.get('distinguishedName', '')),
                'mail': '',
                'display_name': '',
                'type': 'delegation',
                'password_age': 'N/A',
                'last_login': 'N/A'
            } for d in delegable[:10]],
            'count': len(delegable),
            'weight': 20,
            'show_last_login': False
        })

    # 4. Violations de niveaux de privilèges (tiering)
    tiering = audit_result.get('tiering_violations', [])
    if tiering:
        issues.append({
            'title': 'Violations de niveaux de privilèges',
            'severity': 'ELEVE',
            'description': 'Des comptes de haut niveau se connectent sur des machines de niveau inférieur, ce qui expose les identités privilégiées.',
            'remediation': 'Respectez strictement le modèle de hiérarchie administrative. Les comptes de niveau supérieur ne doivent se connecter que sur des machines de même niveau.',
            'accounts': [{
                'name': _clean_name(t.get('item', t.get('account', t.get('username', '')))),
                'dn': '',
                'mail': '',
                'display_name': '',
                'type': 'tiering',
                'password_age': 'N/A',
                'last_login': 'N/A'
            } for t in tiering[:10]],
            'count': len(tiering),
            'weight': 20,
            'show_last_login': False
        })

    # 5. Protocoles hérités (NTLMv1, SMBv1, LDAP simple)
    legacy = audit_result.get('legacy_protocols', [])
    if legacy:
        issues.append({
            'title': 'Protocoles hérités non sécurisés',
            'severity': 'MOYEN',
            'description': 'Les protocoles hérités comme NTLMv1, SMBv1 ou LDAP simple sont vulnérables aux attaques.',
            'remediation': 'Désactivez NTLMv1, SMBv1 et forcez le signing LDAP. Migrez vers Kerberos et SMBv3.',
            'accounts': [],
            'count': len(legacy),
            'weight': 15,
            'show_last_login': False
        })

    # 6. Protected Users non utilisé
    protected = audit_result.get('protected_users', [])
    # Vérifier si des comptes sensibles ne sont PAS dans Protected Users
    sensitive_not_protected = [p for p in protected if p.get('severity') == 'warning']
    if sensitive_not_protected:
        issues.append({
            'title': 'Comptes sensibles hors Protected Users',
            'severity': 'MOYEN',
            'description': 'Les comptes privilégiés devraient être dans le groupe Protected Users pour une protection accrue.',
            'remediation': 'Ajoutez les comptes sensibles au groupe Protected Users.',
            'accounts': [{
                'name': _clean_name(p.get('item', p.get('account', p.get('username', '')))),
                'dn': p.get('dn', ''),
                'mail': '',
                'display_name': '',
                'type': 'protected_users',
                'password_age': 'N/A',
                'last_login': 'N/A'
            } for p in sensitive_not_protected[:10]],
            'count': len(sensitive_not_protected),
            'weight': 10,
            'show_last_login': False
        })

    # 7. Politique de mot de passe faible
    policy = audit_result.get('policy', {})
    policy_issues = []
    if policy.get('minPasswordLength', 0) < 12:
        policy_issues.append(f"Longueur minimale: {policy.get('minPasswordLength', 0)} (recommandé: 12+)")
    if not policy.get('complexity_enabled', False):
        policy_issues.append("Complexité désactivée")
    if policy.get('reversible_encryption', False):
        policy_issues.append("Chiffrement réversible activé (critique)")
    if policy.get('maxPasswordAge', 0) == 0:
        policy_issues.append("Expiration désactivée")

    if policy_issues:
        issues.append({
            'title': 'Politique de mot de passe faible',
            'severity': 'ELEVE',
            'description': 'La politique de mot de passe du domaine ne respecte pas les meilleures pratiques.',
            'remediation': 'Renforcez la politique : 12 caractères minimum, complexité activée, expiration à 60-90 jours.',
            'accounts': [],
            'count': len(policy_issues),
            'weight': 20,
            'details': policy_issues,
            'show_last_login': False
        })

    # 8. Groupes privilégiés avec trop de membres
    privileged = audit_result.get('privileged_groups', [])
    large_groups = [p for p in privileged if p.get('member_count', 0) > 10]
    if large_groups:
        issues.append({
            'title': 'Groupes privilégiés surpeuplés',
            'severity': 'MOYEN',
            'description': 'Certains groupes privilégiés ont trop de membres, augmentant la surface d\'attaque.',
            'remediation': 'Réduisez le nombre de membres des groupes privilégiés et appliquez le principe du moindre privilège.',
            'accounts': [{
                'name': _clean_name(g.get('group', g.get('name', 'Inconnu'))),
                'dn': '',
                'mail': '',
                'display_name': '',
                'type': 'privileged_group',
                'password_age': 'N/A',
                'last_login': 'N/A'
            } for g in large_groups[:10]],
            'count': len(large_groups),
            'weight': 10,
            'show_last_login': False
        })

    # 9. SIEM / Audit non configuré
    siem = audit_result.get('siem_logging', [])
    siem_issues = [s for s in siem if s.get('severity') == 'critical']
    if siem_issues:
        issues.append({
            'title': 'Journalisation d\'audit insuffisante',
            'severity': 'MOYEN',
            'description': 'La journalisation des événements de sécurité n\'est pas correctement configurée.',
            'remediation': 'Activez l\'audit avancé et configurez la forwarding vers un SIEM.',
            'accounts': [],
            'count': len(siem_issues),
            'weight': 10,
            'show_last_login': False
        })

    # 10. Vulnérabilités password spray
    spray = audit_result.get('spray_vulnerabilities', [])
    if spray:
        issues.append({
            'title': 'Vulnérabilité aux attaques par spray',
            'severity': 'MOYEN',
            'description': 'Certains comptes sont vulnérables aux attaques par password spray.',
            'remediation': 'Activez le verrouillage de compte et surveillez les tentatives de connexion échouées.',
            'accounts': [{
                'name': _clean_name(s.get('username', s.get('account', ''))),
                'dn': s.get('dn', ''),
                'mail': s.get('mail', ''),
                'display_name': s.get('display_name', ''),
                'type': 'spray_vulnerability',
                'password_age': 'N/A',
                'last_login': 'N/A'
            } for s in spray[:10]],
            'count': len(spray),
            'weight': 15,
            'show_last_login': False
        })

    return issues
