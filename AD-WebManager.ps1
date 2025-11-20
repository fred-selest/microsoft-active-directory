#Requires -Version 5.1

<#
.SYNOPSIS
    Serveur web pour la gestion d'Active Directory
.DESCRIPTION
    Interface web complète pour gérer les utilisateurs Active Directory
.NOTES
    Nécessite les droits administrateur pour démarrer le serveur
#>

# Configuration du serveur
$Port = 8080
$Prefix = "http://localhost:$Port/"

# Vérifier si le module AD est disponible
$adModuleAvailable = Get-Module -ListAvailable -Name ActiveDirectory

# Variable de session pour stocker les identifiants
$script:adCredential = $null
$script:adDomain = $null
$script:sessionToken = $null

# Fonction pour générer un token de session
function New-SessionToken {
    return [System.Guid]::NewGuid().ToString()
}

# Fonction pour échapper les caractères spéciaux LDAP (protection contre injection)
function Escape-LDAPFilter {
    param(
        [string]$Input
    )

    if ([string]::IsNullOrEmpty($Input)) {
        return ""
    }

    # Échapper les caractères dangereux pour LDAP
    # ( ) \ * / NUL
    $escaped = $Input -replace '\\', '\5c'  # Backslash doit être échappé en premier
    $escaped = $escaped -replace '\*', '\2a'
    $escaped = $escaped -replace '\(', '\28'
    $escaped = $escaped -replace '\)', '\29'
    $escaped = $escaped -replace '/', '\2f'
    $escaped = $escaped -replace "`0", '\00'

    return $escaped
}

# Fonction pour écrire dans le journal d'audit
function Write-AuditLog {
    param(
        [string]$Action,
        [string]$User,
        [string]$Details,
        [string]$PerformedBy
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp | $PerformedBy | $Action | User: $User | $Details"
    
    $logFile = Join-Path $PSScriptRoot "AD-WebManager-Audit.log"
    Add-Content -Path $logFile -Value $logEntry
}

# Fonction pour tester la connexion AD
function Test-ADConnection {
    param(
        [string]$Domain,
        [string]$Username,
        [string]$Password
    )
    
    try {
        $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($Username, $securePassword)
        
        # Tester la connexion
        $null = Get-ADDomain -Server $Domain -Credential $credential -ErrorAction Stop
        
        return @{
            Success = $true
            Message = "Connexion réussie"
            Credential = $credential
        }
    } catch {
        return @{
            Success = $false
            Message = $_.Exception.Message
            Credential = $null
        }
    }
}

# Fonction pour obtenir le HTML de la page de connexion
function Get-LoginPage {
    param([string]$ErrorMessage = "")
    
    $errorHtml = if ($ErrorMessage) {
        "<div class='alert alert-danger'>$ErrorMessage</div>"
    } else { "" }
    
    return @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion - AD Manager</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .login-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 450px;
            padding: 40px;
            animation: slideIn 0.5s ease-out;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo h1 {
            color: #667eea;
            font-size: 32px;
            margin-bottom: 5px;
        }
        
        .logo p {
            color: #666;
            font-size: 14px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
            font-size: 14px;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            transition: all 0.3s ease;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn-login {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease;
            margin-top: 10px;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        
        .btn-login:active {
            transform: translateY(0);
        }
        
        .alert {
            padding: 12px 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        
        .alert-danger {
            background-color: #fee;
            color: #c33;
            border-left: 4px solid #c33;
        }
        
        .info-box {
            background-color: #e7f3ff;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            font-size: 13px;
            color: #0066cc;
            border-left: 4px solid #0066cc;
        }
        
        .info-box strong {
            display: block;
            margin-bottom: 5px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🔐 AD Manager</h1>
            <p>Gestion Active Directory</p>
        </div>
        
        $errorHtml
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="domain">Nom de domaine ou serveur DC</label>
                <input type="text" id="domain" name="domain" placeholder="exemple: domain.local ou 192.168.1.10" required>
            </div>
            
            <div class="form-group">
                <label for="username">Compte administrateur</label>
                <input type="text" id="username" name="username" placeholder="exemple: administrateur@domain.local ou DOMAIN\admin" required>
            </div>
            
            <div class="form-group">
                <label for="password">Mot de passe</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn-login">Se connecter</button>
        </form>
        
        <div class="info-box">
            <strong>ℹ️ Informations importantes :</strong>
            • Le serveur web écoute sur le port $Port<br>
            • Vos identifiants sont stockés en mémoire uniquement<br>
            • Toutes les actions sont enregistrées dans le journal d'audit
        </div>
    </div>
</body>
</html>
"@
}

# Fonction pour obtenir la page principale
function Get-MainPage {
    param([string]$SessionToken)
    
    return @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Manager - Tableau de bord</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
        }
        
        .navbar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .navbar h1 {
            font-size: 24px;
        }
        
        .navbar-info {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .btn-logout {
            background: rgba(255,255,255,0.2);
            color: white;
            padding: 8px 20px;
            border: 1px solid rgba(255,255,255,0.3);
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.3s ease;
        }
        
        .btn-logout:hover {
            background: rgba(255,255,255,0.3);
        }
        
        .container {
            max-width: 1400px;
            margin: 30px auto;
            padding: 0 20px;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #e0e0e0;
            overflow-x: auto;
        }
        
        .tab {
            padding: 12px 24px;
            background: transparent;
            border: none;
            color: #666;
            cursor: pointer;
            font-size: 15px;
            font-weight: 600;
            transition: all 0.3s ease;
            border-bottom: 3px solid transparent;
            white-space: nowrap;
        }
        
        .tab:hover {
            color: #667eea;
        }
        
        .tab.active {
            color: #667eea;
            border-bottom-color: #667eea;
        }
        
        .tab-content {
            display: none;
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            animation: fadeIn 0.3s ease;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .form-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
            font-size: 14px;
        }
        
        .form-group input,
        .form-group textarea,
        .form-group select {
            width: 100%;
            padding: 10px 12px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
            transition: border-color 0.3s ease;
        }
        
        .form-group input:focus,
        .form-group textarea:focus,
        .form-group select:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .form-group textarea {
            resize: vertical;
            min-height: 80px;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
        }
        
        .btn-group {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }
        
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
        }
        
        .btn-secondary {
            background: #f0f0f0;
            color: #333;
        }
        
        .btn-secondary:hover {
            background: #e0e0e0;
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        
        .btn-warning {
            background: #ffc107;
            color: #333;
        }
        
        .btn-auto {
            background: #17a2b8;
            color: white;
            font-size: 12px;
            padding: 8px 16px;
        }
        
        .status-box {
            margin-top: 20px;
            padding: 15px;
            border-radius: 6px;
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .search-box {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .search-box input {
            flex: 1;
        }
        
        .results-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .results-table th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        
        .results-table td {
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .results-table tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .badge-success {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-danger {
            background: #f8d7da;
            color: #721c24;
        }
        
        .alert {
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
        }
        
        .alert-info {
            background: #d1ecf1;
            color: #0c5460;
            border-left: 4px solid #0c5460;
        }
        
        .alert-success {
            background: #d4edda;
            color: #155724;
            border-left: 4px solid #155724;
        }
        
        .alert-danger {
            background: #f8d7da;
            color: #721c24;
            border-left: 4px solid #721c24;
        }
        
        .hidden {
            display: none;
        }
        
        .list-group {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .list-box {
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            padding: 10px;
            min-height: 250px;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .list-box h3 {
            font-size: 16px;
            margin-bottom: 10px;
            color: #667eea;
        }
        
        .list-item {
            padding: 8px 10px;
            background: #f8f9fa;
            margin-bottom: 5px;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s ease;
        }
        
        .list-item:hover {
            background: #e9ecef;
        }
        
        .list-item.selected {
            background: #667eea;
            color: white;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>🔐 AD Manager</h1>
        <div class="navbar-info">
            <span>Domaine: <strong>$($script:adDomain)</strong></span>
            <a href="/logout" class="btn-logout">Déconnexion</a>
        </div>
    </div>
    
    <div class="container">
        <div class="tabs">
            <button class="tab active" onclick="showTab('create')">➕ Créer un utilisateur</button>
            <button class="tab" onclick="showTab('search')">🔍 Rechercher/Modifier</button>
            <button class="tab" onclick="showTab('groups')">👥 Gestion des groupes</button>
            <button class="tab" onclick="showTab('export')">📊 Export/Rapports</button>
            <button class="tab" onclick="showTab('audit')">📋 Journal d'audit</button>
        </div>
        
        <!-- ONGLET CRÉATION -->
        <div id="tab-create" class="tab-content active">
            <h2>Créer un nouvel utilisateur</h2>
            <form id="form-create" onsubmit="createUser(event)">
                <div class="form-row">
                    <div class="form-group">
                        <label>Prénom *</label>
                        <input type="text" name="firstName" id="firstName" required>
                    </div>
                    <div class="form-group">
                        <label>Nom *</label>
                        <input type="text" name="lastName" id="lastName" required>
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label>Identifiant (login) *</label>
                        <div style="display: flex; gap: 10px;">
                            <input type="text" name="samAccount" id="samAccount" required style="flex: 1;">
                            <button type="button" class="btn btn-auto" onclick="generateLogin()">Auto-générer</button>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" name="email" id="email">
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label>Mot de passe *</label>
                        <input type="password" name="password" id="password" required>
                    </div>
                    <div class="form-group">
                        <label>Département</label>
                        <input type="text" name="department" id="department">
                    </div>
                </div>
                
                <div class="form-group">
                    <label>OU (chemin complet) *</label>
                    <input type="text" name="ou" id="ou" value="OU=Users,DC=domain,DC=com" required>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label>Téléphone</label>
                        <input type="tel" name="phone" id="phone">
                    </div>
                    <div class="form-group">
                        <label>Description</label>
                        <input type="text" name="description" id="description">
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="checkbox-group">
                        <input type="checkbox" name="enabled" id="enabled" checked>
                        <label for="enabled">Activer le compte</label>
                    </div>
                    <div class="checkbox-group">
                        <input type="checkbox" name="changePassword" id="changePassword" checked>
                        <label for="changePassword">Forcer le changement de mot de passe</label>
                    </div>
                </div>
                
                <div class="btn-group">
                    <button type="submit" class="btn btn-primary">Créer l'utilisateur</button>
                    <button type="reset" class="btn btn-secondary">Effacer</button>
                </div>
            </form>
            
            <div id="create-status" class="status-box hidden"></div>
        </div>
        
        <!-- ONGLET RECHERCHE -->
        <div id="tab-search" class="tab-content">
            <h2>Rechercher et modifier un utilisateur</h2>
            
            <div class="search-box">
                <input type="text" id="search-input" placeholder="Rechercher par login ou nom...">
                <button class="btn btn-primary" onclick="searchUsers()">Rechercher</button>
            </div>
            
            <div id="search-results"></div>
            
            <div id="user-details" class="hidden" style="margin-top: 30px;">
                <h3>Détails de l'utilisateur</h3>
                <form id="form-update" onsubmit="updateUser(event)">
                    <input type="hidden" id="update-samAccount">
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label>Prénom</label>
                            <input type="text" id="update-firstName">
                        </div>
                        <div class="form-group">
                            <label>Nom</label>
                            <input type="text" id="update-lastName">
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label>Email</label>
                            <input type="email" id="update-email">
                        </div>
                        <div class="form-group">
                            <label>Département</label>
                            <input type="text" id="update-department">
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label>Téléphone</label>
                            <input type="tel" id="update-phone">
                        </div>
                        <div class="form-group">
                            <label>Description</label>
                            <input type="text" id="update-description">
                        </div>
                    </div>
                    
                    <div class="checkbox-group">
                        <input type="checkbox" id="update-enabled">
                        <label for="update-enabled">Compte activé</label>
                    </div>
                    
                    <div class="btn-group">
                        <button type="submit" class="btn btn-primary">Mettre à jour</button>
                        <button type="button" class="btn btn-warning" onclick="resetPassword()">Réinitialiser mot de passe</button>
                        <button type="button" class="btn btn-danger" onclick="disableUser()">Désactiver</button>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- ONGLET GROUPES -->
        <div id="tab-groups" class="tab-content">
            <h2>Gestion des groupes</h2>
            
            <div class="search-box">
                <input type="text" id="group-user-input" placeholder="Login de l'utilisateur...">
                <button class="btn btn-primary" onclick="loadUserGroups()">Charger les groupes</button>
            </div>
            
            <div id="groups-container" class="hidden">
                <div class="list-group">
                    <div class="list-box">
                        <h3>Groupes de l'utilisateur</h3>
                        <div id="current-groups"></div>
                        <button class="btn btn-danger" style="margin-top: 10px; width: 100%;" onclick="removeFromGroups()">Retirer des groupes sélectionnés</button>
                    </div>
                    
                    <div class="list-box">
                        <h3>Groupes disponibles</h3>
                        <input type="text" id="search-groups-input" placeholder="Rechercher..." style="width: 100%; margin-bottom: 10px;">
                        <button class="btn btn-secondary" style="width: 100%; margin-bottom: 10px;" onclick="searchGroups()">Rechercher</button>
                        <div id="available-groups"></div>
                        <button class="btn btn-success" style="margin-top: 10px; width: 100%;" onclick="addToGroups()">Ajouter aux groupes sélectionnés</button>
                    </div>
                </div>
            </div>
            
            <div id="groups-status" class="status-box hidden"></div>
        </div>
        
        <!-- ONGLET EXPORT -->
        <div id="tab-export" class="tab-content">
            <h2>Export et rapports</h2>
            
            <div class="form-group">
                <label>Type d'export</label>
                <select id="export-type">
                    <option value="all">Tous les utilisateurs</option>
                    <option value="enabled">Utilisateurs actifs uniquement</option>
                    <option value="disabled">Utilisateurs désactivés</option>
                    <option value="recent">Créés dans les 30 derniers jours</option>
                    <option value="nopassword">N'ayant jamais changé de mot de passe</option>
                </select>
            </div>
            
            <div class="form-group">
                <label>OU spécifique (optionnel)</label>
                <input type="text" id="export-ou" placeholder="Laisser vide pour exporter tout le domaine">
            </div>
            
            <div class="btn-group">
                <button class="btn btn-primary" onclick="exportCSV()">📥 Exporter en CSV</button>
                <button class="btn btn-success" onclick="exportHTML()">📊 Générer rapport HTML</button>
            </div>
            
            <div id="export-status" class="status-box hidden"></div>
        </div>
        
        <!-- ONGLET AUDIT -->
        <div id="tab-audit" class="tab-content">
            <h2>Journal d'audit</h2>
            
            <div class="alert alert-info">
                Toutes les actions effectuées via cette interface sont enregistrées dans le journal d'audit.
            </div>
            
            <div class="btn-group">
                <button class="btn btn-primary" onclick="loadAudit()">🔄 Actualiser</button>
                <button class="btn btn-danger" onclick="clearAudit()">🗑️ Effacer le journal</button>
            </div>
            
            <div id="audit-log" class="status-box" style="max-height: 600px;"></div>
        </div>
    </div>
    
    <script>
        const sessionToken = '$SessionToken';
        let currentUser = null;
        let selectedCurrentGroups = [];
        let selectedAvailableGroups = [];
        
        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById('tab-' + tabName).classList.add('active');
        }
        
        function generateLogin() {
            const firstName = document.getElementById('firstName').value.trim();
            const lastName = document.getElementById('lastName').value.trim();
            
            if (!firstName || !lastName) {
                alert('Veuillez d\'abord renseigner le prénom et le nom.');
                return;
            }
            
            const login = firstName.charAt(0).toLowerCase() + lastName.toLowerCase()
                .replace(/[àâä]/g, 'a')
                .replace(/[éèêë]/g, 'e')
                .replace(/[îï]/g, 'i')
                .replace(/[ôö]/g, 'o')
                .replace(/[ùûü]/g, 'u')
                .replace(/[ç]/g, 'c')
                .replace(/\s/g, '');
            
            document.getElementById('samAccount').value = login;
            document.getElementById('email').value = login + '@' + '$($script:adDomain)';
        }
        
        async function createUser(event) {
            event.preventDefault();
            
            const formData = new FormData(event.target);
            const data = Object.fromEntries(formData);
            data.sessionToken = sessionToken;
            data.enabled = document.getElementById('enabled').checked;
            data.changePassword = document.getElementById('changePassword').checked;
            
            const statusDiv = document.getElementById('create-status');
            statusDiv.classList.remove('hidden');
            statusDiv.innerHTML = 'Création en cours...';
            
            try {
                const response = await fetch('/api/create-user', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    statusDiv.innerHTML = '<div class="alert alert-success">✓ ' + result.message + '</div>';
                    event.target.reset();
                    document.getElementById('enabled').checked = true;
                    document.getElementById('changePassword').checked = true;
                } else {
                    statusDiv.innerHTML = '<div class="alert alert-danger">✗ ' + result.message + '</div>';
                }
            } catch (error) {
                statusDiv.innerHTML = '<div class="alert alert-danger">✗ Erreur: ' + error.message + '</div>';
            }
        }
        
        async function searchUsers() {
            const query = document.getElementById('search-input').value.trim();
            if (!query) return;
            
            try {
                const response = await fetch('/api/search-users', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sessionToken, query })
                });
                
                const result = await response.json();
                const resultsDiv = document.getElementById('search-results');
                
                if (result.success && result.users.length > 0) {
                    let html = '<table class="results-table"><thead><tr>';
                    html += '<th>Login</th><th>Nom complet</th><th>Email</th><th>Statut</th><th>Action</th>';
                    html += '</tr></thead><tbody>';
                    
                    result.users.forEach(user => {
                        const statusBadge = user.enabled ? 
                            '<span class="badge badge-success">Actif</span>' : 
                            '<span class="badge badge-danger">Désactivé</span>';
                        
                        html += '<tr>';
                        html += '<td>' + user.samAccountName + '</td>';
                        html += '<td>' + user.name + '</td>';
                        html += '<td>' + (user.email || '-') + '</td>';
                        html += '<td>' + statusBadge + '</td>';
                        html += '<td><button class="btn btn-primary" onclick="loadUserDetails(\'' + user.samAccountName + '\')">Modifier</button></td>';
                        html += '</tr>';
                    });
                    
                    html += '</tbody></table>';
                    resultsDiv.innerHTML = html;
                } else {
                    resultsDiv.innerHTML = '<div class="alert alert-info">Aucun utilisateur trouvé.</div>';
                }
            } catch (error) {
                alert('Erreur: ' + error.message);
            }
        }
        
        async function loadUserDetails(samAccount) {
            try {
                const response = await fetch('/api/get-user', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sessionToken, samAccount })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    currentUser = result.user;
                    document.getElementById('update-samAccount').value = result.user.samAccountName;
                    document.getElementById('update-firstName').value = result.user.givenName || '';
                    document.getElementById('update-lastName').value = result.user.surname || '';
                    document.getElementById('update-email').value = result.user.email || '';
                    document.getElementById('update-department').value = result.user.department || '';
                    document.getElementById('update-phone').value = result.user.phone || '';
                    document.getElementById('update-description').value = result.user.description || '';
                    document.getElementById('update-enabled').checked = result.user.enabled;
                    
                    document.getElementById('user-details').classList.remove('hidden');
                }
            } catch (error) {
                alert('Erreur: ' + error.message);
            }
        }
        
        async function updateUser(event) {
            event.preventDefault();
            
            const data = {
                sessionToken,
                samAccount: document.getElementById('update-samAccount').value,
                firstName: document.getElementById('update-firstName').value,
                lastName: document.getElementById('update-lastName').value,
                email: document.getElementById('update-email').value,
                department: document.getElementById('update-department').value,
                phone: document.getElementById('update-phone').value,
                description: document.getElementById('update-description').value,
                enabled: document.getElementById('update-enabled').checked
            };
            
            try {
                const response = await fetch('/api/update-user', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    alert('✓ ' + result.message);
                    searchUsers();
                } else {
                    alert('✗ ' + result.message);
                }
            } catch (error) {
                alert('Erreur: ' + error.message);
            }
        }
        
        async function resetPassword() {
            const newPassword = prompt('Nouveau mot de passe:');
            if (!newPassword) return;
            
            const forceChange = confirm('Forcer le changement de mot de passe à la prochaine connexion?');
            
            try {
                const response = await fetch('/api/reset-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        sessionToken,
                        samAccount: currentUser.samAccountName,
                        newPassword,
                        forceChange
                    })
                });
                
                const result = await response.json();
                alert(result.success ? '✓ ' + result.message : '✗ ' + result.message);
            } catch (error) {
                alert('Erreur: ' + error.message);
            }
        }
        
        async function disableUser() {
            if (!confirm('Voulez-vous vraiment désactiver ce compte?')) return;
            
            try {
                const response = await fetch('/api/disable-user', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        sessionToken,
                        samAccount: currentUser.samAccountName
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    alert('✓ ' + result.message);
                    searchUsers();
                    document.getElementById('user-details').classList.add('hidden');
                } else {
                    alert('✗ ' + result.message);
                }
            } catch (error) {
                alert('Erreur: ' + error.message);
            }
        }
        
        async function loadUserGroups() {
            const username = document.getElementById('group-user-input').value.trim();
            if (!username) return;
            
            try {
                const response = await fetch('/api/get-user-groups', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sessionToken, username })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    let html = '';
                    result.groups.forEach(group => {
                        html += '<div class="list-item" onclick="toggleGroupSelection(this, \'current\')">' + group + '</div>';
                    });
                    
                    document.getElementById('current-groups').innerHTML = html;
                    document.getElementById('groups-container').classList.remove('hidden');
                    
                    const statusDiv = document.getElementById('groups-status');
                    statusDiv.classList.remove('hidden');
                    statusDiv.innerHTML = '<div class="alert alert-success">✓ ' + result.groups.length + ' groupe(s) chargé(s)</div>';
                } else {
                    alert('✗ ' + result.message);
                }
            } catch (error) {
                alert('Erreur: ' + error.message);
            }
        }
        
        async function searchGroups() {
            const query = document.getElementById('search-groups-input').value.trim();
            if (!query) return;
            
            try {
                const response = await fetch('/api/search-groups', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sessionToken, query })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    let html = '';
                    result.groups.forEach(group => {
                        html += '<div class="list-item" onclick="toggleGroupSelection(this, \'available\')">' + group + '</div>';
                    });
                    
                    document.getElementById('available-groups').innerHTML = html;
                } else {
                    alert('✗ ' + result.message);
                }
            } catch (error) {
                alert('Erreur: ' + error.message);
            }
        }
        
        function toggleGroupSelection(element, type) {
            element.classList.toggle('selected');
            
            const groupName = element.textContent;
            const array = type === 'current' ? selectedCurrentGroups : selectedAvailableGroups;
            
            const index = array.indexOf(groupName);
            if (index > -1) {
                array.splice(index, 1);
            } else {
                array.push(groupName);
            }
        }
        
        async function addToGroups() {
            if (selectedAvailableGroups.length === 0) {
                alert('Veuillez sélectionner au moins un groupe.');
                return;
            }
            
            const username = document.getElementById('group-user-input').value.trim();
            
            try {
                const response = await fetch('/api/add-to-groups', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sessionToken, username, groups: selectedAvailableGroups })
                });
                
                const result = await response.json();
                alert(result.success ? '✓ ' + result.message : '✗ ' + result.message);
                
                if (result.success) {
                    selectedAvailableGroups = [];
                    loadUserGroups();
                }
            } catch (error) {
                alert('Erreur: ' + error.message);
            }
        }
        
        async function removeFromGroups() {
            if (selectedCurrentGroups.length === 0) {
                alert('Veuillez sélectionner au moins un groupe.');
                return;
            }
            
            if (!confirm('Voulez-vous vraiment retirer l\'utilisateur de ces groupes?')) return;
            
            const username = document.getElementById('group-user-input').value.trim();
            
            try {
                const response = await fetch('/api/remove-from-groups', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sessionToken, username, groups: selectedCurrentGroups })
                });
                
                const result = await response.json();
                alert(result.success ? '✓ ' + result.message : '✗ ' + result.message);
                
                if (result.success) {
                    selectedCurrentGroups = [];
                    loadUserGroups();
                }
            } catch (error) {
                alert('Erreur: ' + error.message);
            }
        }
        
        async function exportCSV() {
            const statusDiv = document.getElementById('export-status');
            statusDiv.classList.remove('hidden');
            statusDiv.innerHTML = 'Export en cours...';
            
            try {
                const response = await fetch('/api/export-csv', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        sessionToken,
                        type: document.getElementById('export-type').value,
                        ou: document.getElementById('export-ou').value
                    })
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'AD-Export-' + new Date().toISOString().slice(0,10) + '.csv';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(url);
                    
                    statusDiv.innerHTML = '<div class="alert alert-success">✓ Export réussi!</div>';
                } else {
                    statusDiv.innerHTML = '<div class="alert alert-danger">✗ Erreur lors de l\'export</div>';
                }
            } catch (error) {
                statusDiv.innerHTML = '<div class="alert alert-danger">✗ Erreur: ' + error.message + '</div>';
            }
        }
        
        async function exportHTML() {
            const statusDiv = document.getElementById('export-status');
            statusDiv.classList.remove('hidden');
            statusDiv.innerHTML = 'Génération du rapport...';
            
            try {
                const response = await fetch('/api/export-html', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        sessionToken,
                        type: document.getElementById('export-type').value,
                        ou: document.getElementById('export-ou').value
                    })
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    window.open(url, '_blank');
                    
                    statusDiv.innerHTML = '<div class="alert alert-success">✓ Rapport généré et ouvert dans un nouvel onglet!</div>';
                } else {
                    statusDiv.innerHTML = '<div class="alert alert-danger">✗ Erreur lors de la génération</div>';
                }
            } catch (error) {
                statusDiv.innerHTML = '<div class="alert alert-danger">✗ Erreur: ' + error.message + '</div>';
            }
        }
        
        async function loadAudit() {
            try {
                const response = await fetch('/api/get-audit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sessionToken })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    document.getElementById('audit-log').textContent = result.log || 'Aucune entrée dans le journal.';
                } else {
                    alert('✗ ' + result.message);
                }
            } catch (error) {
                alert('Erreur: ' + error.message);
            }
        }
        
        async function clearAudit() {
            if (!confirm('Voulez-vous vraiment effacer tout le journal d\'audit?')) return;
            
            try {
                const response = await fetch('/api/clear-audit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sessionToken })
                });
                
                const result = await response.json();
                alert(result.success ? '✓ ' + result.message : '✗ ' + result.message);
                
                if (result.success) {
                    loadAudit();
                }
            } catch (error) {
                alert('Erreur: ' + error.message);
            }
        }
        
        // Charger le journal d'audit au chargement de la page
        loadAudit();
    </script>
</body>
</html>
"@
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  🔐 AD Web Manager - Serveur Web" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (-not $adModuleAvailable) {
    Write-Host "⚠️  ATTENTION: Le module ActiveDirectory n'est pas installé." -ForegroundColor Yellow
    Write-Host "   Le serveur démarrera mais ne pourra pas se connecter à AD." -ForegroundColor Yellow
    Write-Host "   Installez les outils RSAT pour activer les fonctionnalités AD." -ForegroundColor Yellow
    Write-Host ""
} else {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
}

Write-Host "🚀 Démarrage du serveur web..." -ForegroundColor Green
Write-Host "📍 URL: $Prefix" -ForegroundColor Green
Write-Host "🛑 Pour arrêter le serveur, appuyez sur Ctrl+C" -ForegroundColor Yellow
Write-Host ""

# Créer le listener HTTP
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($Prefix)

try {
    $listener.Start()
    Write-Host "✅ Serveur démarré avec succès!" -ForegroundColor Green
    Write-Host "🌐 Ouvrez votre navigateur à l'adresse: $Prefix" -ForegroundColor Cyan
    Write-Host ""
    
    # Ouvrir automatiquement le navigateur
    Start-Process $Prefix
    
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $path = $request.Url.LocalPath
        $method = $request.HttpMethod
        
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - $method $path" -ForegroundColor Gray
        
        # Route: Page de connexion
        if ($path -eq "/" -and $method -eq "GET") {
            $html = Get-LoginPage
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
            $response.ContentType = "text/html; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        # Route: Traitement du login
        elseif ($path -eq "/login" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $body = $reader.ReadToEnd()
            $reader.Close()
            
            # Parser les données du formulaire
            $params = @{}
            $body -split '&' | ForEach-Object {
                $pair = $_ -split '='
                $params[$pair[0]] = [System.Web.HttpUtility]::UrlDecode($pair[1])
            }
            
            $testResult = Test-ADConnection -Domain $params['domain'] -Username $params['username'] -Password $params['password']
            
            if ($testResult.Success) {
                $script:adCredential = $testResult.Credential
                $script:adDomain = $params['domain']
                $script:sessionToken = New-SessionToken
                
                Write-Host "✅ Connexion réussie pour $($params['username'])" -ForegroundColor Green
                
                # Rediriger vers la page principale
                $html = Get-MainPage -SessionToken $script:sessionToken
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
                $response.ContentType = "text/html; charset=utf-8"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            } else {
                Write-Host "❌ Échec de connexion: $($testResult.Message)" -ForegroundColor Red
                $html = Get-LoginPage -ErrorMessage "Échec de la connexion: $($testResult.Message)"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
                $response.ContentType = "text/html; charset=utf-8"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
        }
        
        # Route: Déconnexion
        elseif ($path -eq "/logout") {
            $script:adCredential = $null
            $script:adDomain = $null
            $script:sessionToken = $null
            
            $response.Redirect($Prefix)
        }
        
        # Route: API - Créer un utilisateur
        elseif ($path -eq "/api/create-user" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    $displayName = "$($json.firstName) $($json.lastName)"
                    
                    $params = @{
                        GivenName = $json.firstName
                        Surname = $json.lastName
                        Name = $displayName
                        DisplayName = $displayName
                        SamAccountName = $json.samAccount
                        UserPrincipalName = "$($json.samAccount)@$script:adDomain"
                        Path = $json.ou
                        AccountPassword = (ConvertTo-SecureString $json.password -AsPlainText -Force)
                        Enabled = $json.enabled
                        ChangePasswordAtLogon = $json.changePassword
                        Server = $script:adDomain
                        Credential = $script:adCredential
                    }
                    
                    if ($json.email) { $params.Add('EmailAddress', $json.email) }
                    if ($json.department) { $params.Add('Department', $json.department) }
                    if ($json.phone) { $params.Add('OfficePhone', $json.phone) }
                    if ($json.description) { $params.Add('Description', $json.description) }
                    
                    New-ADUser @params
                    
                    $result.success = $true
                    $result.message = "Utilisateur '$displayName' créé avec succès"
                    
                    Write-AuditLog -Action "CREATE_USER" -User $json.samAccount -Details "Name: $displayName" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json))
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        # Route: API - Rechercher des utilisateurs
        elseif ($path -eq "/api/search-users" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; users = @(); message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    # Échapper les caractères spéciaux pour éviter l'injection LDAP
                    $escapedQuery = Escape-LDAPFilter -Input $json.query
                    $searchTerm = "*$escapedQuery*"
                    $users = Get-ADUser -Filter "SamAccountName -like '$searchTerm' -or Name -like '$searchTerm'" `
                        -Properties EmailAddress, Enabled `
                        -Server $script:adDomain `
                        -Credential $script:adCredential
                    
                    $result.success = $true
                    $result.users = $users | ForEach-Object {
                        @{
                            samAccountName = $_.SamAccountName
                            name = $_.Name
                            email = $_.EmailAddress
                            enabled = $_.Enabled
                        }
                    }
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 3))
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        # Route: API - Obtenir les détails d'un utilisateur
        elseif ($path -eq "/api/get-user" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; user = $null; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    $user = Get-ADUser -Identity $json.samAccount `
                        -Properties * `
                        -Server $script:adDomain `
                        -Credential $script:adCredential
                    
                    $result.success = $true
                    $result.user = @{
                        samAccountName = $user.SamAccountName
                        givenName = $user.GivenName
                        surname = $user.Surname
                        email = $user.EmailAddress
                        department = $user.Department
                        phone = $user.OfficePhone
                        description = $user.Description
                        enabled = $user.Enabled
                    }
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 3))
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        # Route: API - Mettre à jour un utilisateur
        elseif ($path -eq "/api/update-user" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    Set-ADUser -Identity $json.samAccount `
                        -GivenName $json.firstName `
                        -Surname $json.lastName `
                        -EmailAddress $json.email `
                        -Department $json.department `
                        -OfficePhone $json.phone `
                        -Description $json.description `
                        -Enabled $json.enabled `
                        -Server $script:adDomain `
                        -Credential $script:adCredential
                    
                    $result.success = $true
                    $result.message = "Utilisateur mis à jour avec succès"
                    
                    Write-AuditLog -Action "UPDATE_USER" -User $json.samAccount -Details "Modified properties" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json))
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        # Route: API - Réinitialiser le mot de passe
        elseif ($path -eq "/api/reset-password" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    Set-ADAccountPassword -Identity $json.samAccount `
                        -Reset `
                        -NewPassword (ConvertTo-SecureString $json.newPassword -AsPlainText -Force) `
                        -Server $script:adDomain `
                        -Credential $script:adCredential
                    
                    if ($json.forceChange) {
                        Set-ADUser -Identity $json.samAccount -ChangePasswordAtLogon $true `
                            -Server $script:adDomain `
                            -Credential $script:adCredential
                    }
                    
                    $result.success = $true
                    $result.message = "Mot de passe réinitialisé avec succès"
                    
                    Write-AuditLog -Action "RESET_PASSWORD" -User $json.samAccount -Details "Force change: $($json.forceChange)" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json))
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        # Route: API - Désactiver un utilisateur
        elseif ($path -eq "/api/disable-user" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    Disable-ADAccount -Identity $json.samAccount `
                        -Server $script:adDomain `
                        -Credential $script:adCredential
                    
                    $result.success = $true
                    $result.message = "Compte désactivé avec succès"
                    
                    Write-AuditLog -Action "DISABLE_ACCOUNT" -User $json.samAccount -Details "Account disabled" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json))
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        # Route: API - Obtenir les groupes d'un utilisateur
        elseif ($path -eq "/api/get-user-groups" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; groups = @(); message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    $groups = Get-ADPrincipalGroupMembership -Identity $json.username `
                        -Server $script:adDomain `
                        -Credential $script:adCredential | 
                        Select-Object -ExpandProperty Name | 
                        Sort-Object
                    
                    $result.success = $true
                    $result.groups = $groups
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 3))
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        # Route: API - Rechercher des groupes
        elseif ($path -eq "/api/search-groups" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; groups = @(); message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    # Échapper les caractères spéciaux pour éviter l'injection LDAP
                    $escapedQuery = Escape-LDAPFilter -Input $json.query
                    $searchTerm = "*$escapedQuery*"
                    $groups = Get-ADGroup -Filter "Name -like '$searchTerm'" `
                        -Server $script:adDomain `
                        -Credential $script:adCredential | 
                        Select-Object -ExpandProperty Name | 
                        Sort-Object
                    
                    $result.success = $true
                    $result.groups = $groups
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 3))
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        # Route: API - Ajouter à des groupes
        elseif ($path -eq "/api/add-to-groups" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    $successCount = 0
                    foreach ($group in $json.groups) {
                        try {
                            Add-ADGroupMember -Identity $group -Members $json.username `
                                -Server $script:adDomain `
                                -Credential $script:adCredential
                            $successCount++
                        } catch {
                            # Continuer même en cas d'erreur
                        }
                    }
                    
                    $result.success = $true
                    $result.message = "$successCount groupe(s) ajouté(s) avec succès"
                    
                    Write-AuditLog -Action "ADD_TO_GROUPS" -User $json.username -Details "$successCount groups added" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json))
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        # Route: API - Retirer de groupes
        elseif ($path -eq "/api/remove-from-groups" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    $successCount = 0
                    foreach ($group in $json.groups) {
                        if ($group -eq "Domain Users") { continue }
                        
                        try {
                            Remove-ADGroupMember -Identity $group -Members $json.username -Confirm:$false `
                                -Server $script:adDomain `
                                -Credential $script:adCredential
                            $successCount++
                        } catch {
                            # Continuer même en cas d'erreur
                        }
                    }
                    
                    $result.success = $true
                    $result.message = "$successCount groupe(s) retiré(s) avec succès"
                    
                    Write-AuditLog -Action "REMOVE_FROM_GROUPS" -User $json.username -Details "$successCount groups removed" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json))
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        # Route: API - Export CSV (simplifié - à compléter)
        elseif ($path -eq "/api/export-csv" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $response.StatusCode = 403
            } else {
                try {
                    $filter = switch ($json.type) {
                        "all" { "*" }
                        "enabled" { "Enabled -eq `$true" }
                        "disabled" { "Enabled -eq `$false" }
                        default { "*" }
                    }
                    
                    $users = Get-ADUser -Filter $filter `
                        -Properties EmailAddress, Enabled, Created, Department `
                        -Server $script:adDomain `
                        -Credential $script:adCredential
                    
                    $csv = $users | Select-Object SamAccountName, Name, EmailAddress, Enabled, Created, Department | 
                        ConvertTo-Csv -NoTypeInformation | 
                        Out-String
                    
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($csv)
                    $response.ContentType = "text/csv"
                    $response.AddHeader("Content-Disposition", "attachment; filename=export.csv")
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                    
                    Write-AuditLog -Action "EXPORT_CSV" -User "N/A" -Details "$($users.Count) users exported" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $response.StatusCode = 500
                }
            }
        }
        
        # Route: API - Obtenir le journal d'audit
        elseif ($path -eq "/api/get-audit" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; log = ""; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    $logFile = Join-Path $PSScriptRoot "AD-WebManager-Audit.log"
                    
                    if (Test-Path $logFile) {
                        $result.log = Get-Content $logFile -Raw
                    } else {
                        $result.log = "Aucune entrée dans le journal."
                    }
                    
                    $result.success = $true
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json))
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        # Route: API - Effacer le journal d'audit
        elseif ($path -eq "/api/clear-audit" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    $logFile = Join-Path $PSScriptRoot "AD-WebManager-Audit.log"
                    
                    if (Test-Path $logFile) {
                        Remove-Item $logFile -Force
                    }
                    
                    $result.success = $true
                    $result.message = "Journal effacé"
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            $buffer = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json))
            $response.ContentType = "application/json"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        # Route inconnue
        else {
            $response.StatusCode = 404
            $html = "<h1>404 - Page non trouvée</h1>"
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
            $response.ContentType = "text/html"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        $response.Close()
    }
} catch {
    Write-Host "❌ Erreur: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    if ($listener.IsListening) {
        $listener.Stop()
    }
    $listener.Close()
    Write-Host ""
    Write-Host "🛑 Serveur arrêté." -ForegroundColor Yellow
}
