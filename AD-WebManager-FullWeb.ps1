#Requires -Version 5.1

<#
.SYNOPSIS
    Serveur web pour la gestion d'Active Directory - Version Full Web
.DESCRIPTION
    Interface web moderne avec encodage UTF-8 parfait
#>

Add-Type -AssemblyName System.Web

# Configuration
$Port = 8080
$Prefix = "http://localhost:$Port/"

# Variables de session
$script:adCredential = $null
$script:adDomain = $null
$script:sessionToken = $null

# Vérifier module AD
$adModuleAvailable = Get-Module -ListAvailable -Name ActiveDirectory
if ($adModuleAvailable) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
}

# Fonction de journalisation avec UTF-8
function Write-AuditLog {
    param([string]$Action, [string]$User, [string]$Details, [string]$PerformedBy)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp | $PerformedBy | $Action | User: $User | $Details"
    $logFile = Join-Path $PSScriptRoot "AD-WebManager-Audit.log"
    Add-Content -Path $logFile -Value $logEntry -Encoding UTF8
}

# Fonction de test connexion AD
function Test-ADConnection {
    param([string]$Domain, [string]$Username, [string]$Password)
    try {
        $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($Username, $securePassword)
        $null = Get-ADDomain -Server $Domain -Credential $credential -ErrorAction Stop
        return @{ Success = $true; Message = "Connexion réussie"; Credential = $credential }
    } catch {
        return @{ Success = $false; Message = $_.Exception.Message; Credential = $null }
    }
}

# Fonction token de session
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

# Fonction pour envoyer une réponse HTML avec UTF-8
function Send-HtmlResponse {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [string]$Html
    )
    $Response.ContentEncoding = [System.Text.Encoding]::UTF8
    $Response.ContentType = "text/html; charset=utf-8"
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($Html)
    $Response.ContentLength64 = $buffer.Length
    $Response.OutputStream.Write($buffer, 0, $buffer.Length)
}

# Fonction pour envoyer une réponse JSON avec UTF-8
function Send-JsonResponse {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [object]$Data
    )
    $json = $Data | ConvertTo-Json -Depth 10
    $Response.ContentEncoding = [System.Text.Encoding]::UTF8
    $Response.ContentType = "application/json; charset=utf-8"
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Response.ContentLength64 = $buffer.Length
    $Response.OutputStream.Write($buffer, 0, $buffer.Length)
}

# HTML - Page de connexion avec UTF-8 parfait
function Get-LoginPage {
    param([string]$ErrorMessage = "")
    
    $errorHtml = if ($ErrorMessage) {
        "<div class='alert alert-danger'>$ErrorMessage</div>"
    } else { "" }
    
    # Utiliser @" "@ avec UTF-8 BOM
    return @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion - AD Manager</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .login-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 460px;
            padding: 50px 40px;
            animation: slideIn 0.6s ease-out;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .logo {
            text-align: center;
            margin-bottom: 40px;
        }
        .logo h1 {
            color: #667eea;
            font-size: 36px;
            margin-bottom: 8px;
            font-weight: 700;
        }
        .logo p {
            color: #666;
            font-size: 15px;
            font-weight: 400;
        }
        .form-group {
            margin-bottom: 24px;
        }
        .form-group label {
            display: block;
            margin-bottom: 10px;
            color: #2d3748;
            font-weight: 600;
            font-size: 14px;
        }
        .form-group input {
            width: 100%;
            padding: 14px 16px;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            font-size: 15px;
            transition: all 0.3s ease;
            font-family: inherit;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.1);
        }
        .form-group input::placeholder {
            color: #a0aec0;
        }
        .btn-login {
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 10px;
            font-family: inherit;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
        }
        .btn-login:active {
            transform: translateY(0);
        }
        .alert {
            padding: 14px 16px;
            border-radius: 10px;
            margin-bottom: 24px;
            font-size: 14px;
        }
        .alert-danger {
            background-color: #fed7d7;
            color: #c53030;
            border-left: 4px solid #c53030;
        }
        .info-box {
            background-color: #e6fffa;
            padding: 18px;
            border-radius: 10px;
            margin-top: 24px;
            font-size: 13px;
            color: #234e52;
            border-left: 4px solid #38b2ac;
        }
        .info-box strong {
            display: block;
            margin-bottom: 10px;
            color: #1a365d;
        }
        .info-item {
            margin: 6px 0;
            padding-left: 8px;
        }
        .info-item::before {
            content: '• ';
            color: #38b2ac;
            font-weight: bold;
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
        
        <form method="POST" action="/login" accept-charset="UTF-8">
            <div class="form-group">
                <label for="domain">Nom de domaine ou serveur DC</label>
                <input type="text" id="domain" name="domain" placeholder="exemple: domain.local" required>
            </div>
            
            <div class="form-group">
                <label for="username">Compte administrateur</label>
                <input type="text" id="username" name="username" placeholder="exemple: admin@domain.local" required>
            </div>
            
            <div class="form-group">
                <label for="password">Mot de passe</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn-login">Se connecter</button>
        </form>
        
        <div class="info-box">
            <strong>ℹ️ Informations :</strong>
            <div class="info-item">Serveur sur le port $Port</div>
            <div class="info-item">Identifiants en mémoire uniquement</div>
            <div class="info-item">Actions enregistrées dans l'audit</div>
        </div>
    </div>
</body>
</html>
"@
}

# HTML - Page principale complète avec UTF-8 parfait
function Get-MainPage {
    param([string]$SessionToken)
    
    return @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Manager - Tableau de bord</title>
    <link rel="stylesheet" href="/static/style.css">
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
            <button class="tab active" onclick="showTab('create')">➕ Créer utilisateur</button>
            <button class="tab" onclick="showTab('list')">📋 Liste utilisateurs</button>
            <button class="tab" onclick="showTab('groups')">👥 Gestion groupes</button>
            <button class="tab" onclick="showTab('import')">📥 Import/Export</button>
        </div>
        
        <!-- ONGLET CRÉATION -->
        <div id="tab-create" class="tab-content active">
            <h2>➕ Créer un utilisateur</h2>
            
            <div class="alert alert-info" id="domain-info">
                <strong>📡 Domaine connecté :</strong> $($script:adDomain)<br>
                <strong>📂 OUs disponibles :</strong> <span id="ou-count">Chargement...</span>
            </div>
            
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
                        <input type="text" name="samAccount" id="samAccount" required>
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
                    <label>OU (Unité d'organisation) *</label>
                    <input type="text" id="ou-search" placeholder="🔍 Rechercher une OU..." style="margin-bottom: 10px;">
                    <select name="ou" id="ou" required size="5" style="height: 150px; overflow-y: auto;">
                        <option value="">Chargement des OUs...</option>
                    </select>
                </div>
                
                <div class="btn-group">
                    <button type="submit" class="btn btn-primary">Créer l'utilisateur</button>
                    <button type="reset" class="btn btn-secondary">Effacer</button>
                </div>
            </form>
            
            <div id="create-status" class="status-box hidden"></div>
        </div>
        
        <!-- ONGLET LISTE -->
        <div id="tab-list" class="tab-content">
            <h2>📋 Liste des utilisateurs</h2>
            
            <div class="search-box">
                <input type="text" id="search-input" placeholder="Rechercher par nom ou login...">
                <button class="btn btn-primary" onclick="searchUsers()">🔍 Rechercher</button>
                <button class="btn btn-secondary" onclick="loadAllUsers()">📋 Tous les utilisateurs</button>
            </div>
            
            <div id="users-list"></div>
        </div>
        
        <!-- ONGLET GROUPES -->
        <div id="tab-groups" class="tab-content">
            <h2>👥 Gestion des groupes</h2>
            
            <div class="alert alert-info">
                Sélectionnez un utilisateur dans la liste pour gérer ses groupes
            </div>
            
            <div class="search-box">
                <input type="text" id="group-user-input" placeholder="Login de l'utilisateur...">
                <button class="btn btn-primary" onclick="loadUserGroups()">Charger les groupes</button>
            </div>
            
            <div id="groups-container" class="hidden">
                <div class="form-row">
                    <div>
                        <h3>Groupes actuels</h3>
                        <div class="list-box" id="current-groups"></div>
                        <button class="btn btn-danger" onclick="removeFromGroups()">Retirer des groupes sélectionnés</button>
                    </div>
                    
                    <div>
                        <h3>Groupes disponibles</h3>
                        <input type="text" id="search-groups-input" placeholder="Rechercher..." style="width: 100%; margin-bottom: 10px;">
                        <button class="btn btn-secondary" onclick="searchGroups()" style="width: 100%; margin-bottom: 10px;">Rechercher</button>
                        <div class="list-box" id="available-groups"></div>
                        <button class="btn btn-success" onclick="addToGroups()">Ajouter aux groupes sélectionnés</button>
                    </div>
                </div>
            </div>
            
            <div id="groups-status" class="status-box hidden"></div>
        </div>
        
        <!-- ONGLET IMPORT/EXPORT -->
        <div id="tab-import" class="tab-content">
            <h2>📥 Import / Export</h2>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px;">
                <div>
                    <h3>📤 Export</h3>
                    <div class="form-group">
                        <label>Type d'export</label>
                        <select id="export-type">
                            <option value="all">Tous les utilisateurs</option>
                            <option value="enabled">Utilisateurs actifs</option>
                            <option value="disabled">Utilisateurs désactivés</option>
                        </select>
                    </div>
                    
                    <div class="btn-group">
                        <button class="btn btn-primary" onclick="exportCSV()">📥 Exporter CSV</button>
                    </div>
                </div>
                
                <div>
                    <h3>📥 Import</h3>
                    <div class="alert alert-info">
                        Format CSV requis: PreNom,Nom,Login,Email,Departement,OU
                    </div>
                    <input type="file" id="import-file" accept=".csv" style="margin-bottom: 10px;">
                    <button class="btn btn-success" onclick="importCSV()">📤 Importer CSV</button>
                </div>
            </div>
            
            <div id="import-status" class="status-box hidden"></div>
        </div>
    </div>
    
    <!-- Modal de modification -->
    <div id="edit-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>✏️ Modifier l'utilisateur</h3>
                <button class="close-modal" onclick="closeEditModal()">×</button>
            </div>
            
            <form id="form-edit" onsubmit="updateUser(event)">
                <input type="hidden" id="edit-samAccount">
                
                <div class="form-row">
                    <div class="form-group">
                        <label>Prénom</label>
                        <input type="text" id="edit-firstName">
                    </div>
                    <div class="form-group">
                        <label>Nom</label>
                        <input type="text" id="edit-lastName">
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" id="edit-email">
                    </div>
                    <div class="form-group">
                        <label>Département</label>
                        <input type="text" id="edit-department">
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Description</label>
                    <input type="text" id="edit-description">
                </div>
                
                <div class="btn-group">
                    <button type="submit" class="btn btn-primary">💾 Enregistrer</button>
                    <button type="button" class="btn btn-warning" onclick="resetPassword()">🔑 Réinitialiser mot de passe</button>
                    <button type="button" class="btn btn-danger" onclick="disableUser()">🚫 Désactiver</button>
                    <button type="button" class="btn btn-secondary" onclick="closeEditModal()">Annuler</button>
                </div>
            </form>
        </div>
    </div>
    
    <script src="/static/app.js"></script>
    <script>
        // Initialiser avec le token de session
        const sessionToken = '$SessionToken';
    </script>
</body>
</html>
"@
}

# CSS externe
function Get-StyleCSS {
    return @"
* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: #f5f7fa;
}

.navbar {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 18px 30px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.navbar h1 { font-size: 24px; font-weight: 700; }
.navbar-info { display: flex; align-items: center; gap: 20px; }

.btn-logout {
    background: rgba(255,255,255,0.2);
    color: white;
    padding: 10px 24px;
    border: 1px solid rgba(255,255,255,0.3);
    border-radius: 8px;
    cursor: pointer;
    text-decoration: none;
    transition: all 0.3s;
    font-weight: 600;
}

.btn-logout:hover { background: rgba(255,255,255,0.3); }

.container { max-width: 1400px; margin: 30px auto; padding: 0 20px; }

.tabs {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
    border-bottom: 2px solid #e0e0e0;
    overflow-x: auto;
}

.tab {
    padding: 14px 28px;
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

.tab:hover { color: #667eea; }

.tab.active {
    color: #667eea;
    border-bottom-color: #667eea;
}

.tab-content {
    display: none;
    background: white;
    border-radius: 12px;
    padding: 35px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
    animation: fadeIn 0.3s ease;
}

.tab-content.active { display: block; }

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.form-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-bottom: 20px;
}

.form-group { margin-bottom: 20px; }

.form-group label {
    display: block;
    margin-bottom: 10px;
    color: #2d3748;
    font-weight: 600;
    font-size: 14px;
}

.form-group input,
.form-group select,
.form-group textarea {
    width: 100%;
    padding: 12px 14px;
    border: 2px solid #e2e8f0;
    border-radius: 8px;
    font-size: 14px;
    transition: border-color 0.3s;
    background-color: white;
    font-family: inherit;
}

.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.form-group select {
    cursor: pointer;
}

.form-group select:not([size]) {
    appearance: none;
    background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e");
    background-repeat: no-repeat;
    background-position: right 12px center;
    background-size: 20px;
    padding-right: 40px;
}

.form-group select[size] {
    height: auto;
    padding: 8px;
}

.form-group select option {
    padding: 10px;
    cursor: pointer;
}

.btn-group {
    display: flex;
    gap: 12px;
    margin-top: 24px;
    flex-wrap: wrap;
}

.btn {
    padding: 12px 28px;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    font-family: inherit;
}

.btn-primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
}

.btn-secondary { background: #e2e8f0; color: #2d3748; }
.btn-secondary:hover { background: #cbd5e0; }
.btn-success { background: #48bb78; color: white; }
.btn-success:hover { background: #38a169; }
.btn-danger { background: #f56565; color: white; }
.btn-danger:hover { background: #e53e3e; }
.btn-warning { background: #ed8936; color: white; }
.btn-warning:hover { background: #dd6b20; }

.status-box {
    margin-top: 24px;
    padding: 16px;
    border-radius: 8px;
    background: #f7fafc;
    border-left: 4px solid #667eea;
    font-family: 'Courier New', monospace;
    font-size: 13px;
    min-height: 60px;
    max-height: 400px;
    overflow-y: auto;
}

.hidden { display: none !important; }

h2 {
    color: #2d3748;
    margin-bottom: 24px;
    font-size: 26px;
    font-weight: 700;
}

h3 {
    color: #2d3748;
    font-size: 18px;
    font-weight: 600;
    margin-bottom: 12px;
}

.search-box {
    display: flex;
    gap: 12px;
    margin-bottom: 24px;
}

.search-box input { flex: 1; }

.results-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 24px;
}

.results-table th {
    background: #667eea;
    color: white;
    padding: 14px;
    text-align: left;
    font-weight: 600;
}

.results-table td {
    padding: 14px;
    border-bottom: 1px solid #e2e8f0;
}

.results-table tr:hover { background: #f7fafc; }

.badge {
    display: inline-block;
    padding: 5px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
}

.badge-success {
    background: #c6f6d5;
    color: #22543d;
}

.badge-danger {
    background: #fed7d7;
    color: #742a2a;
}

.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0,0,0,0.5);
    animation: fadeIn 0.3s;
}

.modal.active {
    display: flex;
    justify-content: center;
    align-items: center;
}

.modal-content {
    background: white;
    padding: 35px;
    border-radius: 12px;
    max-width: 650px;
    width: 90%;
    max-height: 85vh;
    overflow-y: auto;
    animation: slideIn 0.3s;
}

@keyframes slideIn {
    from { transform: translateY(-50px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
}

.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
}

.modal-header h3 { margin: 0; color: #2d3748; }

.close-modal {
    background: none;
    border: none;
    font-size: 28px;
    cursor: pointer;
    color: #a0aec0;
    transition: color 0.2s;
}

.close-modal:hover { color: #2d3748; }

.list-box {
    border: 2px solid #e2e8f0;
    border-radius: 8px;
    padding: 12px;
    min-height: 200px;
    max-height: 320px;
    overflow-y: auto;
    margin-bottom: 12px;
}

.list-item {
    padding: 10px 12px;
    background: #f7fafc;
    margin-bottom: 6px;
    border-radius: 6px;
    cursor: pointer;
    transition: background 0.2s;
}

.list-item:hover { background: #edf2f7; }
.list-item.selected { background: #667eea; color: white; }

.alert {
    padding: 16px 18px;
    border-radius: 8px;
    margin-bottom: 24px;
    font-size: 14px;
}

.alert-info {
    background: #e6fffa;
    color: #234e52;
    border-left: 4px solid #38b2ac;
}

.alert strong {
    font-weight: 600;
}
"@
}

# JavaScript externe
function Get-AppJS {
    return @"
let currentUser = null;
let selectedCurrentGroups = [];
let selectedAvailableGroups = [];
let allOUs = [];

// Charger les OUs au démarrage
window.addEventListener('DOMContentLoaded', function() {
    loadOUs();
    
    const ouSearch = document.getElementById('ou-search');
    if (ouSearch) {
        ouSearch.addEventListener('input', function() {
            filterOUs(this.value);
        });
    }
});

function filterOUs(searchTerm) {
    const selectOU = document.getElementById('ou');
    const term = searchTerm.toLowerCase();
    
    selectOU.innerHTML = '';
    
    const filteredOUs = allOUs.filter(ou => ou.toLowerCase().includes(term));
    
    if (filteredOUs.length === 0) {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = 'Aucune OU trouvée';
        selectOU.appendChild(option);
    } else {
        filteredOUs.forEach(ou => {
            const option = document.createElement('option');
            option.value = ou;
            option.textContent = ou;
            selectOU.appendChild(option);
        });
    }
}

async function loadOUs() {
    try {
        const response = await fetch('/api/get-ous', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: JSON.stringify({ sessionToken })
        });
        
        const result = await response.json();
        
        if (result.success) {
            allOUs = result.ous;
            const selectOU = document.getElementById('ou');
            selectOU.innerHTML = '';
            
            result.ous.forEach(ou => {
                const option = document.createElement('option');
                option.value = ou;
                option.textContent = ou;
                selectOU.appendChild(option);
            });
            
            const countSpan = document.getElementById('ou-count');
            if (countSpan) {
                countSpan.textContent = result.ous.length + ' OU(s) disponible(s)';
            }
        }
    } catch (error) {
        console.error('Erreur:', error);
    }
}

function showTab(tabName) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById('tab-' + tabName).classList.add('active');
    
    if (tabName === 'list') {
        loadAllUsers();
    }
}

async function createUser(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const data = Object.fromEntries(formData);
    data.sessionToken = sessionToken;
    
    const statusDiv = document.getElementById('create-status');
    statusDiv.classList.remove('hidden');
    statusDiv.innerHTML = 'Création en cours...';
    
    try {
        const response = await fetch('/api/create-user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        if (result.success) {
            statusDiv.innerHTML = '✓ ' + result.message;
            statusDiv.style.background = '#c6f6d5';
            statusDiv.style.borderColor = '#48bb78';
            event.target.reset();
        } else {
            statusDiv.innerHTML = '✗ ' + result.message;
            statusDiv.style.background = '#fed7d7';
            statusDiv.style.borderColor = '#f56565';
        }
    } catch (error) {
        statusDiv.innerHTML = '✗ Erreur: ' + error.message;
        statusDiv.style.background = '#fed7d7';
        statusDiv.style.borderColor = '#f56565';
    }
}

async function loadAllUsers() {
    document.getElementById('users-list').innerHTML = '<p>Chargement...</p>';
    
    try {
        const response = await fetch('/api/list-users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: JSON.stringify({ sessionToken })
        });
        
        const result = await response.json();
        displayUsers(result.users);
    } catch (error) {
        document.getElementById('users-list').innerHTML = '<p style="color: red;">Erreur: ' + error.message + '</p>';
    }
}

async function searchUsers() {
    const query = document.getElementById('search-input').value.trim();
    if (!query) {
        loadAllUsers();
        return;
    }
    
    document.getElementById('users-list').innerHTML = '<p>Recherche...</p>';
    
    try {
        const response = await fetch('/api/search-users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: JSON.stringify({ sessionToken, query })
        });
        
        const result = await response.json();
        displayUsers(result.users);
    } catch (error) {
        document.getElementById('users-list').innerHTML = '<p style="color: red;">Erreur: ' + error.message + '</p>';
    }
}

function displayUsers(users) {
    if (!users || users.length === 0) {
        document.getElementById('users-list').innerHTML = '<p>Aucun utilisateur trouvé.</p>';
        return;
    }
    
    let html = '<table class=\"results-table\"><thead><tr>';
    html += '<th>Login</th><th>Nom complet</th><th>Email</th><th>Département</th><th>Statut</th><th>Actions</th>';
    html += '</tr></thead><tbody>';
    
    users.forEach(user => {
        const statusBadge = user.enabled ? 
            '<span class=\"badge badge-success\">Actif</span>' : 
            '<span class=\"badge badge-danger\">Désactivé</span>';
        
        html += '<tr>';
        html += '<td>' + user.samAccountName + '</td>';
        html += '<td>' + user.name + '</td>';
        html += '<td>' + (user.email || '-') + '</td>';
        html += '<td>' + (user.department || '-') + '</td>';
        html += '<td>' + statusBadge + '</td>';
        html += '<td>';
        html += '<button class=\"btn btn-primary\" style=\"padding: 8px 16px; margin-right: 5px; font-size: 13px;\" onclick=\"openEditModal(\'' + user.samAccountName + '\')\">✏️ Modifier</button>';
        html += '<button class=\"btn btn-success\" style=\"padding: 8px 16px; font-size: 13px;\" onclick=\"openGroupsForUser(\'' + user.samAccountName + '\')\">👥 Groupes</button>';
        html += '</td>';
        html += '</tr>';
    });
    
    html += '</tbody></table>';
    document.getElementById('users-list').innerHTML = html;
}

async function openEditModal(samAccount) {
    try {
        const response = await fetch('/api/get-user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: JSON.stringify({ sessionToken, samAccount })
        });
        
        const result = await response.json();
        
        if (result.success) {
            currentUser = result.user;
            document.getElementById('edit-samAccount').value = result.user.samAccountName;
            document.getElementById('edit-firstName').value = result.user.givenName || '';
            document.getElementById('edit-lastName').value = result.user.surname || '';
            document.getElementById('edit-email').value = result.user.email || '';
            document.getElementById('edit-department').value = result.user.department || '';
            document.getElementById('edit-description').value = result.user.description || '';
            
            document.getElementById('edit-modal').classList.add('active');
        }
    } catch (error) {
        alert('Erreur: ' + error.message);
    }
}

function closeEditModal() {
    document.getElementById('edit-modal').classList.remove('active');
}

async function updateUser(event) {
    event.preventDefault();
    
    const data = {
        sessionToken,
        samAccount: document.getElementById('edit-samAccount').value,
        firstName: document.getElementById('edit-firstName').value,
        lastName: document.getElementById('edit-lastName').value,
        email: document.getElementById('edit-email').value,
        department: document.getElementById('edit-department').value,
        description: document.getElementById('edit-description').value
    };
    
    try {
        const response = await fetch('/api/update-user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        if (result.success) {
            alert('✓ ' + result.message);
            closeEditModal();
            loadAllUsers();
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
    
    try {
        const response = await fetch('/api/reset-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: JSON.stringify({
                sessionToken,
                samAccount: currentUser.samAccountName,
                newPassword
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
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: JSON.stringify({
                sessionToken,
                samAccount: currentUser.samAccountName
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            alert('✓ ' + result.message);
            closeEditModal();
            loadAllUsers();
        } else {
            alert('✗ ' + result.message);
        }
    } catch (error) {
        alert('Erreur: ' + error.message);
    }
}

function openGroupsForUser(samAccount) {
    document.getElementById('group-user-input').value = samAccount;
    const tabBtn = Array.from(document.querySelectorAll('.tab')).find(t => t.textContent.includes('Gestion groupes'));
    if (tabBtn) {
        tabBtn.click();
        setTimeout(() => loadUserGroups(), 100);
    }
}

async function loadUserGroups() {
    const username = document.getElementById('group-user-input').value.trim();
    if (!username) return;
    
    try {
        const response = await fetch('/api/get-user-groups', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: JSON.stringify({ sessionToken, username })
        });
        
        const result = await response.json();
        
        if (result.success) {
            let html = '';
            result.groups.forEach(group => {
                html += '<div class=\"list-item\" onclick=\"toggleGroupSelection(this, \'current\')\">' + group + '</div>';
            });
            
            document.getElementById('current-groups').innerHTML = html || '<p>Aucun groupe</p>';
            document.getElementById('groups-container').classList.remove('hidden');
            
            const statusDiv = document.getElementById('groups-status');
            statusDiv.classList.remove('hidden');
            statusDiv.innerHTML = '✓ ' + result.groups.length + ' groupe(s) chargé(s)';
            statusDiv.style.background = '#c6f6d5';
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
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: JSON.stringify({ sessionToken, query })
        });
        
        const result = await response.json();
        
        if (result.success) {
            let html = '';
            result.groups.forEach(group => {
                html += '<div class=\"list-item\" onclick=\"toggleGroupSelection(this, \'available\')\">' + group + '</div>';
            });
            
            document.getElementById('available-groups').innerHTML = html || '<p>Aucun groupe trouvé</p>';
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
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
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
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
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
    const statusDiv = document.getElementById('import-status');
    statusDiv.classList.remove('hidden');
    statusDiv.innerHTML = 'Export en cours...';
    
    try {
        const response = await fetch('/api/export-csv', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: JSON.stringify({
                sessionToken,
                type: document.getElementById('export-type').value
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
            
            statusDiv.innerHTML = '✓ Export réussi!';
            statusDiv.style.background = '#c6f6d5';
        } else {
            statusDiv.innerHTML = '✗ Erreur lors de l\'export';
            statusDiv.style.background = '#fed7d7';
        }
    } catch (error) {
        statusDiv.innerHTML = '✗ Erreur: ' + error.message;
        statusDiv.style.background = '#fed7d7';
    }
}

async function importCSV() {
    const fileInput = document.getElementById('import-file');
    if (!fileInput.files.length) {
        alert('Veuillez sélectionner un fichier CSV');
        return;
    }
    
    const file = fileInput.files[0];
    const reader = new FileReader();
    
    reader.onload = async function(e) {
        const csvContent = e.target.result;
        
        const statusDiv = document.getElementById('import-status');
        statusDiv.classList.remove('hidden');
        statusDiv.innerHTML = 'Import en cours...';
        
        try {
            const response = await fetch('/api/import-csv', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json; charset=utf-8' },
                body: JSON.stringify({
                    sessionToken,
                    csvData: csvContent
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                statusDiv.innerHTML = '✓ ' + result.message;
                statusDiv.style.background = '#c6f6d5';
            } else {
                statusDiv.innerHTML = '✗ ' + result.message;
                statusDiv.style.background = '#fed7d7';
            }
        } catch (error) {
            statusDiv.innerHTML = '✗ Erreur: ' + error.message;
            statusDiv.style.background = '#fed7d7';
        }
    };
    
    reader.readAsText(file);
}
"@
}

# Démarrage du serveur
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  🔐 AD Web Manager - Version Full Web" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (-not $adModuleAvailable) {
    Write-Host "⚠️  ATTENTION: Module ActiveDirectory non installé." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "🚀 Démarrage du serveur web..." -ForegroundColor Green
Write-Host "📍 URL: $Prefix" -ForegroundColor Green
Write-Host "🛑 Pour arrêter: Ctrl+C" -ForegroundColor Yellow
Write-Host ""

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($Prefix)

try {
    $listener.Start()
    Write-Host "✅ Serveur démarré!" -ForegroundColor Green
    Write-Host "🌐 Ouvrez: $Prefix" -ForegroundColor Cyan
    Write-Host ""
    
    Start-Process $Prefix
    
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $path = $request.Url.LocalPath
        $method = $request.HttpMethod
        
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - $method $path" -ForegroundColor Gray
        
        # Routes statiques
        if ($path -eq "/static/style.css") {
            $css = Get-StyleCSS
            Send-HtmlResponse -Response $response -Html $css
        }
        elseif ($path -eq "/static/app.js") {
            $js = Get-AppJS
            $response.ContentEncoding = [System.Text.Encoding]::UTF8
            $response.ContentType = "application/javascript; charset=utf-8"
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($js)
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        # Route: Login page
        elseif ($path -eq "/" -and $method -eq "GET") {
            $html = Get-LoginPage
            Send-HtmlResponse -Response $response -Html $html
        }
        # Route: Login POST
        elseif ($path -eq "/login" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
            $body = $reader.ReadToEnd()
            $reader.Close()
            
            $params = @{}
            $body -split "&" | ForEach-Object {
                $pair = $_ -split "="
                if ($pair.Length -eq 2) {
                    $params[$pair[0]] = [System.Web.HttpUtility]::UrlDecode($pair[1])
                }
            }
            
            $testResult = Test-ADConnection -Domain $params['domain'] -Username $params['username'] -Password $params['password']
            
            if ($testResult.Success) {
                $script:adCredential = $testResult.Credential
                $script:adDomain = $params['domain']
                $script:sessionToken = New-SessionToken
                
                Write-Host "✅ Connexion OK: $($params['username'])" -ForegroundColor Green
                
                $html = Get-MainPage -SessionToken $script:sessionToken
                Send-HtmlResponse -Response $response -Html $html
            } else {
                Write-Host "❌ Connexion échouée" -ForegroundColor Red
                $html = Get-LoginPage -ErrorMessage "Échec: $($testResult.Message)"
                Send-HtmlResponse -Response $response -Html $html
            }
        }
        # Route: Logout
        elseif ($path -eq "/logout") {
            $script:adCredential = $null
            $script:adDomain = $null
            $script:sessionToken = $null
            $response.Redirect($Prefix)
        }
        # API: Get OUs
        elseif ($path -eq "/api/get-ous" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; ous = @(); message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    $ous = Get-ADOrganizationalUnit -Filter * -Server $script:adDomain -Credential $script:adCredential | 
                        Select-Object -ExpandProperty DistinguishedName | 
                        Sort-Object
                    
                    $result.success = $true
                    $result.ous = $ous
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            Send-JsonResponse -Response $response -Data $result
        }
        # API: Create User
        elseif ($path -eq "/api/create-user" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
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
                        Enabled = $true
                        Server = $script:adDomain
                        Credential = $script:adCredential
                    }
                    
                    if ($json.email) { $params.Add('EmailAddress', $json.email) }
                    if ($json.department) { $params.Add('Department', $json.department) }
                    
                    New-ADUser @params
                    
                    $result.success = $true
                    $result.message = "Utilisateur '$displayName' créé avec succès"
                    
                    Write-AuditLog -Action "CREATE_USER" -User $json.samAccount -Details "Name: $displayName" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            Send-JsonResponse -Response $response -Data $result
        }
        # API: List all users
        elseif ($path -eq "/api/list-users" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; users = @(); message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    $users = Get-ADUser -Filter * -Properties EmailAddress, Enabled, Department -Server $script:adDomain -Credential $script:adCredential | Select-Object -First 100
                    
                    $result.success = $true
                    $result.users = $users | ForEach-Object {
                        @{
                            samAccountName = $_.SamAccountName
                            name = $_.Name
                            email = $_.EmailAddress
                            department = $_.Department
                            enabled = $_.Enabled
                        }
                    }
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            Send-JsonResponse -Response $response -Data $result
        }
        # API: Search users
        elseif ($path -eq "/api/search-users" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
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
                    $users = Get-ADUser -Filter "SamAccountName -like '$searchTerm' -or Name -like '$searchTerm'" -Properties EmailAddress, Enabled, Department -Server $script:adDomain -Credential $script:adCredential
                    
                    $result.success = $true
                    $result.users = $users | ForEach-Object {
                        @{
                            samAccountName = $_.SamAccountName
                            name = $_.Name
                            email = $_.EmailAddress
                            department = $_.Department
                            enabled = $_.Enabled
                        }
                    }
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            Send-JsonResponse -Response $response -Data $result
        }
        # API: Get user details
        elseif ($path -eq "/api/get-user" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; user = $null; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    $user = Get-ADUser -Identity $json.samAccount -Properties * -Server $script:adDomain -Credential $script:adCredential
                    
                    $result.success = $true
                    $result.user = @{
                        samAccountName = $user.SamAccountName
                        givenName = $user.GivenName
                        surname = $user.Surname
                        email = $user.EmailAddress
                        department = $user.Department
                        description = $user.Description
                        enabled = $user.Enabled
                    }
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            Send-JsonResponse -Response $response -Data $result
        }
        # API: Update user
        elseif ($path -eq "/api/update-user" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    Set-ADUser -Identity $json.samAccount -GivenName $json.firstName -Surname $json.lastName -EmailAddress $json.email -Department $json.department -Description $json.description -Server $script:adDomain -Credential $script:adCredential
                    
                    $result.success = $true
                    $result.message = "Utilisateur mis à jour avec succès"
                    
                    Write-AuditLog -Action "UPDATE_USER" -User $json.samAccount -Details "Modified" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            Send-JsonResponse -Response $response -Data $result
        }
        # API: Reset password
        elseif ($path -eq "/api/reset-password" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    Set-ADAccountPassword -Identity $json.samAccount -Reset -NewPassword (ConvertTo-SecureString $json.newPassword -AsPlainText -Force) -Server $script:adDomain -Credential $script:adCredential
                    
                    $result.success = $true
                    $result.message = "Mot de passe réinitialisé"
                    
                    Write-AuditLog -Action "RESET_PASSWORD" -User $json.samAccount -Details "Password reset" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            Send-JsonResponse -Response $response -Data $result
        }
        # API: Disable user
        elseif ($path -eq "/api/disable-user" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    Disable-ADAccount -Identity $json.samAccount -Server $script:adDomain -Credential $script:adCredential
                    
                    $result.success = $true
                    $result.message = "Compte désactivé"
                    
                    Write-AuditLog -Action "DISABLE_ACCOUNT" -User $json.samAccount -Details "Account disabled" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            Send-JsonResponse -Response $response -Data $result
        }
        # API: Get user groups
        elseif ($path -eq "/api/get-user-groups" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; groups = @(); message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    $groups = Get-ADPrincipalGroupMembership -Identity $json.username -Server $script:adDomain -Credential $script:adCredential | Select-Object -ExpandProperty Name | Sort-Object
                    
                    $result.success = $true
                    $result.groups = $groups
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            Send-JsonResponse -Response $response -Data $result
        }
        # API: Search groups
        elseif ($path -eq "/api/search-groups" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
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
                    $groups = Get-ADGroup -Filter "Name -like '$searchTerm'" -Server $script:adDomain -Credential $script:adCredential | Select-Object -ExpandProperty Name | Sort-Object
                    
                    $result.success = $true
                    $result.groups = $groups
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            Send-JsonResponse -Response $response -Data $result
        }
        # API: Add to groups
        elseif ($path -eq "/api/add-to-groups" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
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
                            Add-ADGroupMember -Identity $group -Members $json.username -Server $script:adDomain -Credential $script:adCredential
                            $successCount++
                        } catch { }
                    }
                    
                    $result.success = $true
                    $result.message = "$successCount groupe(s) ajouté(s)"
                    
                    Write-AuditLog -Action "ADD_TO_GROUPS" -User $json.username -Details "$successCount groups" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            Send-JsonResponse -Response $response -Data $result
        }
        # API: Remove from groups
        elseif ($path -eq "/api/remove-from-groups" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
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
                            Remove-ADGroupMember -Identity $group -Members $json.username -Confirm:$false -Server $script:adDomain -Credential $script:adCredential
                            $successCount++
                        } catch { }
                    }
                    
                    $result.success = $true
                    $result.message = "$successCount groupe(s) retiré(s)"
                    
                    Write-AuditLog -Action "REMOVE_FROM_GROUPS" -User $json.username -Details "$successCount groups" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            Send-JsonResponse -Response $response -Data $result
        }
        # API: Export CSV
        elseif ($path -eq "/api/export-csv" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
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
                    
                    $users = Get-ADUser -Filter $filter -Properties EmailAddress, Enabled, Department -Server $script:adDomain -Credential $script:adCredential
                    
                    $csv = $users | Select-Object SamAccountName, Name, EmailAddress, Enabled, Department | ConvertTo-Csv -NoTypeInformation | Out-String
                    
                    $response.ContentEncoding = [System.Text.Encoding]::UTF8
                    $response.ContentType = "text/csv; charset=utf-8"
                    $response.AddHeader("Content-Disposition", "attachment; filename=export.csv")
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($csv)
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                    
                    Write-AuditLog -Action "EXPORT_CSV" -User "N/A" -Details "$($users.Count) users" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $response.StatusCode = 500
                }
            }
        }
        # API: Import CSV
        elseif ($path -eq "/api/import-csv" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
            $json = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $result = @{ success = $false; message = "" }
            
            if ($json.sessionToken -ne $script:sessionToken) {
                $result.message = "Session invalide"
            } else {
                try {
                    $csvData = $json.csvData | ConvertFrom-Csv
                    $successCount = 0
                    $errorCount = 0
                    
                    foreach ($row in $csvData) {
                        try {
                            $displayName = "$($row.PreNom) $($row.Nom)"
                            
                            $params = @{
                                GivenName = $row.PreNom
                                Surname = $row.Nom
                                Name = $displayName
                                DisplayName = $displayName
                                SamAccountName = $row.Login
                                UserPrincipalName = "$($row.Login)@$script:adDomain"
                                Path = $row.OU
                                AccountPassword = (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force)
                                Enabled = $true
                                Server = $script:adDomain
                                Credential = $script:adCredential
                            }
                            
                            if ($row.Email) { $params.Add('EmailAddress', $row.Email) }
                            if ($row.Departement) { $params.Add('Department', $row.Departement) }
                            
                            New-ADUser @params
                            $successCount++
                        } catch {
                            $errorCount++
                        }
                    }
                    
                    $result.success = $true
                    $result.message = "$successCount utilisateur(s) importé(s), $errorCount erreur(s)"
                    
                    Write-AuditLog -Action "IMPORT_CSV" -User "N/A" -Details "$successCount users" -PerformedBy $script:adCredential.UserName
                    
                } catch {
                    $result.message = $_.Exception.Message
                }
            }
            
            Send-JsonResponse -Response $response -Data $result
        }
        # Route: 404
        else {
            $response.StatusCode = 404
            $html = "<!DOCTYPE html><html><head><meta charset='UTF-8'></head><body><h1>404 - Page non trouvée</h1></body></html>"
            Send-HtmlResponse -Response $response -Html $html
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
