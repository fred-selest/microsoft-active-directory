/**
 * Cross-platform JavaScript for AD Web Interface
 * Works on any modern browser regardless of OS
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize search forms
    initSearchForms();

    // Check system info
    fetchSystemInfo();
});

/**
 * Initialize search form handlers
 */
function initSearchForms() {
    const forms = [
        'search-users-form',
        'search-groups-form',
        'search-computers-form'
    ];

    forms.forEach(formId => {
        const form = document.getElementById(formId);
        if (form) {
            form.addEventListener('submit', handleSearchSubmit);
        }
    });
}

/**
 * Handle search form submission
 */
async function handleSearchSubmit(event) {
    event.preventDefault();

    const form = event.target;
    const formData = new FormData(form);
    const resultsDiv = document.getElementById('results');

    // Show loading state
    resultsDiv.innerHTML = '<p>Recherche en cours...</p>';

    // Get connection credentials from session or prompt
    const credentials = getStoredCredentials();

    if (!credentials) {
        resultsDiv.innerHTML = '<p style="color: red;">Veuillez d\'abord vous connecter à Active Directory.</p>';
        return;
    }

    const searchData = {
        server: credentials.server,
        username: credentials.username,
        password: credentials.password,
        base_dn: formData.get('base_dn'),
        filter: formData.get('filter'),
        attributes: ['cn', 'distinguishedName', 'description', 'mail', 'memberOf']
    };

    try {
        const response = await fetch('/api/search', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(searchData)
        });

        const data = await response.json();

        if (data.success) {
            displayResults(data.results);
        } else {
            resultsDiv.innerHTML = `<p style="color: red;">Erreur: ${data.error}</p>`;
        }
    } catch (error) {
        resultsDiv.innerHTML = `<p style="color: red;">Erreur de connexion: ${error.message}</p>`;
    }
}

/**
 * Display search results
 */
function displayResults(results) {
    const resultsDiv = document.getElementById('results');

    if (results.length === 0) {
        resultsDiv.innerHTML = '<p>Aucun résultat trouvé.</p>';
        return;
    }

    let html = `<p><strong>${results.length} résultat(s) trouvé(s)</strong></p>`;
    html += '<pre>';

    results.forEach((result, index) => {
        html += `--- Résultat ${index + 1} ---\n`;
        html += JSON.stringify(JSON.parse(result), null, 2);
        html += '\n\n';
    });

    html += '</pre>';
    resultsDiv.innerHTML = html;
}

/**
 * Get stored credentials (simplified - in production, use secure session)
 */
function getStoredCredentials() {
    // In a production app, these would come from a secure session
    // For demo purposes, we'll prompt the user
    const stored = sessionStorage.getItem('ad_credentials');

    if (stored) {
        return JSON.parse(stored);
    }

    // Prompt for credentials if not stored
    const server = prompt('Serveur AD:');
    const username = prompt('Nom d\'utilisateur:');
    const password = prompt('Mot de passe:');

    if (server && username && password) {
        const credentials = { server, username, password };
        sessionStorage.setItem('ad_credentials', JSON.stringify(credentials));
        return credentials;
    }

    return null;
}

/**
 * Fetch and display system information
 */
async function fetchSystemInfo() {
    try {
        const response = await fetch('/api/system-info');
        const data = await response.json();
        console.log('System Info:', data);
    } catch (error) {
        console.error('Failed to fetch system info:', error);
    }
}

/**
 * Clear stored credentials
 */
function clearCredentials() {
    sessionStorage.removeItem('ad_credentials');
    alert('Identifiants effacés.');
}
