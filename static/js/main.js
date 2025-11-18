/**
 * JavaScript multi-plateforme pour l'interface Web AD
 * Fonctionne sur n'importe quel navigateur moderne, quel que soit le système d'exploitation
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialiser les formulaires de recherche
    initSearchForms();

    // Vérifier les informations système
    fetchSystemInfo();
});

/**
 * Initialiser les gestionnaires de formulaires de recherche
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
 * Gérer la soumission du formulaire de recherche
 */
async function handleSearchSubmit(event) {
    event.preventDefault();

    const form = event.target;
    const formData = new FormData(form);
    const resultsDiv = document.getElementById('results');

    // Afficher l'état de chargement
    resultsDiv.innerHTML = '<p>Recherche en cours...</p>';

    // Obtenir les identifiants de connexion depuis la session ou demander à l'utilisateur
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
 * Afficher les résultats de recherche
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
 * Obtenir les identifiants stockés (simplifié - en production, utiliser une session sécurisée)
 */
function getStoredCredentials() {
    // Dans une application de production, ceux-ci proviendraient d'une session sécurisée
    // Pour la démonstration, nous demandons à l'utilisateur
    const stored = sessionStorage.getItem('ad_credentials');

    if (stored) {
        return JSON.parse(stored);
    }

    // Demander les identifiants s'ils ne sont pas stockés
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
 * Récupérer et afficher les informations système
 */
async function fetchSystemInfo() {
    try {
        const response = await fetch('/api/system-info');
        const data = await response.json();
        console.log('Informations système:', data);
    } catch (error) {
        console.error('Échec de la récupération des informations système:', error);
    }
}

/**
 * Effacer les identifiants stockés
 */
function clearCredentials() {
    sessionStorage.removeItem('ad_credentials');
    alert('Identifiants effacés.');
}
