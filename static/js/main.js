/**
 * JavaScript multi-plateforme pour l'interface Web AD
 * Fonctionne sur n'importe quel navigateur moderne, quel que soit le système d'exploitation
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialiser les formulaires de recherche
    initSearchForms();

    // Vérifier les informations système
    fetchSystemInfo();

    // Initialiser les tableaux triables
    initSortableTables();

    // Initialiser les raccourcis clavier
    initKeyboardShortcuts();
});

/**
 * Initialiser le tri des tableaux
 */
function initSortableTables() {
    document.querySelectorAll('.data-table.sortable thead th').forEach(th => {
        th.style.cursor = 'pointer';
        th.addEventListener('click', function() {
            const table = this.closest('table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const index = Array.from(this.parentNode.children).indexOf(this);
            const isAsc = this.classList.contains('sort-asc');

            // Retirer les classes de tri des autres colonnes
            table.querySelectorAll('th').forEach(h => {
                h.classList.remove('sort-asc', 'sort-desc');
            });

            // Trier les lignes
            rows.sort((a, b) => {
                const aVal = a.children[index]?.textContent.trim() || '';
                const bVal = b.children[index]?.textContent.trim() || '';

                // Detecter si c'est un nombre
                const aNum = parseFloat(aVal);
                const bNum = parseFloat(bVal);

                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return isAsc ? bNum - aNum : aNum - bNum;
                }

                return isAsc
                    ? bVal.localeCompare(aVal, 'fr')
                    : aVal.localeCompare(bVal, 'fr');
            });

            // Ajouter la classe de tri
            this.classList.add(isAsc ? 'sort-desc' : 'sort-asc');

            // Reinserer les lignes triees
            rows.forEach(row => tbody.appendChild(row));
        });
    });
}

/**
 * Initialiser les raccourcis clavier
 */
function initKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ignorer si on est dans un champ de saisie
        if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) {
            return;
        }

        // Ctrl+K ou Ctrl+F: Focus sur la recherche
        if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'f')) {
            e.preventDefault();
            const searchInput = document.querySelector('input[name="search"], input[name="q"], #search-query');
            if (searchInput) {
                searchInput.focus();
                searchInput.select();
            }
        }

        // Ctrl+N: Nouveau (utilisateur, groupe, etc.)
        if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
            e.preventDefault();
            const newBtn = document.querySelector('a.btn-primary[href*="create"], a.btn-primary[href*="new"]');
            if (newBtn) {
                window.location.href = newBtn.href;
            }
        }

        // Escape: Fermer les modals
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal').forEach(modal => {
                modal.style.display = 'none';
            });
        }

        // ?: Afficher l'aide des raccourcis
        if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
            showKeyboardHelp();
        }
    });
}

/**
 * Afficher l'aide des raccourcis clavier
 */
function showKeyboardHelp() {
    const helpHtml = `
        <div id="keyboard-help-modal" class="modal" style="display: flex;">
            <div class="modal-content">
                <h3>Raccourcis clavier</h3>
                <table style="width: 100%;">
                    <tr><td><kbd>Ctrl+K</kbd> ou <kbd>Ctrl+F</kbd></td><td>Rechercher</td></tr>
                    <tr><td><kbd>Ctrl+N</kbd></td><td>Nouveau</td></tr>
                    <tr><td><kbd>Escape</kbd></td><td>Fermer</td></tr>
                    <tr><td><kbd>?</kbd></td><td>Afficher cette aide</td></tr>
                </table>
                <button onclick="this.closest('.modal').remove()" class="btn btn-secondary" style="margin-top: 1rem;">Fermer</button>
            </div>
        </div>
    `;

    // Supprimer l'ancien modal s'il existe
    const existing = document.getElementById('keyboard-help-modal');
    if (existing) existing.remove();

    document.body.insertAdjacentHTML('beforeend', helpHtml);
}

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
