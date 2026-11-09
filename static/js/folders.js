/*
 * Répertoires : analyses en arrière-plan et affichage des accès d'un compte.
 *
 * Utilisé par la page « Accès d'un compte », les fiches utilisateur et
 * groupe (section Répertoires) et la vue d'ensemble des droits.
 * Toutes les valeurs venues du serveur passent par esc() avant insertion.
 */
(function () {
    'use strict';

    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
        });
    }

    function csrf() {
        var meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.content : '';
    }

    /*
     * Lance une analyse (POST startUrl body) puis interroge statusUrl + job
     * toutes les 2 s. onProgress(secondes) pendant l'analyse, onDone(data) à
     * la fin (data.success faux en cas d'erreur).
     */
    function runJob(startUrl, statusUrl, body, onProgress, onDone) {
        function poll(job) {
            fetch(statusUrl + encodeURIComponent(job), {headers: {'X-Requested-With': 'XMLHttpRequest'}})
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (data.status === 'running') {
                        onProgress(data.elapsed || 0);
                        setTimeout(function () { poll(job); }, 2000);
                        return;
                    }
                    onDone(data);
                })
                .catch(function () { setTimeout(function () { poll(job); }, 5000); });
        }
        fetch(startUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrf(),
                      'X-Requested-With': 'XMLHttpRequest'},
            body: JSON.stringify(body)
        }).then(function (r) { return r.json(); })
          .then(function (data) {
              if (!data.success || !data.job) { onDone(data); return; }
              poll(data.job);
          })
          .catch(function () { onDone({success: false, error: 'Le serveur n\'a pas répondu.'}); });
    }

    function levelClass(level) {
        if (level === 'Contrôle total') { return 'right-full'; }
        if (level === 'Modification' || level === 'Écriture') { return 'right-modify'; }
        if (level === 'Spéciale') { return 'right-special'; }
        return 'right-read';
    }

    function rightBadge(a) {
        return '<span class="right-badge ' + (a.deny ? 'right-deny' : levelClass(a.level)) + '">' +
            (a.deny ? 'Refusé : ' : '') + esc(a.level) + '</span>';
    }

    /* Tableau des dossiers accessibles à un compte (réponse de /folders/api/access). */
    function renderAccess(out, data, browseUrl, options) {
        options = options || {};
        if (!data.success) {
            out.innerHTML = '<div class="alert alert-error">' + esc(data.error || 'Erreur') + '</div>';
            return;
        }
        var p = data.principal || {};
        var html = '<p class="text-muted folder-access-summary">' +
            (options.compact ? '' : '<strong>' + esc(p.name) + '</strong> — ') +
            data.found.length + ' droit(s) sur ' + data.scanned + ' dossier(s) analysé(s), via ' +
            p.groups + ' groupe(s)' +
            (data.truncated ? ' — <strong>analyse interrompue à la limite de dossiers</strong>' : '') + '.</p>';
        if (data.found.length) {
            html += '<div class="table-container folder-table-wrap"><table class="data-table"><thead><tr>' +
                '<th>Dossier</th><th>Droits</th><th>Via</th><th>S\'applique à</th></tr></thead><tbody>';
            data.found.forEach(function (a) {
                html += '<tr><td class="access-path"><a href="' +
                    esc(browseUrl + '?path=' + encodeURIComponent(a.path)) + '">' + esc(a.path) + '</a>' +
                    (a.inherited ? ' <small class="text-muted">(hérité)</small>' : '') + '</td><td>' +
                    rightBadge(a) + '</td><td>' + (a.direct ? '<strong>Directement</strong>' : esc(a.via)) +
                    '</td><td>' + esc(a.applies) + '</td></tr>';
            });
            html += '</tbody></table></div>';
        } else {
            html += '<p>Aucun droit sur les dossiers analysés.</p>';
        }
        if (data.errors && data.errors.length) {
            html += '<details><summary>' + data.errors.length + ' dossier(s) illisible(s)</summary><ul>' +
                data.errors.map(function (e) { return '<li>' + esc(e) + '</li>'; }).join('') + '</ul></details>';
        }
        out.innerHTML = html;
    }

    /*
     * Section « Répertoires » d'une fiche : lance l'analyse du compte au
     * chargement (résultat mis en cache 10 min côté serveur) et l'affiche.
     */
    function initPrincipalSection(el) {
        var out = el.querySelector('.folder-access-result');
        var refresh = el.querySelector('.folder-access-refresh');
        function start(force) {
            if (refresh) { refresh.disabled = true; }
            out.innerHTML = '<p class="text-muted">⏳ Recherche des répertoires accessibles…</p>';
            runJob(el.dataset.startUrl, el.dataset.statusUrl, {dn: el.dataset.dn, refresh: !!force},
                function (sec) {
                    out.innerHTML = '<p class="text-muted">⏳ Recherche des répertoires accessibles… (' + sec + ' s)</p>';
                },
                function (data) {
                    renderAccess(out, data, el.dataset.browseUrl, {compact: true});
                    if (refresh) { refresh.disabled = false; }
                });
        }
        if (refresh) { refresh.addEventListener('click', function () { start(true); }); }
        start(false);
    }

    window.AdwiFolders = {esc: esc, runJob: runJob, renderAccess: renderAccess, rightBadge: rightBadge,
                          levelClass: levelClass};

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('[data-folder-access]').forEach(initPrincipalSection);
    });
})();
