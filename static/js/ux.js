/**
 * Confort d'utilisation commun à toutes les pages :
 *  - recherche rapide dans la barre du haut (comptes, groupes, postes, pages) ;
 *  - étiquettes de colonnes sur les tableaux affichés en cartes (mobile) ;
 *  - sections du menu repliables, état mémorisé ;
 *  - barre de progression pendant le chargement d'une page ;
 *  - bouton d'envoi verrouillé pendant l'envoi d'un formulaire.
 */
(function () {
    'use strict';

    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
        });
    }

    /* --- Tableaux : reprend l'en-tête de chaque colonne dans data-label --- */
    function labelTable(table) {
        var heads = [];
        table.querySelectorAll('thead tr:last-child th').forEach(function (th) {
            heads.push(th.textContent.replace(/\s+/g, ' ').trim());
        });
        if (!heads.length) { return; }
        table.querySelectorAll('tbody tr').forEach(function (tr) {
            var i = 0;
            Array.prototype.forEach.call(tr.children, function (td) {
                if (td.tagName === 'TD' && !td.hasAttribute('data-label') && td.colSpan === 1 && heads[i]) {
                    td.setAttribute('data-label', heads[i]);
                }
                i += td.colSpan || 1;
            });
        });
    }
    function labelTables(root) {
        (root.querySelectorAll ? root.querySelectorAll('table.data-table') : []).forEach(labelTable);
    }
    function watchTables() {
        labelTables(document);
        if (!window.MutationObserver) { return; }
        var pending = false;
        new MutationObserver(function () {
            if (pending) { return; }
            pending = true;
            setTimeout(function () { pending = false; labelTables(document); }, 150);
        }).observe(document.getElementById('main-content') || document.body, {childList: true, subtree: true});
    }

    /* --- Menu : sections repliables --- */
    function initSidebarSections() {
        var saved = {};
        try { saved = JSON.parse(localStorage.getItem('sidebarSections') || '{}'); } catch (e) { saved = {}; }
        document.querySelectorAll('.sidebar-section').forEach(function (section) {
            var label = section.querySelector('.sidebar-label');
            if (!label) { return; }
            var key = label.textContent.trim();
            label.setAttribute('role', 'button');
            label.setAttribute('tabindex', '0');
            function apply(collapsed) {
                // La section de la page en cours reste toujours ouverte.
                if (section.querySelector('.sidebar-link.active')) { collapsed = false; }
                section.classList.toggle('collapsed', collapsed);
                label.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
            }
            function toggle() {
                var collapsed = !section.classList.contains('collapsed');
                section.classList.toggle('collapsed', collapsed);
                label.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
                saved[key] = collapsed;
                try { localStorage.setItem('sidebarSections', JSON.stringify(saved)); } catch (e) { /* stockage indisponible */ }
            }
            apply(saved[key] === true);
            label.addEventListener('click', toggle);
            label.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
            });
        });
        var active = document.querySelector('.sidebar-link.active');
        if (active && active.scrollIntoView) { active.scrollIntoView({block: 'nearest'}); }
    }

    /* --- Recherche rapide --- */
    function initQuickSearch() {
        var box = document.getElementById('quick-search');
        if (!box) { return; }
        var input = box.querySelector('input'), list = box.querySelector('.quick-search-results');
        var url = box.getAttribute('data-url'), timer = null, items = [], index = -1, seq = 0;
        var ICONS = {user: '👤', group: '👥', computer: '💻', ou: '📁', page: '➜'};
        var pages = [];
        document.querySelectorAll('.sidebar-link').forEach(function (a) {
            var text = a.querySelector('.sidebar-text');
            if (text) { pages.push({kind: 'page', label: text.textContent.trim(), detail: 'Page', url: a.getAttribute('href')}); }
        });

        function close() { list.hidden = true; index = -1; }
        function render(note) {
            if (!items.length) {
                list.innerHTML = '<div class="quick-search-empty">' + esc(note || 'Aucun résultat') + '</div>';
            } else {
                list.innerHTML = items.map(function (r, i) {
                    return '<a href="' + esc(r.url) + '" class="quick-search-item' + (i === index ? ' active' : '') +
                        '"><span class="quick-search-icon">' + (ICONS[r.kind] || '') + '</span><span><strong>' +
                        esc(r.label) + '</strong><small>' + esc(r.detail || '') + '</small></span></a>';
                }).join('');
            }
            list.hidden = false;
        }
        function search() {
            var q = input.value.trim(), mine = ++seq;
            if (q.length < 2) { close(); return; }
            var ql = q.toLowerCase();
            var found = pages.filter(function (p) { return p.label.toLowerCase().indexOf(ql) >= 0; }).slice(0, 4);
            items = found; index = -1;
            render('Recherche…');
            fetch(url + '?q=' + encodeURIComponent(q), {headers: {'Accept': 'application/json'}})
                .then(function (r) { return r.ok ? r.json() : []; })
                .catch(function () { return []; })
                .then(function (rows) {
                    if (mine !== seq) { return; }
                    items = (Array.isArray(rows) ? rows : []).concat(found);
                    render();
                });
        }
        input.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(search, 250); });
        input.addEventListener('focus', function () { if (input.value.trim().length >= 2) { search(); } });
        input.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') { close(); input.blur(); return; }
            if (list.hidden || !items.length) { return; }
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault();
                index = (index + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
                render();
            } else if (e.key === 'Enter') {
                e.preventDefault();
                window.location.href = items[Math.max(index, 0)].url;
            }
        });
        document.addEventListener('click', function (e) { if (!box.contains(e.target)) { close(); } });
        // « / » ou Ctrl+K : aller à la recherche depuis n'importe où.
        document.addEventListener('keydown', function (e) {
            var typing = ['INPUT', 'TEXTAREA', 'SELECT'].indexOf(e.target.tagName) >= 0 || e.target.isContentEditable;
            if ((e.key === '/' && !typing && !e.ctrlKey && !e.metaKey) || ((e.ctrlKey || e.metaKey) && e.key === 'k')) {
                e.preventDefault();
                e.stopImmediatePropagation();
                input.focus();
                input.select();
            }
        }, true);
    }

    /* --- Chargement : barre de progression et bouton verrouillé --- */
    function initProgress() {
        var bar = document.createElement('div');
        bar.className = 'page-progress';
        document.body.appendChild(bar);
        function start() { bar.classList.add('running'); }
        window.addEventListener('beforeunload', start);
        window.addEventListener('pageshow', function () {
            bar.classList.remove('running');
            document.querySelectorAll('button[data-busy]').forEach(function (b) {
                b.disabled = false;
                b.removeAttribute('data-busy');
            });
        });
        document.addEventListener('submit', function (e) {
            var form = e.target;
            if (e.defaultPrevented || !form || form.target === '_blank' || form.hasAttribute('data-no-busy')) { return; }
            // Laisse le formulaire partir, puis verrouille : pas de double envoi.
            setTimeout(function () {
                if (e.defaultPrevented) { return; }
                form.querySelectorAll('button[type="submit"], button:not([type])').forEach(function (b) {
                    b.disabled = true;
                    b.setAttribute('data-busy', '1');
                });
                start();
                // Téléchargement ou réponse sans changement de page : on rend la main.
                setTimeout(function () {
                    bar.classList.remove('running');
                    form.querySelectorAll('button[data-busy]').forEach(function (b) {
                        b.disabled = false;
                        b.removeAttribute('data-busy');
                    });
                }, 8000);
            }, 0);
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        watchTables();
        initSidebarSections();
        initQuickSearch();
        initProgress();
    });
})();
