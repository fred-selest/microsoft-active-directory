/*
 * Délégation d'événements compatible avec la CSP stricte (constat M9).
 *
 * Avec un nonce dans script-src, le navigateur n'exécute plus les attributs
 * on*="…". Les éléments déclarent à la place ce qu'ils déclenchent :
 *
 *   <button data-onclick="showMoveModal" data-args='["CN=…", "Dupont"]'>
 *   <select data-onchange="updateSelectedCount" data-args='["weak"]'>
 *   <form data-confirm="Supprimer ce compte ?">           (confirmation)
 *   <button data-confirm="Sûr ?" type="submit">           (idem sur un bouton)
 *
 * - data-on<événement> : nom d'une fonction globale (window) ou d'une action
 *   intégrée (voir BUILTINS). Événements gérés : click, change, input,
 *   keyup, submit.
 * - data-args : tableau JSON d'arguments. Les chaînes spéciales "$el",
 *   "$event" et "$value" sont remplacées par l'élément, l'événement et
 *   la valeur de l'élément (équivalents de this, event, this.value).
 *   Côté Jinja, toujours générer data-args avec le filtre |tojson dans un
 *   attribut entre apostrophes : data-args='{{ [a, b]|tojson }}'.
 *   Côté JS (HTML construit dans une chaîne), utiliser actionArgs() dans un
 *   attribut entre guillemets : data-args="${actionArgs(a, b)}".
 * - Si la fonction renvoie false, l'action par défaut est annulée
 *   (équivalent de onclick="return f()").
 * - data-stop-propagation : les éléments parents ne reçoivent pas le clic
 *   (équivalent de onclick="event.stopPropagation()").
 */
(function () {
    'use strict';

    var BUILTINS = {
        reload: function () { window.location.reload(); },
        back: function () { window.history.back(); },
        removeParent: function (el) { el.parentElement.remove(); },
        submitParentForm: function (el) { el.form.submit(); },
        removeClosestModal: function (el) { el.closest('.modal').remove(); },
        removeElement: function (el, event, id) { document.getElementById(id).remove(); },
        toggleDisplay: function (el, event, id) {
            var t = document.getElementById(id);
            t.style.display = t.style.display === 'block' ? 'none' : 'block';
        },
        submitForm: function (el, event, formId) {
            document.getElementById(formId).submit();
        },
        // Affiche l'élément #id et masque le parent du déclencheur.
        revealAndHideParent: function (el, event, id) {
            document.getElementById(id).style.display = 'block';
            el.parentElement.style.display = 'none';
            return false;
        },
        // Bascule une classe sur l'élément qui suit le parent du déclencheur.
        toggleNextOfParent: function (el, event, cls) {
            el.parentElement.nextElementSibling.classList.toggle(cls);
        }
    };

    // Encode des arguments pour un attribut data-args="…" d'un HTML généré en
    // JS. JSON + échappement HTML : aucune valeur (DN avec apostrophe, etc.)
    // ne peut sortir de l'attribut ni devenir du code.
    window.actionArgs = function () {
        return JSON.stringify(Array.prototype.slice.call(arguments))
            .replace(/&/g, '&amp;').replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    };

    function resolveArgs(el, event) {
        var raw = el.getAttribute('data-args');
        if (!raw) { return null; }
        var args;
        try {
            args = JSON.parse(raw);
        } catch (e) {
            console.error('data-args invalide sur', el, e);
            return [];
        }
        return args.map(function (a) {
            if (a === '$el') { return el; }
            if (a === '$event') { return event; }
            if (a === '$value') { return el.value; }
            return a;
        });
    }

    function invoke(el, name, event) {
        var args = resolveArgs(el, event);
        var result;
        if (Object.prototype.hasOwnProperty.call(BUILTINS, name)) {
            // Les actions intégrées reçoivent toujours (el, event, ...args).
            result = BUILTINS[name].apply(el, [el, event].concat(args || []));
        } else if (typeof window[name] === 'function') {
            // Fonctions de page : mêmes arguments que l'ancien on*="f(...)".
            result = window[name].apply(el, args || []);
        } else {
            console.error('Action inconnue : ' + name, el);
            return;
        }
        if (result === false) { event.preventDefault(); }
    }

    // Parcourt les ancêtres de la cible comme le ferait la propagation native,
    // pour que l'ordre et stopPropagation se comportent comme avant.
    function dispatch(event) {
        var attr = 'data-on' + event.type;
        for (var el = event.target; el && el !== document; el = el.parentElement) {
            if (el.nodeType !== 1) { continue; }
            if (event.type === 'click' || event.type === 'submit') {
                var msg = el.getAttribute('data-confirm');
                var confirmTarget = event.type === 'submit'
                    ? el.tagName === 'FORM'
                    : el.tagName !== 'FORM';
                if (msg !== null && confirmTarget && !window.confirm(msg)) {
                    event.preventDefault();
                    event.stopImmediatePropagation();
                    return;
                }
            }
            var name = el.getAttribute(attr);
            if (name) { invoke(el, name, event); }
            if (event.type === 'click' && el.hasAttribute('data-stop-propagation')) { return; }
            if (event.cancelBubble) { return; }
        }
    }

    ['click', 'change', 'input', 'keyup', 'submit'].forEach(function (type) {
        document.addEventListener(type, dispatch);
    });
})();
