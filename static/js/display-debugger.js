/**
 * Bookmarklet - Debug d'affichage responsive
 * 
 * Utilisation:
 * 1. Copier ce code dans un bookmark
 * 2. Cliquer sur le bookmark sur n'importe quelle page
 * 3. L'outil de debug s'affiche
 * 
 * OU
 * 
 * Dans la console du navigateur (F12):
 *   loadDisplayDebugger()
 */

(function() {
    'use strict';
    
    // Éviter le double chargement
    if (document.getElementById('display-debugger')) {
        document.getElementById('display-debugger').remove();
        alert('Display Debugger fermé');
        return;
    }
    
    // Créer le container de debug
    const debuggerEl = document.createElement('div');
    debuggerEl.id = 'display-debugger';
    debuggerEl.innerHTML = `
        <style>
            #display-debugger {
                position: fixed;
                bottom: 20px;
                right: 20px;
                background: #1a1a2e;
                color: #fff;
                padding: 15px;
                border-radius: 8px;
                font-family: monospace;
                font-size: 12px;
                z-index: 999999;
                box-shadow: 0 4px 6px rgba(0,0,0,0.3);
                max-width: 300px;
                min-width: 250px;
            }
            #display-debugger h3 {
                margin: 0 0 10px 0;
                font-size: 14px;
                color: #00d9ff;
                border-bottom: 1px solid #333;
                padding-bottom: 5px;
            }
            #display-debugger .debug-row {
                display: flex;
                justify-content: space-between;
                margin: 5px 0;
                padding: 3px 0;
            }
            #display-debugger .debug-label {
                color: #888;
            }
            #display-debugger .debug-value {
                color: #0f0;
                font-weight: bold;
            }
            #display-debugger .debug-warning {
                color: #ff0;
            }
            #display-debugger .debug-error {
                color: #f00;
            }
            #display-debugger button {
                background: #e94560;
                color: #fff;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
                cursor: pointer;
                margin-top: 10px;
                width: 100%;
            }
            #display-debugger button:hover {
                background: #ff6b6b;
            }
            #display-debugger .grid-overlay {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background-image: 
                    linear-gradient(rgba(255,0,0,0.1) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(255,0,0,0.1) 1px, transparent 1px);
                background-size: 100px 100px;
                pointer-events: none;
                z-index: 999998;
                display: none;
            }
        </style>
        
        <h3>🔍 Display Debugger</h3>
        
        <div class="debug-row">
            <span class="debug-label">Viewport:</span>
            <span class="debug-value" id="dd-viewport">--</span>
        </div>
        
        <div class="debug-row">
            <span class="debug-label">Device Pixel Ratio:</span>
            <span class="debug-value" id="dd-dpr">--</span>
        </div>
        
        <div class="debug-row">
            <span class="debug-label">Orientation:</span>
            <span class="debug-value" id="dd-orientation">--</span>
        </div>
        
        <div class="debug-row">
            <span class="debug-label">Breakpoint:</span>
            <span class="debug-value" id="dd-breakpoint">--</span>
        </div>
        
        <div class="debug-row">
            <span class="debug-label">Overflow X:</span>
            <span class="debug-value" id="dd-overflow">--</span>
        </div>
        
        <div class="debug-row">
            <span class="debug-label">Elements:</span>
            <span class="debug-value" id="dd-elements">--</span>
        </div>
        
        <button onclick="document.getElementById('dd-grid').style.display = document.getElementById('dd-grid').style.display === 'block' ? 'none' : 'block'">
            Toggle Grid Overlay
        </button>
        
        <button onclick="document.getElementById('display-debugger').remove()">
            Fermer
        </button>
        
        <div id="dd-grid" class="grid-overlay"></div>
    `;
    
    document.body.appendChild(debuggerEl);
    
    // Fonction de mise à jour
    function updateDebugInfo() {
        const width = window.innerWidth;
        const height = window.innerHeight;
        const dpr = window.devicePixelRatio || 1;
        const orientation = screen.orientation ? screen.orientation.type : (width > height ? 'landscape' : 'portrait');
        
        // Déterminer le breakpoint
        let breakpoint = 'Unknown';
        if (width < 768) breakpoint = 'Mobile (<768px)';
        else if (width < 1024) breakpoint = 'Tablette (768-1024px)';
        else if (width < 1440) breakpoint = 'Desktop (1024-1440px)';
        else breakpoint = 'Large (>1440px)';
        
        // Vérifier l'overflow
        const hasOverflowX = document.documentElement.scrollWidth > document.documentElement.clientWidth;
        const overflowEl = document.getElementById('dd-overflow');
        overflowEl.textContent = hasOverflowX ? '⚠️ OUI (Bug!)' : '✅ Non';
        overflowEl.className = hasOverflowX ? 'debug-value debug-warning' : 'debug-value';
        
        // Compter les éléments
        const elementCount = document.getElementsByTagName('*').length;
        
        // Mettre à jour l'affichage
        document.getElementById('dd-viewport').textContent = `${width} x ${height}`;
        document.getElementById('dd-dpr').textContent = dpr.toFixed(2);
        document.getElementById('dd-orientation').textContent = orientation;
        document.getElementById('dd-breakpoint').textContent = breakpoint;
        document.getElementById('dd-elements').textContent = elementCount;
    }
    
    // Mettre à jour immédiatement
    updateDebugInfo();
    
    // Mettre à jour au redimensionnement
    window.addEventListener('resize', updateDebugInfo);
    
    // Mettre à jour périodiquement
    setInterval(updateDebugInfo, 2000);
    
    console.log('✅ Display Debugger loaded!');
    console.log('📏 Resize the window to test responsive behavior');
    
})();
