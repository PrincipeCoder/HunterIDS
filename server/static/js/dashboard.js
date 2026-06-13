document.addEventListener('DOMContentLoaded', () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws/dashboard`;
    
    let socket;
    let reconnectInterval = 3000;

    let totalAlerts = 0;
    let criticalAlerts = 0;
    const uniqueNodesMap = new Map();

    const alertsTableBody = document.getElementById('alerts-table-body');
    const emptyStateRow = document.getElementById('empty-state');
    const connStatus = document.getElementById('connection-status');
    const statTotal = document.getElementById('stat-total');
    const statCritical = document.getElementById('stat-critical');
    const statNodes = document.getElementById('stat-nodes');
    const clearBtn = document.getElementById('clear-btn');
    const filterClass = document.getElementById('filter-class');
    const filterIp = document.getElementById('filter-ip');
    const sysTime = document.getElementById('sys-time');
    const radarTargets = document.getElementById('radar-targets');

    // Modal elements
    const shapModal = document.getElementById('shap-modal');
    const closeModalBtn = document.getElementById('close-modal');
    const shapImage = document.getElementById('shap-image');

    closeModalBtn.addEventListener('click', () => {
        shapModal.classList.add('hidden');
    });

    // System Clock Update
    setInterval(() => {
        const now = new Date();
        sysTime.textContent = now.toISOString().substr(11, 8);
    }, 1000);

    function applyFilters() {
        const classVal = filterClass.value;
        const ipVal = filterIp.value.toLowerCase();
        
        const rows = alertsTableBody.querySelectorAll('tr:not(#empty-state)');
        rows.forEach(row => {
            const rowClass = row.getAttribute('data-threat-class');
            const rowIps = row.getAttribute('data-ips').toLowerCase();
            
            let showClass = classVal === 'ALL' || rowClass === classVal;
            let showIp = ipVal === '' || rowIps.includes(ipVal);
            
            row.style.display = (showClass && showIp) ? 'table-row' : 'none';
        });
    }

    filterClass.addEventListener('change', applyFilters);
    filterIp.addEventListener('input', applyFilters);

    clearBtn.addEventListener('click', () => {
        const rows = alertsTableBody.querySelectorAll('tr:not(#empty-state)');
        rows.forEach(r => r.remove());
        totalAlerts = 0;
        criticalAlerts = 0;
        uniqueNodesMap.clear();
        updateStats();
        emptyStateRow.style.display = 'table-row';
        radarTargets.innerHTML = ''; // Clear radar
    });

    function connect() {
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
            updateConnectionStatus(true);
        };

        socket.onmessage = (event) => {
            const data = JSON.parse(event.data);
            handleNewAlert(data);
        };

        socket.onclose = () => {
            updateConnectionStatus(false);
            setTimeout(connect, reconnectInterval);
        };

        socket.onerror = (error) => {
            socket.close();
        };
    }

    function updateConnectionStatus(connected) {
        const pingIndicator = document.getElementById('conn-ping');
        const dotIndicator = document.getElementById('conn-dot');
        
        if (connected) {
            connStatus.textContent = 'UPLINK_ACTIVE';
            connStatus.className = 'text-xs font-mono font-bold uppercase tracking-wider text-soc-green';
            pingIndicator.className = 'animate-ping absolute inline-flex h-full w-full rounded-full bg-soc-green opacity-75';
            dotIndicator.className = 'relative inline-flex rounded-full h-3 w-3 bg-soc-green';
        } else {
            connStatus.textContent = 'LINK_SEVERED';
            connStatus.className = 'text-xs font-mono font-bold uppercase tracking-wider text-soc-red text-neon-red';
            pingIndicator.className = 'hidden';
            dotIndicator.className = 'relative inline-flex rounded-full h-3 w-3 bg-soc-red bg-neon-red';
        }
    }

    function addRadarBlip(isMalicious) {
        const blip = document.createElement('div');
        // Random position within radar circle
        const angle = Math.random() * Math.PI * 2;
        const radius = Math.random() * 80; // Assuming 200px radar -> 100px radius
        const x = 100 + radius * Math.cos(angle);
        const y = 100 + radius * Math.sin(angle);
        
        blip.className = `absolute w-2 h-2 rounded-full ${isMalicious ? 'bg-soc-red shadow-[0_0_8px_#ff003c]' : 'bg-soc-green shadow-[0_0_8px_#00ff41]'} animate-ping`;
        blip.style.left = `${x}px`;
        blip.style.top = `${y}px`;
        
        radarTargets.appendChild(blip);
        
        // Remove blip after 4 seconds
        setTimeout(() => {
            if (blip.parentNode) blip.parentNode.removeChild(blip);
        }, 4000);
    }

    function handleNewAlert(alert) {
        totalAlerts++;
        const isNormal = alert.prediction.toLowerCase() === 'normal' || alert.prediction === '0';
        const isMalicious = !isNormal;
        
        if (isMalicious) {
            criticalAlerts++;
        }
        uniqueNodesMap.set(alert.node_ip, new Date());
        updateStats();

        if (emptyStateRow.parentNode === alertsTableBody) {
            emptyStateRow.style.display = 'none';
        }

        // Add visual blip to radar
        addRadarBlip(isMalicious);

        let topFeaturesHtml = '';
        if (alert.features) {
            const featureEntries = Object.entries(alert.features).slice(0, 3);
            topFeaturesHtml = featureEntries.map(([k, v]) => 
                `<span class="inline-flex items-center px-1.5 py-0.5 border border-soc-border bg-soc-panel text-[10px] text-soc-text mr-1">
                    <span class="text-soc-cyan mr-1">${k}:</span>${Number(v).toFixed(2)}
                </span>`
            ).join('');
        }

        const confidencePercent = (alert.confidence * 100).toFixed(1);
        
        let predClass = isMalicious ? 'text-soc-red border-soc-red bg-soc-red/10' : 'text-soc-green border-soc-green bg-soc-green/10';
        let rowHighlight = isMalicious && alert.confidence > 0.9 ? 'bg-soc-red/5 border-l-2 border-soc-red' : (isNormal ? 'bg-soc-green/5 border-l-2 border-soc-green' : 'border-l-2 border-transparent');
        let alertLabel = isMalicious ? `DETECTED: ${alert.prediction.toUpperCase()}` : 'NORMAL_TRAFFIC';
        let confColor = isMalicious && alert.confidence > 0.9 ? 'bg-soc-red' : (isMalicious ? 'bg-soc-yellow' : 'bg-soc-green');
        let confText = isMalicious && alert.confidence > 0.9 ? 'text-soc-red' : (isMalicious ? 'text-soc-yellow' : 'text-soc-green');
        
        const row = document.createElement('tr');
        row.className = `hover:bg-soc-panel transition-colors row-animate-in ${rowHighlight}`;
        row.setAttribute('data-threat-class', isMalicious ? 'MALICIOUS' : 'NORMAL');
        row.setAttribute('data-ips', `${alert.src_ip} ${alert.dst_ip} ${alert.node_ip}`);
        row.innerHTML = `
            <td class="px-4 py-3 whitespace-nowrap">
                <div class="text-soc-white/80">${alert.timestamp}</div>
            </td>
            <td class="px-4 py-3 whitespace-nowrap">
                <div class="text-soc-cyan"><span class="opacity-70">${alert.src_ip || 'N/A'}</span> &rarr; ${alert.dst_ip || 'N/A'}</div>
                <div class="text-[9px] text-soc-text opacity-50 uppercase tracking-widest">SENSOR: ${alert.node_ip}</div>
            </td>
            <td class="px-4 py-3 whitespace-nowrap">
                <span class="inline-block px-2 py-0.5 text-[10px] uppercase font-bold border ${predClass}">
                    ${alertLabel}
                </span>
            </td>
            <td class="px-4 py-3 whitespace-nowrap">
                <div class="flex items-center space-x-2">
                    <div class="w-16 bg-soc-bg border border-soc-border h-2">
                        <div class="${confColor} h-full" style="width: ${confidencePercent}%"></div>
                    </div>
                    <span class="${confText} text-xs">${confidencePercent}%</span>
                </div>
            </td>
            <td class="px-4 py-3">
                <div class="flex flex-wrap">
                    ${topFeaturesHtml}
                </div>
            </td>
            <td class="px-4 py-3 text-right">
                <button class="analyze-btn px-3 py-1 text-[10px] font-mono border border-soc-cyan text-soc-cyan hover:bg-soc-cyan hover:text-soc-bg transition-colors"
                        data-plot="${alert.shap_plot_b64}">
                    <i class="fa-solid fa-microscope mr-1"></i>ANALYZE
                </button>
            </td>
        `;

        alertsTableBody.insertBefore(row, alertsTableBody.firstChild);
        
        // Aplica filtros a la nueva fila inmediatamente
        applyFilters();
        
        // Attach event listener to the newly created button
        const btn = row.querySelector('.analyze-btn');
        if(btn) {
            btn.addEventListener('click', function() {
                shapImage.src = this.getAttribute('data-plot');
                shapModal.classList.remove('hidden');
            });
        }

        while (alertsTableBody.children.length > 51) {
            alertsTableBody.removeChild(alertsTableBody.lastChild);
        }
    }

    function padZero(num, size) {
        let s = String(num);
        while (s.length < size) s = "0" + s;
        return s;
    }

    function updateStats() {
        statTotal.textContent = padZero(totalAlerts, 3);
        statCritical.textContent = padZero(criticalAlerts, 3);
        statNodes.textContent = padZero(uniqueNodesMap.size, 3);
        
        const activeNodesList = document.getElementById('active-nodes-list');
        if (activeNodesList) {
            activeNodesList.innerHTML = '';
            uniqueNodesMap.forEach((lastSeen, ip) => {
                const ageSec = Math.floor((new Date() - lastSeen) / 1000);
                const color = ageSec < 10 ? 'text-soc-green' : 'text-soc-yellow';
                const label = ageSec < 10 ? 'ONLINE' : 'AWAY';
                activeNodesList.innerHTML += `
                    <div class="flex justify-between items-center border-b border-soc-border/30 pb-1">
                        <span>[${ip}]</span>
                        <span class="${color} animate-pulse">${label}</span>
                    </div>
                `;
            });
        }
    }

    connect();
});
