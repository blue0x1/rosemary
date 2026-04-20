let portForwardsCache = [];
let reverseForwardsCache = [];
let currentCtxAgent = null;

document.addEventListener('DOMContentLoaded', function () {
    const themeToggle = document.getElementById('checkbox');
    const body = document.body;
    const csrfTokenMeta = document.querySelector('meta[name="csrf-token"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute('content') : '';

    let pingSectionHiddenManually = false;
    let lastPingClearTime = 0;
    let lastDisplayedLogCount = 0;  

    let agentsCache = [];
    let cy = null;
    let currentGraphTheme = 'dark';  

    const knownAgentIds = new Set();  

    const backdrop = document.getElementById('modal-backdrop');

     
    const msgModal = document.getElementById('message-modal');
    const msgModalTitle = document.getElementById('message-modal-title');
    const msgModalBody = document.getElementById('message-modal-body');
    const msgModalOk = document.getElementById('message-modal-ok');

     
    const confirmModal = document.getElementById('confirm-modal');
    const confirmTitle = document.getElementById('confirm-modal-title');
    const confirmBody = document.getElementById('confirm-modal-body');
    const confirmOk = document.getElementById('confirm-modal-ok');
    const confirmCancel = document.getElementById('confirm-modal-cancel');

    let confirmResolve = null;

    const notificationsContainer = document.getElementById('notifications-container');

    function showMessage(title, text) {
        if (!backdrop || !msgModal) return;
        msgModalTitle.textContent = title || 'Message';
        msgModalBody.textContent = text || '';
        backdrop.style.display = 'block';
        msgModal.style.display = 'block';
    }

    if (msgModalOk) {
        msgModalOk.addEventListener('click', () => {
            if (msgModal) msgModal.style.display = 'none';
            if (backdrop) backdrop.style.display = 'none';
        });
    }

    function showConfirm(title, text) {
        if (!backdrop || !confirmModal) return Promise.resolve(false);
        confirmTitle.textContent = title || 'Confirm';
        confirmBody.textContent = text || '';
        backdrop.style.display = 'block';
        confirmModal.style.display = 'block';

        return new Promise(resolve => {
            confirmResolve = resolve;
        });
    }

    function closeConfirm(result) {
        if (confirmModal) confirmModal.style.display = 'none';
        if (backdrop) backdrop.style.display = 'none';
        if (confirmResolve) {
            confirmResolve(result);
            confirmResolve = null;
        }
    }

    if (confirmOk) {
        confirmOk.addEventListener('click', () => closeConfirm(true));
    }
    if (confirmCancel) {
        confirmCancel.addEventListener('click', () => closeConfirm(false));
    }

    function showAgentToast(agent, kind) {
        if (!notificationsContainer) return;

        const toast = document.createElement('div');
        toast.className = 'notification-toast';

        const img = document.createElement('img');
        img.src = getOsIcon((agent.os || '').toLowerCase());
        img.alt = agent.os || 'OS';

        const textWrap = document.createElement('div');
        textWrap.className = 'toast-text';

        const titleEl = document.createElement('div');
        titleEl.className = 'toast-title';
        titleEl.textContent = kind === 'connected' ? 'Agent connected' : 'Agent disconnected';

        const bodyEl = document.createElement('div');
        bodyEl.className = 'toast-body';
        const osLabel = agent.os || 'Unknown OS';
        bodyEl.textContent = kind === 'connected'
            ? `${agent.id} • ${osLabel}`
            : agent.id;

        textWrap.appendChild(titleEl);
        textWrap.appendChild(bodyEl);

        toast.appendChild(img);
        toast.appendChild(textWrap);

        notificationsContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s ease';
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, 4000);
    }

    function setTheme(theme) {
        body.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        if (themeToggle) {
            themeToggle.checked = (theme === 'dark');
        }

         
        currentGraphTheme = theme;
        if (cy) {
            cy.destroy();
            cy = null;
            var cyContainer = document.getElementById('cy');
            if (cyContainer) cyContainer.innerHTML = '';
            graphLayoutDone = false;
            graphFitted = false;
            initGraph();
            if (cy) {
                updateGraph(agentsCache);
                var graphView = document.getElementById('graph-view');
                if (graphView && graphView.style.display !== 'none') {
                    cy.resize();
                    fitGraph();
                    graphFitted = true;
                }
            }
        }
        const logo = document.getElementById('header-logo');
        if (logo) {
            logo.src = theme === 'dark' ? '/static/img/logo-dark.png' : '/static/img/logo-light.png';
        }
        const aboutLogo = document.getElementById('about-logo');
        if (aboutLogo) {
            aboutLogo.src = theme === 'dark' ? '/static/img/logo-dark.png' : '/static/img/logo-light.png';
        }
    }

    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'light') {
        setTheme('light');
    } else {
        setTheme('dark');
    }

    if (themeToggle) {
        themeToggle.addEventListener('change', function () {
            if (this.checked) {
                setTheme('dark');
            } else {
                setTheme('light');
            }
        });
    }

    const portForwardForm = document.querySelector('form[action="/port-forward"]');
    if (portForwardForm) {
        portForwardForm.addEventListener('submit', function (event) {
            const agentPort = document.getElementById('agentListenPort').value.trim();
            if (agentPort === '') {
                event.preventDefault();
                showMessage('Validation', 'Please specify an Agent Listen Port.');
            }
        });
    }

    const pingForm = document.getElementById('ping-form');
    if (pingForm) {
        pingForm.addEventListener('submit', function (event) {
            event.preventDefault();

            const pingResultsSection = document.getElementById('ping-results-section');
            const pingTableBody = document.getElementById('ping-table-body');

            const agentID = document.getElementById('pingAgentID').value;
            const target = document.getElementById('pingTarget').value.trim();
            const count = document.getElementById('pingCount').value.trim() || '4';

            if (!agentID || target === '') {
                showMessage('Validation', 'Please select an agent and enter a target.');
                return;
            }

            lastPingClearTime = Date.now();
            pingSectionHiddenManually = true;

            if (pingTableBody) {
                pingTableBody.innerHTML = '';
            }
            if (pingResultsSection) {
                pingResultsSection.style.display = 'none';
            }

            sendPingRequest(agentID, target, count);
        });
    }

    function sendPingRequest(agentID, target, count) {
        fetch('/api/icmp-ping', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body:
                'agentID=' + encodeURIComponent(agentID) +
                '&target=' + encodeURIComponent(target) +
                '&count=' + encodeURIComponent(count) +
                '&csrf_token=' + encodeURIComponent(csrfToken),
            credentials: 'include'
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok ' + response.statusText);
                }
                return response.text();
            })
            .then(text => {
                console.log(text);
            })
            .catch(error => console.error('Error sending ICMP ping:', error));
    }

    function processData(data) {
                if (!data) return;

                const agentsTableBody = document.getElementById('agents-table-body');
                const agentsArr = data.agents || [];

                const currentIds = new Set(agentsArr.map(a => a.id));

                agentsArr.forEach(agent => {
                    if (!knownAgentIds.has(agent.id)) {
                        showAgentToast(agent, 'connected');
                        knownAgentIds.add(agent.id);
                    }
                });

                knownAgentIds.forEach(id => {
                    if (!currentIds.has(id)) {
                        const prev = agentsCache.find(a => a.id === id) || { id, os: '' };
                        showAgentToast(prev, 'disconnected');
                        knownAgentIds.delete(id);
                    }
                });

                if (agentsTableBody) {
                     
                    const existingRows = new Map();
                    Array.from(agentsTableBody.rows).forEach(row => {
                        if (row.dataset.agentId) existingRows.set(row.dataset.agentId, row);
                    });

                    const sortedAgents = [...agentsArr].sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true, sensitivity: 'base' }));

                    sortedAgents.forEach(agent => {
                        if (existingRows.has(agent.id)) {
                             
                            const row = existingRows.get(agent.id);
                            existingRows.delete(agent.id);  

                             
                            const idCell = row.cells[0];
                            const existingBadge = idCell.querySelector('.agent-tag-badge');
                            if (agent.tag) {
                                if (existingBadge) {
                                    existingBadge.textContent = agent.tag;
                                } else {
                                    const tagBadge = document.createElement('div');
                                    tagBadge.className = 'agent-tag-badge';
                                    tagBadge.textContent = agent.tag;
                                    idCell.insertBefore(tagBadge, idCell.firstChild);
                                }
                            } else if (existingBadge) {
                                existingBadge.remove();
                            }

                            
                            const lastSeenCell = row.cells[4];
                            if (agent.last_seen) {
                                lastSeenCell.dataset.lastSeen = agent.last_seen;
                                lastSeenCell.textContent = new Date(agent.last_seen).toLocaleString();
                            }

                             
                            const uptimeCell = row.cells[5];
                            if (agent.connected_at) {
                                const newTs = new Date(agent.connected_at).getTime();
                                if (String(newTs) !== uptimeCell.dataset.connectedAt) {
                                    uptimeCell.dataset.connectedAt = newTs;
                                }
                            }

                            
                            row.cells[6].textContent = (agent.subnets || []).join(', ');

                             
                            agentsTableBody.appendChild(row);
                        } else {
                            
                            const row = document.createElement('tr');
                            row.dataset.agentId = agent.id;

                            const idCell = document.createElement('td');
                            if (agent.tag) {
                                const tagBadge = document.createElement('div');
                                tagBadge.className = 'agent-tag-badge';
                                tagBadge.textContent = agent.tag;
                                idCell.appendChild(tagBadge);
                            }
                            const idText = document.createElement('div');
                            idText.textContent = agent.id;
                            idCell.appendChild(idText);
                            row.appendChild(idCell);

                            const osCell = document.createElement('td');
                            osCell.textContent = agent.os || '';
                            row.appendChild(osCell);

                            const hostCell = document.createElement('td');
                            hostCell.textContent = agent.hostname || '';
                            row.appendChild(hostCell);

                            const userCell = document.createElement('td');
                            userCell.textContent = agent.username || '';
                            row.appendChild(userCell);

                            const lastSeenCell = document.createElement('td');
                            if (agent.last_seen) {
                                lastSeenCell.dataset.lastSeen = agent.last_seen;
                                lastSeenCell.textContent = new Date(agent.last_seen).toLocaleString();
                            }
                            row.appendChild(lastSeenCell);

                             
                            const uptimeCell = document.createElement('td');
                            if (agent.connected_at) {
                                const ts = new Date(agent.connected_at).getTime();
                                uptimeCell.dataset.connectedAt = ts;
                                uptimeCell.textContent = formatUptime(Math.floor((Date.now() - ts) / 1000));
                            } else {
                                uptimeCell.textContent = '—';
                            }
                            row.appendChild(uptimeCell);

                            const subnetsCell = document.createElement('td');
                            subnetsCell.textContent = (agent.subnets || []).join(', ');
                            row.appendChild(subnetsCell);

                            const actionsCell = document.createElement('td');
                            const disconnectButton = document.createElement('button');
                            disconnectButton.textContent = 'Disconnect';
                            disconnectButton.className = 'disconnect-button';
                            disconnectButton.onclick = () => disconnectAgent(agent.id);
                            actionsCell.appendChild(disconnectButton);
                            row.appendChild(actionsCell);

                            row.addEventListener('contextmenu', function (e) {
                                e.preventDefault();
                                currentCtxAgent = agent.id;
                                showAgentContextMenu(e.clientX, e.clientY, currentCtxAgent, agent.id);
                            });

                            agentsTableBody.appendChild(row);
                        }
                    });

                     
                    existingRows.forEach(row => row.remove());
                }

                agentsCache = agentsArr.map(a => ({
                    id: a.id,
                    os: (a.os || '').toLowerCase(),
                    subnets: (a.subnets || []),
                    tag: a.tag || ''
                }));

                updateGraph(agentsCache);

                const destinationAgentSelect = document.getElementById('destinationAgentID');
                if (destinationAgentSelect) {
                    const currentSelectedAgent = destinationAgentSelect.value;
                    destinationAgentSelect.innerHTML = '';
                    const defaultOpt = document.createElement('option');
                    defaultOpt.value = '';
                    defaultOpt.textContent = '--Select an Agent--';
                    destinationAgentSelect.appendChild(defaultOpt);

                    agentsArr.forEach(agent => {
                        const option = document.createElement('option');
                        option.value = agent.id;
                        option.textContent = agent.id;
                        destinationAgentSelect.appendChild(option);
                    });

                    if ([...destinationAgentSelect.options].some(option => option.value === currentSelectedAgent)) {
                        destinationAgentSelect.value = currentSelectedAgent;
                    }
                }

                const pingAgentSelect = document.getElementById('pingAgentID');
                if (pingAgentSelect) {
                    const currentPingAgent = pingAgentSelect.value;
                    pingAgentSelect.innerHTML = '';
                    const defaultPingOpt = document.createElement('option');
                    defaultPingOpt.value = '';
                    defaultPingOpt.textContent = '--Select an Agent--';
                    pingAgentSelect.appendChild(defaultPingOpt);

                    agentsArr.forEach(agent => {
                        const option = document.createElement('option');
                        option.value = agent.id;
                        option.textContent = agent.id;
                        pingAgentSelect.appendChild(option);
                    });

                    if ([...pingAgentSelect.options].some(option => option.value === currentPingAgent)) {
                        pingAgentSelect.value = currentPingAgent;
                    }
                }

                const routingTableBody = document.getElementById('routing-table-body');
                if (routingTableBody) {
                    routingTableBody.innerHTML = '';
                    const rt = data.routing_table || {};
                    for (const subnet in rt) {
                        if (Object.prototype.hasOwnProperty.call(rt, subnet)) {
                            const row = routingTableBody.insertRow();
                            row.insertCell().textContent = subnet;
                            row.insertCell().textContent = rt[subnet];
                        }
                    }
                }

                const portForwardsTableBody = document.getElementById('port-forwards-table-body');
                const portForwards = data.port_forwards || [];
                portForwardsCache = portForwards;
                 
                const fwdDrawer = document.getElementById('forwards-drawer');
                if (fwdDrawer && fwdDrawer.classList.contains('open')) {
                    populateAllForwards(portForwardsCache);
                    populateReverseForwards(reverseForwardsCache);
                    populateRoutingToggleTable(
                        data.routing_table || {},
                        data.disabled_subnets || {},
                        data.subnet_owners || {}
                    );
                }
                if (portForwardsTableBody) {
                    portForwardsTableBody.innerHTML = '';
                    portForwards.forEach(pf => {
                        const row = portForwardsTableBody.insertRow();
                        row.insertCell().textContent = pf.agent_listen_port;
                        row.insertCell().textContent = pf.destination_agent_id;
                        row.insertCell().textContent = pf.destination_host;
                        row.insertCell().textContent = pf.destination_port;

                        const actionsCell = row.insertCell();
                        const deleteButton = document.createElement('button');
                        deleteButton.textContent = 'Delete';
                        deleteButton.className = 'delete-button';
                        deleteButton.onclick = () => deletePortForward(pf.listener_id);
                        actionsCell.appendChild(deleteButton);
                    });
                }

                const pingTableBody = document.getElementById('ping-table-body');
                const pingResultsSection = document.getElementById('ping-results-section');
                if (pingTableBody) {
                    pingTableBody.innerHTML = '';
                    let history = data.ping_history || [];

                    if (lastPingClearTime) {
                        history = history.filter(rec => {
                            if (!rec.time) return true;
                            const t = new Date(rec.time).getTime();
                            return t >= lastPingClearTime;
                        });
                    }

                    if (history.length) {
                        pingSectionHiddenManually = false;
                        if (pingResultsSection && !pingSectionHiddenManually) {
                            pingResultsSection.style.display = 'block';
                        }
                        history.forEach(rec => {
                            const row = pingTableBody.insertRow();
                            const t = new Date(rec.time);
                            row.insertCell().textContent = t.toLocaleTimeString();
                            row.insertCell().textContent = rec.agent_id;
                            row.insertCell().textContent = rec.target;
                            row.insertCell().textContent = rec.seq;
                            row.insertCell().textContent = rec.success ? 'yes' : 'no';
                            row.insertCell().textContent = rec.rtt_ms.toFixed(2);
                            row.insertCell().textContent = rec.error || '';
                        });
                    } else if (pingResultsSection) {
                        pingResultsSection.style.display = 'none';
                    }
                }

                 
                syncCliLog(data.cli_log);
                syncServerLog(data.server_log);

                // Reverse forwards
                if (data.reverse_forwards !== undefined) {
                    reverseForwardsCache = data.reverse_forwards || [];
                    const fwdDrawer2 = document.getElementById('forwards-drawer');
                    if (fwdDrawer2 && fwdDrawer2.classList.contains('open')) {
                        populateReverseForwards(reverseForwardsCache);
                    }
                }

               
                if (data.routing_table !== undefined) {
                    populateRoutingToggleTable(data.routing_table, data.disabled_subnets || {}, data.subnet_owners || {});
                }
    }

    function fetchData() {
        fetch('/api/dashboard-data', { credentials: 'include' })
            .then(response => {
                if (response.redirected) {
                    window.location.href = response.url;
                    return;
                }
                if (!response.ok) throw new Error('Network response was not ok ' + response.statusText);
                return response.json();
            })
            .then(data => { if (data) processData(data); })
            .catch(error => console.error('Error fetching dashboard data:', error));
    }

    let _dashWS = null;
    let _dashWSBackoff = 1000;
    let _dashWSServerShutdown = false;

    function connectDashboardWS() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(`${proto}//${location.host}/api/dashboard-ws`);
        _dashWS = ws;

        ws.onmessage = function(event) {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'shutdown') {
                    _dashWSServerShutdown = true;
                    ws.close();
                   
                    appendLog('Server is shutting down...');
                    const logoutForm = document.querySelector('.logout-form');
                    if (logoutForm) {
                        setTimeout(() => logoutForm.submit(), 1500);
                    }
                    return;
                }
                processData(msg);
                _dashWSBackoff = 1000;
            } catch(e) {
                console.error('Dashboard WS parse error:', e);
            }
        };

        ws.onopen = function() {
            _dashWSBackoff = 1000;
        };

        ws.onclose = function() {
            _dashWS = null;
            if (_dashWSServerShutdown) return; 
            setTimeout(connectDashboardWS, _dashWSBackoff);
            _dashWSBackoff = Math.min(_dashWSBackoff * 2, 30000);
        };

        ws.onerror = function() {
            ws.close();
        };
    }

    
    function formatUptime(diffSec) {
        const h = Math.floor(diffSec / 3600);
        const m = Math.floor((diffSec % 3600) / 60);
        const s = diffSec % 60;
        return h > 0 ? `${h}h ${m}m ${s}s` : m > 0 ? `${m}m ${s}s` : `${s}s`;
    }

    setInterval(function() {
        const now = Date.now();
       
        document.querySelectorAll('td[data-connected-at]').forEach(cell => {
            const connectedAt = parseInt(cell.dataset.connectedAt, 10);
            if (connectedAt) {
                cell.textContent = formatUptime(Math.floor((now - connectedAt) / 1000));
            }
        });
        
        document.querySelectorAll('td[data-last-seen]').forEach(cell => {
            const lastSeen = cell.dataset.lastSeen;
            if (lastSeen) {
                cell.textContent = new Date(lastSeen).toLocaleString();
            }
        });
    }, 1000);

    function disconnectAgent(agentID) {
        if (!agentID) return;
        showConfirm('Disconnect Agent', `Are you sure you want to disconnect agent ${agentID}?`)
            .then(yes => {
                if (!yes) return;

                fetch('/disconnect-agent', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'agentID=' + encodeURIComponent(agentID) + '&csrf_token=' + encodeURIComponent(csrfToken),
                    credentials: 'include'
                })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Network response was not ok ' + response.statusText);
                        }
                        return response.text();
                    })
                    .then(message => {
                        console.log(message);
                        fetchData();
                    })
                    .catch(error => console.error('Error disconnecting agent:', error));
            });
    }

    function deletePortForward(listenerID) {
        if (!listenerID) return;
        showConfirm('Delete Port Forward', 'Are you sure you want to delete this port forward?')
            .then(yes => {
                if (!yes) return;

                fetch('/stop-port-forward', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'listenerID=' + encodeURIComponent(listenerID) + '&csrf_token=' + encodeURIComponent(csrfToken),
                    credentials: 'include'
                })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Network response was not ok ' + response.statusText);
                        }
                        return response.text();
                    })
                    .then(message => {
    appendLog(message)
    portForwardsCache = portForwardsCache.filter(pf => pf.listener_id !== listenerID)
    fetchData()
})


                    .catch(error => console.error('Error deleting port forward:', error));
            });
    }

    function initViewToggle() {
        const viewButtons = document.querySelectorAll('.view-toggle-btn');
        const graphView = document.getElementById('graph-view');
        const tableView = document.getElementById('table-view');
        if (!viewButtons.length || !graphView || !tableView) return;

        function updateCtxButtonsForView(mode) {
            if (!ctxDisconnectBtn) return;
            ctxDisconnectBtn.style.display = (mode === 'graph') ? 'block' : 'none';
        }

        function showGraphView() {
            graphView.classList.add('active');
            tableView.classList.remove('active');
            if (cy) {
                cy.resize(); 
                updateGraph(agentsCache);
                
                if (!graphFitted && graphLayoutDone) {
                    fitGraph();
                    graphFitted = true;
                }
            }
            updateCtxButtonsForView('graph');
        }

        let activeBtn = document.querySelector('.view-toggle-btn.active') || viewButtons[0];
        let mode = activeBtn.dataset.mode;
        if (mode === 'graph') {
            showGraphView();
        } else {
            tableView.classList.add('active');
            graphView.classList.remove('active');
            updateCtxButtonsForView(mode);
        }

        viewButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                viewButtons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');

                const m = btn.dataset.mode;
                if (m === 'graph') {
                    showGraphView();
                } else {
                    tableView.classList.add('active');
                    graphView.classList.remove('active');
                    updateCtxButtonsForView(m);
                }
            });
        });
    }

    function getOsIcon(os) {
        if (!os) return '/static/icons/os-unknown.png';
        if (os.includes('windows')) return '/static/icons/OS_Windows.png';
        if (os.includes('linux'))   return '/static/icons/linux_os.png';
        if (os.includes('darwin') || os.includes('mac')) return '/static/icons/mac-os.png';
        return '/static/icons/os-unknown.png';
    }

    function buildGraphStylesheet(textColor, primaryColor, surfaceColor) {
        return [
            {
                selector: 'node[?isServer]',
                style: {
                    'background-color': primaryColor,
                    'label': 'data(label)',
                    'shape': 'round-rectangle',
                    'color': textColor,
                    'font-weight': 'bold',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'width': 90,
                    'height': 40,
                    'font-size': 13
                }
            },
            {
                selector: 'node.agent',
                style: {
                    'shape': 'round-rectangle',
                    'width': 80,
                    'height': 60,
                    'background-color': surfaceColor,
                    'background-image': 'data(icon)',
                    'background-fit': 'contain',
                    'background-clip': 'none',
                    'background-repeat': 'no-repeat',
                    'background-position-x': '50%',
                    'background-position-y': '35%',
                    'label': 'data(label)',
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'text-margin-y': 2,
                    'color': textColor,
                    'font-size': 10,
                    'text-wrap': 'wrap',
                    'text-max-width': 80,
                    'border-width': 2,
                    'border-color': primaryColor
                }
            },
            {
                selector: 'edge[source = "server"], edge[target = "server"]',
                style: {
                    'width': 2,
                    'line-color': '#FFB6C1',
                    'target-arrow-color': '#FFB6C1',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'line-style': 'solid'
                }
            },
            {
                selector: 'edge[source != "server"][target != "server"]',
                style: {
                    'width': 2,
                    'line-color': '#7DF9C0',
                    'target-arrow-color': '#7DF9C0',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'line-style': 'dashed',
                    'line-dash-pattern': [6, 3],
                    'label': 'data(sharedSubnet)',
                    'font-size': 9,
                    'color': '#7DF9C0',
                    'text-background-color': surfaceColor,
                    'text-background-opacity': 0.8,
                    'text-background-padding': '2px',
                    'text-rotation': 'autorotate'
                }
            }
        ];
    }

    function initGraph() {
        const container = document.getElementById('cy');
        if (!container || !window.cytoscape) return;

        const theme = document.body.getAttribute('data-theme') || 'dark';
        currentGraphTheme = theme;
        const isDark       = (theme === 'dark');
        const textColor    = isDark ? '#F5F5DC' : '#333333';
        const primaryColor = isDark ? '#FFC0CB' : '#FF69B4';
        const surfaceColor = isDark ? '#3E1D40' : '#FFFFFF';

        cy = cytoscape({
            container: container,
            style: buildGraphStylesheet(textColor, primaryColor, surfaceColor),
            layout: { name: 'grid' },
            minZoom: 0.2,
            maxZoom: 2
        });

        cy.on('cxttap', 'node.agent', function (evt) {
            const node = evt.target;
            currentCtxAgent = node.id();
            showAgentContextMenu(
                evt.originalEvent.clientX,
                evt.originalEvent.clientY,
                currentCtxAgent,
                currentCtxAgent
            );
        });

        cy.on('tap', function (evt) {
            if (evt.target === cy) {
                hideAgentContextMenu();
            }
        });
    }

    
    const graphPositions = {};
    let graphLayoutDone = false;
    let graphFitted = false; 

    function fitGraph() {
        cy.fit(undefined, 60);
        if (cy.zoom() > 1.4) {
            cy.zoom(1.4);
            cy.center();
        }
    }

    function updateGraph(agents) {
        if (!cy) return;

        // ── Subnet helpers ──────────────────────────────────────────────────
        const allSubnets = new Set();
        agents.forEach(a => (a.subnets || []).forEach(s => allSubnets.add(s)));

        function getSubnetSet(nodeId) {
            if (nodeId === 'server') return allSubnets;
            const agent = agents.find(a => a.id === nodeId);
            return new Set(agent ? (agent.subnets || []) : []);
        }

        function shareSubnet(idA, idB) {
            const sa = getSubnetSet(idA);
            const sb = getSubnetSet(idB);
            for (const s of sa) { if (sb.has(s)) return true; }
            return false;
        }

        // ── Build edge map ───────────────────────────────────────────
        
        const agentHasPivotPeer = new Set();
        for (let i = 0; i < agents.length; i++) {
            for (let j = i + 1; j < agents.length; j++) {
                if (shareSubnet(agents[i].id, agents[j].id)) {
                    agentHasPivotPeer.add(agents[i].id);
                    agentHasPivotPeer.add(agents[j].id);
                }
            }
        }

        const desiredEdges = new Map();
        function edgeKey(a, b) { return [a, b].sort().join('||'); }
        function wantEdge(src, tgt) {
            const key = edgeKey(src, tgt);
            if (desiredEdges.has(key)) return;
            const sa = getSubnetSet(src);
            const sb = getSubnetSet(tgt);
            const shared = [...sa].filter(s => sb.has(s));
            desiredEdges.set(key, { source: src, target: tgt, sharedSubnet: shared.join(', ') });
        }

        
        for (let i = 0; i < agents.length; i++) {
            for (let j = i + 1; j < agents.length; j++) {
                if (shareSubnet(agents[i].id, agents[j].id)) {
                    wantEdge(agents[i].id, agents[j].id);
                }
            }
        }

       
        agents.forEach(a => {
            if (!agentHasPivotPeer.has(a.id)) {
                wantEdge('server', a.id);
            }
        });

       
        if (agents.length > 0) {
            const serverHasEdge = [...desiredEdges.values()].some(
                e => e.source === 'server' || e.target === 'server'
            );
            if (!serverHasEdge) {
                wantEdge('server', agents[0].id);
            }
        }

        // ── Snapshot current graph state ─────────────────────────────────────
        const currentNodeIds = new Set(cy.nodes().map(n => n.id()));
        const currentEdgeIds = new Set(cy.edges().map(e => e.id()));
        const desiredNodeIds  = new Set(['server', ...agents.map(a => a.id)]);

        // ── Ensure server node ───────────────────────────────────────────────
        if (!currentNodeIds.has('server')) {
            cy.add({ group: 'nodes', data: { id: 'server', label: 'Server', isServer: true } });
        }

        // ── Update existing agent data, collect truly new nodes ──────────────
        const newNodes = [];
        agents.forEach(a => {
            const subnetLabel = (a.subnets || []).join('\n');
            const lbl = a.id + (subnetLabel ? '\n' + subnetLabel : '');
            if (currentNodeIds.has(a.id)) {
               
                const n = cy.getElementById(a.id);
                n.data('label', lbl);
                n.data('icon',  getOsIcon(a.os || ''));
                n.data('subnets', (a.subnets || []).join(','));
            } else {
                newNodes.push({ id: a.id, label: lbl, os: a.os || '', subnets: a.subnets || [] });
            }
        });

        // ── Remove disconnected nodes  ────────────
        currentNodeIds.forEach(id => {
            if (!desiredNodeIds.has(id)) {
                const n = cy.getElementById(id);
                if (n.length) { graphPositions[id] = { ...n.position() }; n.remove(); }
            }
        });

        
        newNodes.forEach(nd => {
            const subnetLabel = (nd.subnets || []).join('\n');
            const added = cy.add({
                group: 'nodes',
                data: {
                    id: nd.id,
                    label: nd.id + (subnetLabel ? '\n' + subnetLabel : ''),
                    icon: getOsIcon(nd.os),
                    subnets: (nd.subnets || []).join(',')
                },
                classes: 'agent'
            });
            if (graphPositions[nd.id]) added.position({ ...graphPositions[nd.id] });
        });

        // ── Sync edges ───────────────────────────────────────────────────────
        desiredEdges.forEach((edata, key) => {
            if (!currentEdgeIds.has(key)) {
                cy.add({ group: 'edges', data: { id: key, source: edata.source, target: edata.target, sharedSubnet: edata.sharedSubnet } });
            }
        });
        currentEdgeIds.forEach(id => {
            if (!desiredEdges.has(id)) cy.getElementById(id).remove();
        });

        // ── Layout ──────────────────────────────────────────────────────────
        if (!graphLayoutDone) {
            
            const layout = cy.layout({
                name: 'cose',
                animate: false,
                randomize: true,
                nodeRepulsion: 9000,
                idealEdgeLength: 150,
                edgeElasticity: 100,
                gravity: 0.25,
                numIter: 1200,
                coolingFactor: 0.99,
                padding: 60
            });
            layout.run();
            
            cy.nodes().forEach(n => { graphPositions[n.id()] = { ...n.position() }; });
            graphLayoutDone = true;
            
            const graphPanel = document.getElementById('graph-view');
            if (graphPanel && graphPanel.classList.contains('active')) {
                cy.resize();
                fitGraph();
                graphFitted = true;
            }

        } else if (newNodes.length > 0) {
            
            newNodes.forEach(nd => {
                const newNode = cy.getElementById(nd.id);
                if (!newNode.length) return;

                
                const neighbours = newNode.neighborhood('node').filter(
                    n => graphPositions[n.id()]
                );

                let refPos;
                if (neighbours.length > 0) {
                   
                    const ref = graphPositions[neighbours[0].id()];
                    const angle = Math.random() * 2 * Math.PI;
                    const dist  = 180 + Math.random() * 60;
                    refPos = { x: ref.x + Math.cos(angle) * dist,
                               y: ref.y + Math.sin(angle) * dist };
                } else {
                    
                    const srv = graphPositions['server'] || { x: 0, y: 0 };
                    const angle = Math.random() * 2 * Math.PI;
                    refPos = { x: srv.x + Math.cos(angle) * 200,
                               y: srv.y + Math.sin(angle) * 200 };
                }

                newNode.position(refPos);
                graphPositions[nd.id] = { ...refPos };
            });
        }
        
    }

    const ctxMenu = document.getElementById('agent-context-menu');
    const ctxAgentLabel = document.getElementById('ctx-agent-label');
    const ctxPfBtn = document.getElementById('ctx-port-forward-btn');
    const ctxPingBtn = document.getElementById('ctx-ping-btn');
    const ctxScanBtn = document.getElementById('ctx-port-scan-btn');
    const ctxViewForwardsBtn = document.getElementById('ctx-view-forwards-btn');
    const ctxDisconnectBtn = document.getElementById('ctx-disconnect-btn');

    const pfModal = document.getElementById('portforward-modal');
    const pfModalForm = document.getElementById('portforward-modal-form');
    const pfModalAgent = document.getElementById('pf-modal-agent');
    const pfModalListenPort = document.getElementById('pf-modal-listen-port');
    const pfModalTargetHost = document.getElementById('pf-modal-target-host');
    const pfModalTargetPort = document.getElementById('pf-modal-target-port');
    const pfModalCancel = document.getElementById('pf-modal-cancel');
    const pfModalProtocol = document.getElementById('pf-modal-protocol');

    const pingModal = document.getElementById('ping-modal');
    const pingModalForm = document.getElementById('ping-modal-form');
    const pingModalAgent = document.getElementById('ping-modal-agent');
    const pingModalTarget = document.getElementById('ping-modal-target');
    const pingModalCount = document.getElementById('ping-modal-count');
    const pingModalCancel = document.getElementById('ping-modal-cancel');

    const portscanModal = document.getElementById('portscan-modal');
    const portscanModalForm = document.getElementById('portscan-modal-form');
    const portscanModalAgent = document.getElementById('ps-modal-agent');
    const portscanModalTarget = document.getElementById('ps-modal-target');
    const portscanModalPorts = document.getElementById('ps-modal-ports');
    const portscanModalProto = document.getElementById('ps-modal-proto');
    const portscanModalCancel = document.getElementById('ps-modal-cancel');

    const ctxReconnectBtn = document.getElementById('ctx-reconnect-btn');



    const TAG_ICON_SVG = (theme) => `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" id="tags" style="width: 16px; height: 16px; margin-right: 6px; vertical-align: middle; fill: var(--primary-color); stroke: var(--primary-color);">
    <path d="M420.64 265.066 203.759 48.761a17.233 17.233 0 0 0-12.133-5.039l-174.31-.575h-.058a17.248 17.248 0 0 0-12.202 5.057A17.252 17.252 0 0 0 0 60.462l.575 174.304a17.239 17.239 0 0 0 5.039 12.133L221.92 463.78a17.244 17.244 0 0 0 12.207 5.074h.012c4.579 0 8.969-1.818 12.208-5.057l174.31-174.31a17.213 17.213 0 0 0 5.057-12.213 17.282 17.282 0 0 0-5.074-12.208zM234.157 427.175 35.069 227.552 34.574 77.72l149.832.495 199.622 199.087-149.871 149.873z"></path>
    <path d="M125.411 125.411c-23.794 0-43.146 19.352-43.146 43.146s19.352 43.146 43.146 43.146 43.146-19.352 43.146-43.146c0-23.793-19.352-43.146-43.146-43.146zm0 51.776c-4.758 0-8.629-3.872-8.629-8.629s3.872-8.629 8.629-8.629c4.758 0 8.629 3.872 8.629 8.629s-3.871 8.629-8.629 8.629zm381.515 87.879L290.045 48.761c-6.748-6.737-17.678-6.719-24.403.029-6.731 6.754-6.719 17.678.034 24.409l204.645 204.104L308.23 439.394c-6.742 6.737-6.742 17.667 0 24.403 3.371 3.371 7.784 5.057 12.202 5.057s8.831-1.686 12.202-5.057l174.31-174.31a17.217 17.217 0 0 0 5.057-12.213 17.273 17.273 0 0 0-5.075-12.208z"></path>
</svg>
`;

function showAgentContextMenu(x, y, agentId, label) {
    if (!ctxMenu) return;

    ctxAgentLabel.textContent = label || agentId;

    const agent = agentsCache.find(a => a.id === agentId);
    const ctxTagDisplay = document.getElementById('ctx-tag-display');
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';

    if (ctxTagDisplay) {
        if (agent && agent.tag) {
            ctxTagDisplay.innerHTML = TAG_ICON_SVG(currentTheme) + agent.tag;
        } else {
            ctxTagDisplay.innerHTML = '';
        }
    }

    ctxMenu.style.display = 'block';
    ctxMenu.style.left = x + 'px';
    ctxMenu.style.top = y + 'px';
}

    function hideAgentContextMenu() {
        if (!ctxMenu) return;
        ctxMenu.style.display = 'none';
    }

    document.addEventListener('click', function (e) {
        if (!ctxMenu) return;
        if (!ctxMenu.contains(e.target)) {
            hideAgentContextMenu();
        }
    });

    if (ctxPfBtn) {
        ctxPfBtn.addEventListener('click', function () {
            hideAgentContextMenu();
            if (!currentCtxAgent || !pfModal || !backdrop) return;
            pfModalAgent.value = currentCtxAgent;
            pfModalListenPort.value = '';
            pfModalTargetHost.value = '';
            pfModalTargetPort.value = '';
            if (pfModalProtocol) pfModalProtocol.value = 'tcp';
            backdrop.style.display = 'block';
            pfModal.style.display = 'block';
        });
    }

    if (pfModalCancel) {
        pfModalCancel.addEventListener('click', closeAllModals);
    }

    if (pfModalForm) {
        pfModalForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const agentId = pfModalAgent.value;
            const listenPort = pfModalListenPort.value.trim();
            const host = pfModalTargetHost.value.trim();
            const port = pfModalTargetPort.value.trim();
            const protocol = pfModalProtocol ? pfModalProtocol.value : 'tcp';
            if (!agentId || !listenPort || !host || !port) {
                showMessage('Validation', 'Fill all fields.');
                return;
            }

            const body =
                'agentListenPort=' + encodeURIComponent(listenPort) +
                '&destinationAgentID=' + encodeURIComponent(agentId) +
                '&destinationHost=' + encodeURIComponent(host) +
                '&destinationPort=' + encodeURIComponent(port) +
                '&protocol=' + encodeURIComponent(protocol) +
                '&csrf_token=' + encodeURIComponent(csrfToken);

            fetch('/port-forward', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: body,
                credentials: 'include'
            })
                .then(r => {
                    if (!r.ok) {
                        throw new Error('Network response was not ok ' + r.statusText);
                    }
                    return r.text();
                })
                .then(text => {
                    
                    appendLog(text);
                    const sle = document.getElementById('server-log-output');
                    if (sle) {
                        renderServerLogEntry(
                            new Date().toISOString().replace('T',' ').slice(0,19).replace(/-/g,'/') +
                            ' [+] Port forward added: ' + pfModalAgent.value +
                            ' ' + (pfModalProtocol ? pfModalProtocol.value.toUpperCase() : 'TCP') +
                            ' :' + pfModalListenPort.value.trim() +
                            ' → ' + pfModalTargetHost.value.trim() + ':' + pfModalTargetPort.value.trim(),
                            sle);
                        sle.scrollTop = sle.scrollHeight;
                    }
                    fetchData();
                    closeAllModals();
                })
                .catch(err => {
                    console.error('Error adding port forward:', err);
                    closeAllModals();
                });
        });
    }

    if (ctxPingBtn) {
        ctxPingBtn.addEventListener('click', function () {
            hideAgentContextMenu();
            if (!currentCtxAgent || !pingModal || !backdrop) return;
            pingModalAgent.value = currentCtxAgent;
            pingModalTarget.value = '';
            pingModalCount.value = '4';
            backdrop.style.display = 'block';
            pingModal.style.display = 'block';
        });
    }

    if (pingModalCancel) {
        pingModalCancel.addEventListener('click', closeAllModals);
    }

    if (pingModalForm) {
        pingModalForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const agentId = pingModalAgent.value;
            const target = pingModalTarget.value.trim();
            const count = pingModalCount.value.trim() || '4';
            if (!agentId || !target) {
                showMessage('Validation', 'Enter target.');
                return;
            }

            const cmd = `ping ${agentId} ${target} ${count}`;
            appendLog('rosemary> ' + cmd);

            fetch('/api/cli', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'cmd=' + encodeURIComponent(cmd) + '&csrf_token=' + encodeURIComponent(csrfToken),
                credentials: 'include'
            })
                .then(r => r.text())
                .then(text => {
                    appendLog(text);
                })
                .catch(err => {
                    appendLog('Error: ' + err);
                });

            closeAllModals();
        });
    }

    if (ctxScanBtn) {
        ctxScanBtn.addEventListener('click', function () {
            hideAgentContextMenu();
            if (!currentCtxAgent || !portscanModal || !backdrop) return;
            portscanModalAgent.value = currentCtxAgent;
            portscanModalTarget.value = '';
            portscanModalPorts.value = '80,443';
            portscanModalProto.value = 'tcp';
            backdrop.style.display = 'block';
            portscanModal.style.display = 'block';
        });
    }

    if (ctxDisconnectBtn) {
        ctxDisconnectBtn.addEventListener('click', function () {
            hideAgentContextMenu();
            if (!currentCtxAgent) return;
            disconnectAgent(currentCtxAgent);
        });
    }
    
    if (ctxReconnectBtn) {
    ctxReconnectBtn.addEventListener('click', function () {
        hideAgentContextMenu();
        if (!currentCtxAgent) return;
        const cmd = `reconnect ${currentCtxAgent}`;
        appendLog('rosemary> ' + cmd);
        const sle = document.getElementById('server-log-output');
        if (sle) {
            renderServerLogEntry(
                new Date().toISOString().replace('T',' ').slice(0,19).replace(/-/g,'/') +
                ' [+] Reconnect requested for agent ' + currentCtxAgent, sle);
            sle.scrollTop = sle.scrollHeight;
        }
        fetch('/api/cli', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'cmd=' + encodeURIComponent(cmd) + '&csrf_token=' + encodeURIComponent(csrfToken),
            credentials: 'include'
        }).then(r => r.text()).then(text => appendLog(text))
          .catch(err => appendLog('Error: ' + err));
    });
}

    // ── Reverse forward context menu ──────────────────────────────────────
    const rfModal     = document.getElementById('rforward-modal');
    const rfModalForm = document.getElementById('rforward-modal-form');
    const rfModalAgent      = document.getElementById('rf-modal-agent');
    const rfModalListenPort = document.getElementById('rf-modal-listen-port');
    const rfModalTargetHost = document.getElementById('rf-modal-target-host');
    const rfModalTargetPort = document.getElementById('rf-modal-target-port');
    const rfModalCancel     = document.getElementById('rf-modal-cancel');
    const ctxRfBtn          = document.getElementById('ctx-rforward-btn');

    if (ctxRfBtn) {
        ctxRfBtn.addEventListener('click', function () {
            hideAgentContextMenu();
            if (!currentCtxAgent || !rfModal || !backdrop) return;
            rfModalAgent.value      = currentCtxAgent;
            rfModalListenPort.value = '';
            rfModalTargetHost.value = '127.0.0.1';
            rfModalTargetPort.value = '';
            backdrop.style.display = 'block';
            rfModal.style.display  = 'block';
        });
    }
    if (rfModalCancel) rfModalCancel.addEventListener('click', closeAllModals);

    if (rfModalForm) {
        rfModalForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const agentId     = rfModalAgent.value;
            const listenPort  = rfModalListenPort.value.trim();
            const targetHost  = rfModalTargetHost.value.trim();
            const targetPort  = rfModalTargetPort.value.trim();
            if (!agentId || !listenPort || !targetHost || !targetPort) {
                showMessage('Validation', 'Fill all fields.');
                return;
            }
            const body =
                'action=add' +
                '&agentID='     + encodeURIComponent(agentId) +
                '&listenPort='  + encodeURIComponent(listenPort) +
                '&targetHost='  + encodeURIComponent(targetHost) +
                '&targetPort='  + encodeURIComponent(targetPort) +
                '&csrf_token='  + encodeURIComponent(csrfToken);
            fetch('/api/reverse-forward', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body, credentials: 'include'
            }).then(r => r.text()).then(text => {
                appendLog(text);
                const sle = document.getElementById('server-log-output');
                if (sle) {
                    renderServerLogEntry(
                        new Date().toISOString().replace('T',' ').slice(0,19).replace(/-/g,'/') +
                        ' [+] Reverse forward added: server :' + listenPort +
                        ' → agent ' + agentId + ' → ' + targetHost + ':' + targetPort, sle);
                    sle.scrollTop = sle.scrollHeight;
                }
                fetchData();
                closeAllModals();
            }).catch(err => { appendLog('Error: ' + err); closeAllModals(); });
        });
    }

    // ── Tag modal ──────────────────────────────────────────────────────────────
    const tagModal       = document.getElementById('tag-modal');
    const tagModalLabel  = document.getElementById('tag-modal-agent-label');
    const tagModalInput  = document.getElementById('tag-modal-input');
    const tagModalError  = document.getElementById('tag-modal-error');
    const tagModalSave   = document.getElementById('tag-modal-save');
    const tagModalClear  = document.getElementById('tag-modal-clear');
    const tagModalCancel = document.getElementById('tag-modal-cancel');
    const ctxSetTagBtn   = document.getElementById('ctx-set-tag-btn');

    function isValidTag(t) {
        return t.length <= 64 && /^[^\x00-\x1f<>&"']*$/.test(t);
    }

    function openTagModal() {
        if (!currentCtxAgent || !tagModal || !backdrop) return;
        hideAgentContextMenu();
        const agent = agentsCache.find(a => a.id === currentCtxAgent);
        tagModalLabel.textContent = currentCtxAgent;
        tagModalInput.value = (agent && agent.tag) ? agent.tag : '';
        tagModalError.textContent = '';
        backdrop.style.display = 'block';
        tagModal.style.display = 'block';
        tagModalInput.focus();
    }

    function closeTagModal() {
        if (tagModal) tagModal.style.display = 'none';
        if (backdrop) backdrop.style.display = 'none';
    }

    async function submitTag(tagValue) {
        const agentID = currentCtxAgent;
        if (!agentID) return;
        if (tagValue !== '' && !isValidTag(tagValue)) {
            tagModalError.textContent = 'Invalid characters in tag.';
            return;
        }
        const body = 'agentID=' + encodeURIComponent(agentID) +
                     '&tag='     + encodeURIComponent(tagValue) +
                     '&csrf_token=' + encodeURIComponent(csrfToken);
        try {
            const r = await fetch('/api/set-tag', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body,
                credentials: 'include'
            });
            if (!r.ok) {
                const txt = await r.text();
                tagModalError.textContent = 'Error: ' + txt;
                return;
            }
            closeTagModal();
        } catch (err) {
            tagModalError.textContent = 'Network error.';
        }
    }

    if (ctxSetTagBtn)   ctxSetTagBtn.addEventListener('click',   openTagModal);
    if (tagModalCancel) tagModalCancel.addEventListener('click',  closeTagModal);
    if (tagModalClear)  tagModalClear.addEventListener('click',   () => submitTag(''));
    if (tagModalSave)   tagModalSave.addEventListener('click',    () => submitTag(tagModalInput.value.trim()));
    if (tagModalInput)  tagModalInput.addEventListener('keydown', e => {
        if (e.key === 'Enter')  submitTag(tagModalInput.value.trim());
        if (e.key === 'Escape') closeTagModal();
    });
    // ── End tag modal ──────────────────────────────────────────────────────────

    if (portscanModalCancel) {
        portscanModalCancel.addEventListener('click', closeAllModals);
    }

    if (portscanModalForm) {
        portscanModalForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const agentId = portscanModalAgent.value;
            const target = portscanModalTarget.value.trim();
            const ports = portscanModalPorts.value.trim() || '80,443';
            const proto = portscanModalProto.value || 'tcp';
            if (!agentId || !target || !ports) {
                showMessage('Validation', 'Enter target and ports.');
                return;
            }

            const cmd = `portscan ${agentId} ${proto} ${target} ${ports}`;
            appendLog('rosemary> ' + cmd);

            fetch('/api/cli', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'cmd=' + encodeURIComponent(cmd) + '&csrf_token=' + encodeURIComponent(csrfToken),
                credentials: 'include'
            })
                .then(r => r.text())
                .then(text => {
                    appendLog(text);
                })
                .catch(err => {
                    appendLog('Error: ' + err);
                });

            closeAllModals();
        });
    }


const connectBindBtn = document.getElementById('connect-bind-btn');
const connectBindModal = document.getElementById('connect-bind-modal');
const connectBindForm = document.getElementById('connect-bind-form');
const bindModalCancel = document.getElementById('bind-modal-cancel');

if (connectBindBtn) {
    connectBindBtn.addEventListener('click', function() {
        document.getElementById('bind-modal-host').value = '';
        document.getElementById('bind-modal-port').value = '';
        backdrop.style.display = 'block';
        connectBindModal.style.display = 'block';
    });
}

if (bindModalCancel) {
    bindModalCancel.addEventListener('click', closeAllModals);
}

if (connectBindForm) {
    connectBindForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const host = document.getElementById('bind-modal-host').value.trim();
        const port = document.getElementById('bind-modal-port').value.trim();
        if (!host || !port) {
            showMessage('Validation', 'Enter host and port.');
            return;
        }
        const body = 'host=' + encodeURIComponent(host) + 
                    '&port=' + encodeURIComponent(port) + 
                    '&csrf_token=' + encodeURIComponent(csrfToken);
        fetch('/api/connect-bind', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body,
            credentials: 'include'
        })
        .then(r => r.text())
        .then(text => {
            appendLog(text);
            closeAllModals();
        })
        .catch(err => appendLog('Error: ' + err));
    });
}

const shutdownBtn = document.getElementById('shutdown-btn');
if (shutdownBtn) {
    shutdownBtn.addEventListener('click', function() {
        showConfirm('Shutdown Server', 'Are you sure you want to shutdown the server? This will disconnect all agents.')
        .then(yes => {
            if (!yes) return;
            
            appendLog('Shutdown initiated...'); 
            
            
            const body = 'csrf_token=' + encodeURIComponent(csrfToken);
            fetch('/api/shutdown', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: body,
                credentials: 'include'
            }).then(r => r.text())
              .then(text => appendLog('API: ' + text))  
              .catch(() => appendLog('API sent'));
            
            
            setTimeout(() => {
                appendLog('shutting down...');
                document.querySelector('.logout-form').submit();
            }, 2000);
        });
    });
}





    function closeAllModals() {
        if (backdrop) backdrop.style.display = 'none';
        if (pfModal) pfModal.style.display = 'none';
        if (pingModal) pingModal.style.display = 'none';
        if (portscanModal) portscanModal.style.display = 'none';
        if (msgModal) msgModal.style.display = 'none';
        if (confirmModal) confirmModal.style.display = 'none';
        if (connectBindModal) connectBindModal.style.display = 'none';
        const rfModal = document.getElementById('rforward-modal');
        if (rfModal) rfModal.style.display = 'none';
        const settingsModal = document.getElementById('settings-modal');
        if (settingsModal) settingsModal.style.display = 'none';
    }

function initCLI() {
    const input = document.getElementById('cli-input');
    if (!input) return;

    const history = [];
    let historyIndex = -1;

    input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            const cmd = this.value.trim();
            if (!cmd) return;

            appendLog('rosemary> ' + cmd);
            history.push(cmd);
            historyIndex = history.length;  
            this.value = '';

            fetch('/api/cli', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'cmd=' + encodeURIComponent(cmd) + '&csrf_token=' + encodeURIComponent(csrfToken),
                credentials: 'include'
            })
                .then(r => r.text())
                .then(text => appendLog(text))
                .catch(err => appendLog('Error: ' + err));
        } else if (e.key === 'ArrowUp') {
            if (history.length === 0) return;
            if (historyIndex > 0) historyIndex--;
            input.value = history[historyIndex];
            e.preventDefault();
        } else if (e.key === 'ArrowDown') {
            if (history.length === 0) return;
            if (historyIndex < history.length - 1) {
                historyIndex++;
                input.value = history[historyIndex];
            } else {
                historyIndex = history.length;
                input.value = '';
            }
            e.preventDefault();
        }
    });
}


// ── Timeline log ──────────────────────────────────────────────────────────
const logEntries = [];  


function ansiToHtml(text) {
    
    const ESC = '\x1b';
    const ansiMap = {
        [ESC+'[0m']:  '</span>',
        [ESC+'[1m']:  '<span class="ansi-bold">',
        [ESC+'[2m']:  '<span class="ansi-dim">',
        
        [ESC+'[38;2;224;82;82m']:   '<span class="ansi-red">',
        [ESC+'[38;2;46;204;113m']:  '<span class="ansi-green">',
        [ESC+'[38;2;255;192;203m']: '<span class="ansi-yellow">',
        [ESC+'[38;2;95;158;160m']:  '<span class="ansi-cyan">',
        [ESC+'[1;38;2;224;82;82m']:   '<span class="ansi-bold-red">',
        [ESC+'[1;38;2;46;204;113m']:  '<span class="ansi-bold-green">',
        [ESC+'[1;38;2;219;112;147m']: '<span class="ansi-bold-yellow">',
        [ESC+'[1;38;2;95;158;160m']:  '<span class="ansi-bold-cyan">',
        [ESC+'[1;38;2;245;245;220m']: '<span class="ansi-bold-white">',
    };

    let html = text;

    
    const placeholders = {};
    let placeholderIndex = 0;
    for (const [code, replacement] of Object.entries(ansiMap)) {
        const placeholder = `__ANSI_${placeholderIndex}__`;
        placeholders[placeholder] = replacement;
        html = html.replaceAll(code, placeholder);
        placeholderIndex++;
    }

   
    html = html.replace(/&/g, '&amp;')
               .replace(/</g, '&lt;')
               .replace(/>/g, '&gt;')
               .replace(/"/g, '&quot;')
               .replace(/'/g, '&#039;');

    
    for (const [placeholder, replacement] of Object.entries(placeholders)) {
        html = html.replaceAll(placeholder, replacement);
    }

    return html;
}

function appendLog(line) {
    const el = document.getElementById('logs-output');
    if (!el) return;
    const formatted = line.replace(/\\n/g, '\n');
    const div = document.createElement('div');
    div.innerHTML = ansiToHtml(formatted);
    el.appendChild(div);
    el.scrollTop = el.scrollHeight;
}


function syncCliLog(serverLines) {
    if (!serverLines || !serverLines.length) return;
    if (serverLines.length <= lastDisplayedLogCount) return;
    for (let i = lastDisplayedLogCount; i < serverLines.length; i++) {
        appendLog(serverLines[i]);
    }
    lastDisplayedLogCount = serverLines.length;
}

// ── Server event timeline  ───────────────────────────
let lastServerLogCount = 0;

function renderServerLogEntry(text, el) {
    const meta = kindMeta[classifyLogKind(text)] || kindMeta.info;

    const row = document.createElement('div');
    row.className = 'log-row log-kind-' + classifyLogKind(text);

    // Parse timestamp from Go log format "2006/01/02 15:04:05 message"
    const goLogRe = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) (.+)$/;
    const m = text.match(goLogRe);
    const tsText = m ? m[1].split(' ')[1] : new Date().toLocaleTimeString('en-GB', { hour12: false });
    const msgText = m ? m[2] : text;

    const tsEl = document.createElement('span');
    tsEl.className = 'log-ts';
    tsEl.textContent = tsText;

    const badgeEl = document.createElement('span');
    badgeEl.className = 'log-badge';
    badgeEl.textContent = meta.label;

    const iconEl = document.createElement('span');
    iconEl.className = 'log-icon';
    iconEl.textContent = meta.icon;

    const textEl = document.createElement('span');
    textEl.className = 'log-text';
    textEl.innerHTML = ansiToHtml(msgText);

    row.appendChild(tsEl);
    row.appendChild(badgeEl);
    row.appendChild(iconEl);
    row.appendChild(textEl);
    el.appendChild(row);
}

function syncServerLog(serverLines) {
    if (!serverLines || !serverLines.length) return;
    _updateServerLinesMirror(serverLines);
    if (serverLines.length <= lastServerLogCount) return;
    const el = document.getElementById('server-log-output');
    if (!el) { lastServerLogCount = serverLines.length; return; }
    for (let i = lastServerLogCount; i < serverLines.length; i++) {
        const l = serverLines[i].trim();
        if (!l) continue;
        renderServerLogEntry(l, el);
    }
    lastServerLogCount = serverLines.length;
    el.scrollTop = el.scrollHeight;
}

const menuToggle = document.getElementById('header-menu-toggle');
const dropdown = document.getElementById('header-menu-dropdown');

if (menuToggle && dropdown) {
    menuToggle.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdown.classList.toggle('open');
    });

    document.addEventListener('click', () => {
        dropdown.classList.remove('open');
    });

    dropdown.addEventListener('click', (e) => {
        e.stopPropagation();
    });
}


    window.showConfirm = showConfirm;

initViewToggle();
initGraph();
initCLI();
initDrawers();

connectDashboardWS();
});

// ── Log export helpers (global scope) ────────────────────────────────────
let _allServerLines = [];

function _updateServerLinesMirror(serverLines) {
    if (serverLines && serverLines.length > _allServerLines.length) {
        _allServerLines = serverLines.slice();
    }
}

function exportLogsAsCSV() {
    const goLogRe = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) (.+)$/;
    const rows = [['timestamp', 'kind', 'message']];
    _allServerLines.forEach(function(line) {
        var m = line.match(goLogRe);
        var ts = m ? m[1] : new Date().toISOString();
        var msg = m ? m[2] : line;
        var kind = classifyLogKind(msg);
        rows.push([ts, kind, msg.replace(/"/g, '""')]);
    });
    var csv = rows.map(function(r) { return r.map(function(v) { return '"' + v + '"'; }).join(','); }).join('\n');
    _downloadLogFile('logs_' + _logFilestamp() + '.csv', csv, 'text/csv');
}

function exportLogsAsJSON() {
    const goLogRe = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) (.+)$/;
    var entries = _allServerLines.map(function(line) {
        var m = line.match(goLogRe);
        return { timestamp: m ? m[1] : '', kind: classifyLogKind(m ? m[2] : line), message: m ? m[2] : line };
    });
    _downloadLogFile('logs_' + _logFilestamp() + '.json', JSON.stringify(entries, null, 2), 'application/json');
}

function _logFilestamp() {
    var d = new Date();
    var p = function(n) { return String(n).padStart(2, '0'); };
    return d.getFullYear() + p(d.getMonth()+1) + p(d.getDate()) + '_' + p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
}

function _downloadLogFile(filename, content, mime) {
    var blob = new Blob([content], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
}

// ── Log classification (global — used by export helpers and timeline) ─────
function classifyLogKind(text) {
    const t = text.toLowerCase();
    if (t.startsWith('rosemary>'))                                          return 'cmd';
    if (t.includes('agent connected') || t.includes('assigned id'))      return 'connect';
    if (t.includes('disconnected') || t.includes('connection lost'))     return 'disconnect';
    if (t.includes('port forward') || t.includes('socks5'))              return 'forward';
    if (t.includes('error') || t.includes('failed') || t.includes('[-]')) return 'error';
    if (t.includes('[+]') || t.includes('success') || t.includes('started')) return 'success';
    if (t.includes('scan') || t.includes('ping'))                        return 'scan';
    return 'info';
}

const kindMeta = {
    cmd:        { icon: '>',   label: 'CMD'  },
    connect:    { icon: '[+]', label: 'CONN' },
    disconnect: { icon: '[-]', label: 'DISC' },
    forward:    { icon: '[~]', label: 'FWD'  },
    error:      { icon: '[!]', label: 'ERR'  },
    success:    { icon: '[+]', label: 'OK'   },
    scan:       { icon: '[*]', label: 'SCAN' },
    info:       { icon: '[i]', label: 'INFO' },
};

function initCliToolbar() {
     
}

function initDrawers() {
    const drawerBackdrop = document.getElementById('drawer-backdrop');

    function openDrawer(drawerId) {
        document.querySelectorAll('.side-drawer').forEach(d => d.classList.remove('open'));
        const drawer = document.getElementById(drawerId);
        if (drawer) drawer.classList.add('open');
        if (drawerBackdrop) drawerBackdrop.style.display = 'block';
        document.getElementById('header-menu-dropdown').classList.remove('open');
    }

    function closeAllDrawers() {
        document.querySelectorAll('.side-drawer').forEach(d => d.classList.remove('open'));
        if (drawerBackdrop) drawerBackdrop.style.display = 'none';
    }

     
    if (drawerBackdrop) drawerBackdrop.addEventListener('click', closeAllDrawers);

     
    const fwdClose = document.getElementById('forwards-drawer-close');
    if (fwdClose) fwdClose.addEventListener('click', closeAllDrawers);
    const logsClose = document.getElementById('logs-drawer-close');
    if (logsClose) logsClose.addEventListener('click', closeAllDrawers);
    const routingClose = document.getElementById('routing-drawer-close');
    if (routingClose) routingClose.addEventListener('click', closeAllDrawers);

    // ── Header menu: All Forwards ─────────────────────────────────────────
    const allFwdBtn = document.getElementById('all-forwards-menu-btn');
    if (allFwdBtn) {
        allFwdBtn.addEventListener('click', function () {
            populateAllForwards(portForwardsCache);
            populateReverseForwards(reverseForwardsCache);
            openDrawer('forwards-drawer');
        });
    }

    // ── Header menu: Routing Table ────────────────────────────────────────
    const routingBtn = document.getElementById('routing-menu-btn');
    if (routingBtn) {
        routingBtn.addEventListener('click', function () {
            fetch('/api/subnet-status', { credentials: 'include' })
                .then(r => r.json())
                .then(d => {
                    fetch('/api/dashboard-data', { credentials: 'include' })
                        .then(r => r.json())
                        .then(dd => {
                            populateRoutingToggleTable(
                                dd.routing_table || {},
                                d.disabled || {},
                                d.owners || {}
                            );
                        }).catch(() => {});
                }).catch(() => {});
            openDrawer('routing-drawer');
            document.getElementById('header-menu-dropdown').classList.remove('open');
        });
    }

     
    const logsBtn = document.getElementById('logs-menu-btn');
    if (logsBtn) {
        logsBtn.addEventListener('click', function () {
            openDrawer('logs-drawer');
            const logsOutput = document.getElementById('logs-output');
            if (logsOutput) logsOutput.scrollTop = logsOutput.scrollHeight;
        });
    }

     
    const filterInput = document.getElementById('log-filter');
    if (filterInput) {
        filterInput.addEventListener('input', function () {
            const q = this.value.trim().toLowerCase();
            const serverLogEl = document.getElementById('server-log-output');
            if (!serverLogEl) return;
            serverLogEl.querySelectorAll('.log-row').forEach(row => {
                const text = row.querySelector('.log-text');
                row.style.display = (!q || (text && text.textContent.toLowerCase().includes(q))) ? '' : 'none';
            });
        });
    }

     
    const clearBtn = document.getElementById('log-clear-btn');
    if (clearBtn) {
        clearBtn.addEventListener('click', function () {
            const serverLogEl = document.getElementById('server-log-output');
            if (serverLogEl) serverLogEl.innerHTML = '';
            lastServerLogCount = 0;
        });
    }

    
    const exportBtn = document.getElementById('log-export-btn');
    const exportDropdown = document.getElementById('log-export-dropdown');
    if (exportBtn) {
        exportBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            const dd = document.getElementById('log-export-dropdown');
            if (dd) dd.style.display = dd.style.display === 'none' ? 'block' : 'none';
        });
    }
    document.addEventListener('click', function () {
        const dd = document.getElementById('log-export-dropdown');
        if (dd) dd.style.display = 'none';
    });
    if (exportDropdown) {
        exportDropdown.addEventListener('click', function (e) { e.stopPropagation(); });
    }
    const csvBtn = document.getElementById('log-export-csv');
    if (csvBtn) {
        csvBtn.addEventListener('click', function () {
            const dd = document.getElementById('log-export-dropdown');
            if (dd) dd.style.display = 'none';
            exportLogsAsCSV();
        });
    }
    const jsonBtn = document.getElementById('log-export-json');
    if (jsonBtn) {
        jsonBtn.addEventListener('click', function () {
            const dd = document.getElementById('log-export-dropdown');
            if (dd) dd.style.display = 'none';
            exportLogsAsJSON();
        });
    }
}

function populateAllForwards(forwards) {
    const tbody = document.getElementById('all-forwards-tbody');
    const empty = document.getElementById('all-forwards-empty');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (!forwards || forwards.length === 0) {
        if (empty) empty.style.display = 'block';
        return;
    }
    if (empty) empty.style.display = 'none';

    forwards.forEach(pf => {
        const row = tbody.insertRow();
        const isSocks = !pf.destination_host && !pf.destination_port;

        const portCell = row.insertCell();
        portCell.textContent = ':' + pf.agent_listen_port;
        if (isSocks) {
            const badge = document.createElement('span');
            badge.textContent = ' SOCKS5';
            badge.style.cssText = 'font-size:10px;background:var(--primary-color);color:#fff;border-radius:3px;padding:1px 4px;margin-left:4px;vertical-align:middle;';
            portCell.appendChild(badge);
        }

        const protoCell = row.insertCell();
        protoCell.textContent = isSocks ? 'TCP' : (pf.protocol || 'tcp').toUpperCase();
        protoCell.style.fontWeight = '600';
        protoCell.style.color = (!isSocks && pf.protocol === 'udp') ? 'var(--warning-color,#f0a500)' : 'var(--primary-color)';

        const agentCell = row.insertCell();
        agentCell.textContent = pf.destination_agent_id;
        agentCell.style.fontFamily = 'monospace';
        agentCell.style.fontSize = '12px';

        row.insertCell().textContent = isSocks ? '—' : pf.destination_host;
        row.insertCell().textContent = isSocks ? '—' : (pf.destination_port || '');

        const actCell = row.insertCell();
        const del = document.createElement('button');
        del.textContent = 'Delete';
        del.className = 'delete-button';
        del.onclick = () => {
            const confirmFn = window.showConfirm || ((t, m) => Promise.resolve(confirm(m)));
            confirmFn('Delete Port Forward', 'Are you sure you want to delete this port forward?')
            .then(yes => {
                if (!yes) return;
                const csrf = getCSRF();
                fetch('/stop-port-forward', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'listenerID=' + encodeURIComponent(pf.listener_id) + '&csrf_token=' + encodeURIComponent(csrf),
                    credentials: 'include'
                })
                .then(r => { if (!r.ok) throw new Error(r.statusText); return r.text(); })
                .then(msg => {
                    if (typeof appendLog === 'function') appendLog(msg);
                    portForwardsCache = portForwardsCache.filter(p => p.listener_id !== pf.listener_id);
                    populateAllForwards(portForwardsCache);
                })
                .catch(err => console.error('Error deleting port forward:', err));
            });
        };
        actCell.appendChild(del);
    });
}

function populateReverseForwards(rforwards) {
    const tbody = document.getElementById('rforward-tbody');
    const empty = document.getElementById('rforward-empty');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!rforwards || rforwards.length === 0) {
        if (empty) empty.style.display = 'block';
        return;
    }
    if (empty) empty.style.display = 'none';
    rforwards.forEach(rf => {
        const row = tbody.insertRow();
        const portCell = row.insertCell();
        portCell.textContent = ':' + rf.listen_port;
        portCell.style.fontWeight = '600';
        portCell.style.color = 'var(--primary-color)';

        const agentCell = row.insertCell();
        agentCell.textContent = rf.agent_id;
        agentCell.style.fontFamily = 'monospace';
        agentCell.style.fontSize = '12px';

        row.insertCell().textContent = rf.target_host;
        row.insertCell().textContent = rf.target_port;

        const actCell = row.insertCell();
        const del = document.createElement('button');
        del.textContent = 'Delete';
        del.className = 'delete-button';
        del.onclick = () => {
            const csrf = getCSRF();
            const confirmFn = window.showConfirm || ((t, m) => Promise.resolve(confirm(m)));
            confirmFn('Delete Reverse Forward', 'Are you sure you want to stop this reverse forward?')
            .then(yes => {
                if (!yes) return;
                fetch('/api/reverse-forward', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'action=del&listenerID=' + encodeURIComponent(rf.listener_id) + '&csrf_token=' + encodeURIComponent(csrf),
                    credentials: 'include'
                }).then(r => r.text()).then(text => {
                    appendLog(text);
                    reverseForwardsCache = reverseForwardsCache.filter(r => r.listener_id !== rf.listener_id);
                    populateReverseForwards(reverseForwardsCache);
                });
            });
        };
        actCell.appendChild(del);
    });
}

function populateRoutingToggleTable(routingTable, disabledSubnets, subnetOwners) {
    const tbody = document.getElementById('routing-toggle-tbody');
    const empty = document.getElementById('routing-toggle-empty');
    if (!tbody) return;
    tbody.innerHTML = '';
    const subnets = Object.keys(routingTable || {});
    if (subnets.length === 0) {
        if (empty) empty.style.display = 'block';
        return;
    }
    if (empty) empty.style.display = 'none';

    subnets.sort().forEach(subnet => {
        const agentId = routingTable[subnet];
        const disabled = !!(disabledSubnets && disabledSubnets[subnet]);
        const owners = (subnetOwners && subnetOwners[subnet]) || [];
        const hasConflict = owners.length > 1;

        const row = tbody.insertRow();

         
        const subnetCell = row.insertCell();
        subnetCell.textContent = subnet;
        subnetCell.style.fontFamily = 'monospace';
        subnetCell.style.fontSize = '12px';
        if (hasConflict) {
            const warn = document.createElement('span');
            warn.title = '⚠ Conflict: claimed by ' + owners.join(', ');
            warn.textContent = ' ⚠';
            warn.style.cssText = 'color:#f0a500;cursor:help;font-size:13px;';
            subnetCell.appendChild(warn);
        }

         
        const agentCell = row.insertCell();
        agentCell.textContent = agentId;
        agentCell.style.fontFamily = 'monospace';
        agentCell.style.fontSize = '12px';
        if (hasConflict) {
            agentCell.style.color = 'var(--warning-color,#f0a500)';
        }

         
        const statusCell = row.insertCell();
        const statusBadge = document.createElement('span');
        statusBadge.textContent = disabled ? 'Disabled' : 'Active';
        statusBadge.style.cssText = disabled
            ? 'font-size:11px;background:#555;color:#ccc;border-radius:3px;padding:2px 6px;font-weight:600;'
            : 'font-size:11px;background:var(--primary-color);color:#fff;border-radius:3px;padding:2px 6px;font-weight:600;';
        statusCell.appendChild(statusBadge);

         
        const toggleCell = row.insertCell();
        const btn = document.createElement('button');
        btn.textContent = disabled ? 'Enable' : 'Disable';
        btn.className = disabled ? 'delete-button' : 'disconnect-button';
        btn.style.fontSize = '11px';
        btn.onclick = () => {
            const csrf = getCSRF();
            fetch('/api/toggle-subnet', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'subnet=' + encodeURIComponent(subnet) + '&csrf_token=' + encodeURIComponent(csrf),
                credentials: 'include'
            }).then(r => r.json()).then(data => {
                 
                fetchData();
                const routingDrawer = document.getElementById('routing-drawer');
                if (routingDrawer && routingDrawer.classList.contains('open')) {
                    
                    const newDisabled = Object.assign({}, disabledSubnets, { [subnet]: data.disabled });
                    populateRoutingToggleTable(routingTable, newDisabled, subnetOwners);
                }
            }).catch(err => { if (typeof appendLog === 'function') appendLog('Toggle error: ' + err); else console.error('Toggle error:', err); });
        };
        toggleCell.appendChild(btn);

         
        if (disabled) {
            row.style.opacity = '0.5';
        }
    });
}


// ==================== SETTINGS MODAL ====================

// ─── SETTINGS FUNCTIONS  ──────────────────────

function getCSRF() {
    const match = document.cookie.match(/(?:^|;)\s*tunnelcsrf\s*=\s*([^;]+)/);
    if (match && match[1]) return decodeURIComponent(match[1]);
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

function resetSettingsModalState() {
    
    ['net-status-msg', 'sec-status-msg', 'app-status-msg', 'global-status-msg', 'cfg-import-status'].forEach(id => {
        const el = document.getElementById(id);
        if (el) { el.textContent = ''; el.className = 'settings-status'; }
    });
     
    const newKeyInput = document.getElementById('cfg-new-key');
    if (newKeyInput) newKeyInput.value = '';
}

function openSettingsModal() {
    const modal = document.getElementById('settings-modal');
    if (!modal) return;
    modal.style.display = 'flex';
    resetSettingsModalState();
    loadCurrentSettings();
    const currentTheme = document.body.getAttribute('data-theme') || 'dark';
    document.querySelectorAll('.settings-theme-btn').forEach(b => b.classList.remove('active'));
    const themeBtn = document.getElementById('theme-btn-' + currentTheme);
    if (themeBtn) themeBtn.classList.add('active');
    showSettingsSection('networking', document.querySelector('.settings-nav-link[data-section="networking"]'));
}

function closeSettingsModal() {
    hideTokenReveal();
    const modal = document.getElementById('settings-modal');
    if (modal) modal.style.display = 'none';
    resetSettingsModalState();
}

function settingsOverlayClick(e) {
    if (e.target === document.getElementById('settings-modal')) closeSettingsModal();
}

function showSettingsSection(section, el) {
    document.querySelectorAll('.settings-section').forEach(s => s.style.display = 'none');
    const target = document.getElementById('settings-section-' + section);
    if (target) target.style.display = 'flex';
    document.querySelectorAll('.settings-nav-link').forEach(a => a.classList.remove('active'));
    if (el) el.classList.add('active');
}

async function loadCurrentSettings() {
    try {
        const res = await fetch('/api/settings', { credentials: 'include' });
        if (!res.ok) return;
        const data = await res.json();
        const httpEl = document.getElementById('cfg-http-port');
        const tcpEl  = document.getElementById('cfg-tcp-port');
        const udpEl  = document.getElementById('cfg-udp-port');
        const dnsEl  = document.getElementById('cfg-dns-port');
        const keyEl  = document.getElementById('current-key-display');
        if (httpEl) httpEl.value = data.http_port || 1024;
        if (tcpEl)  tcpEl.value  = data.tcp_port  || 1080;
        if (udpEl)  udpEl.value  = data.udp_port  || 1081;
        if (dnsEl)  dnsEl.value  = data.dns_port  || 5300;
        if (keyEl)  keyEl.textContent = data.current_key || '';
        const udpNote = document.getElementById('udp-port-note');
        if (udpNote) udpNote.style.display = navigator.platform.toLowerCase().includes('win') ? 'block' : 'none';
    } catch(e) {
        console.error('Failed to load settings', e);
    }
}

async function applyNetworkingSettings() {
    const csrf      = getCSRF();
    const httpPort  = parseInt(document.getElementById('cfg-http-port').value);
    const tcpPort   = parseInt(document.getElementById('cfg-tcp-port').value);
    const udpPort   = parseInt(document.getElementById('cfg-udp-port').value);
    const dnsPort   = parseInt(document.getElementById('cfg-dns-port').value);
    const statusEl  = document.getElementById('net-status-msg');

    if ([httpPort, tcpPort, udpPort, dnsPort].some(p => isNaN(p) || p < 1 || p > 65535)) {
        if (statusEl) { statusEl.textContent = 'Invalid port value'; statusEl.className = 'settings-status error'; }
        return;
    }
    if (statusEl) { statusEl.textContent = 'Applying...'; statusEl.className = 'settings-status'; }

    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
            body: JSON.stringify({ http_port: httpPort, tcp_port: tcpPort, udp_port: udpPort, dns_port: dnsPort })
        });
        const data = await res.json();
        if (data.success) {
            if (data.http_restart) {
                if (statusEl) { statusEl.textContent = `HTTP restarting on port ${data.new_port}, redirecting...`; statusEl.className = 'settings-status success'; }
                setTimeout(() => { window.location.href = `${window.location.protocol}//${window.location.hostname}:${data.new_port}/dashboard`; }, 2000);
            } else {
                let message = 'Applied successfully';
                if (data.udp_restart_warning) message += ' — ' + data.udp_restart_warning;
                if (statusEl) { statusEl.textContent = message; statusEl.className = data.udp_restart_warning ? 'settings-status warning' : 'settings-status success'; }
            }
        } else {
            if (statusEl) { statusEl.textContent = data.error || 'Failed'; statusEl.className = 'settings-status error'; }
        }
    } catch(e) {
        if (statusEl) { statusEl.textContent = 'Request failed'; statusEl.className = 'settings-status error'; }
    }
}

async function applySecuritySettings() {
    const csrf     = getCSRF();
    const newKey   = (document.getElementById('cfg-new-key').value || '').trim();
    const statusEl = document.getElementById('sec-status-msg');
    if (!newKey) {
        if (statusEl) { statusEl.textContent = 'Enter a key or use Regenerate'; statusEl.className = 'settings-status error'; }
        return;
    }
    if (newKey.length < 40) {
        if (statusEl) { statusEl.textContent = 'Key too short (must be base64-encoded 32 bytes)'; statusEl.className = 'settings-status error'; }
        return;
    }
    if (statusEl) { statusEl.textContent = 'Applying...'; statusEl.className = 'settings-status'; }
    try {
        const res  = await fetch('/api/settings', {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
            body: JSON.stringify({ new_key: newKey })
        });
        const data = await res.json();
        if (data.success) {
            const keyEl = document.getElementById('current-key-display');
            if (keyEl) keyEl.textContent = data.new_key || newKey;
            document.getElementById('cfg-new-key').value = '';
            if (statusEl) { statusEl.textContent = 'Key updated. All agents disconnected.'; statusEl.className = 'settings-status success'; }
        } else {
            if (statusEl) { statusEl.textContent = data.error || 'Failed'; statusEl.className = 'settings-status error'; }
        }
    } catch(e) {
        if (statusEl) { statusEl.textContent = 'Request failed'; statusEl.className = 'settings-status error'; }
    }
}

function regenerateKeyAPI() {
    const statusEl = document.getElementById('sec-status-msg');
    try {
        // Generate 32 random bytes client-side and base64url-encode (matches Go's base64.URLEncoding)
        const raw = new Uint8Array(32);
        crypto.getRandomValues(raw);
        const b64 = btoa(String.fromCharCode(...raw))
            .replace(/\+/g, '-').replace(/\//g, '_');
        const newKeyInput = document.getElementById('cfg-new-key');
        if (newKeyInput) newKeyInput.value = b64;
        if (statusEl) {
            statusEl.textContent = 'New key generated \u2014 click \u201cUpdate Key\u201d to apply it.';
            statusEl.className = 'settings-status warning';
        }
    } catch(e) {
        if (statusEl) { statusEl.textContent = 'Failed to generate key'; statusEl.className = 'settings-status error'; }
    }
}

function copyCurrentKey() {
    const keyEl = document.getElementById('current-key-display');
    const key   = keyEl ? keyEl.textContent : '';
    if (!key) return;
    navigator.clipboard.writeText(key).then(() => {
        const btn = document.querySelector('.settings-copy-btn');
        if (!btn) return;
        const orig = btn.style.background;
        btn.style.background = 'linear-gradient(135deg, var(--primary-color), var(--secondary-color))';
        setTimeout(() => { btn.style.background = orig; }, 300);
    });
}

async function exportConfig() {
    try {
        const res = await fetch('/api/config/export', { credentials: 'include' });
        if (!res.ok) { alert('Export failed: ' + res.statusText); return; }
        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = 'config.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch(e) {
        alert('Export failed: ' + e.message);
    }
}

function triggerConfigImport() {
    const input = document.getElementById('cfg-import-file');
    if (input) input.click();
}

async function importConfigFile(input) {
    const file = input.files && input.files[0];
    if (!file) return;
    input.value = '';
    const statusEl = document.getElementById('cfg-import-status');
    try {
        const text = await file.text();
        let cfg;
        try {
            cfg = JSON.parse(text);
        } catch (parseErr) {
            if (statusEl) { statusEl.textContent = 'Invalid JSON file: ' + parseErr.message; statusEl.className = 'settings-status error'; }
            return;
        }
        // Populate fields only 
        const httpEl = document.getElementById('cfg-http-port');
        const tcpEl  = document.getElementById('cfg-tcp-port');
        const udpEl  = document.getElementById('cfg-udp-port');
        const dnsEl  = document.getElementById('cfg-dns-port');
        const keyEl  = document.getElementById('cfg-new-key');
        if (cfg.http_port && httpEl) httpEl.value = cfg.http_port;
        if (cfg.tcp_port  && tcpEl)  tcpEl.value  = cfg.tcp_port;
        if (cfg.udp_port  && udpEl)  udpEl.value  = cfg.udp_port;
        if (cfg.dns_port  && dnsEl)  dnsEl.value  = cfg.dns_port;
        if (cfg.key       && keyEl)  keyEl.value  = cfg.key;
        if (statusEl) { statusEl.textContent = 'Config loaded into fields — click Apply Changes to save.'; statusEl.className = 'settings-status warning'; }
    } catch(e) {
        if (statusEl) { statusEl.textContent = 'Import error: ' + e.message; statusEl.className = 'settings-status error'; }
    }
}


function applyTheme(theme) {
    const current = document.body.getAttribute('data-theme') || 'light';
    document.body.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    const toggle = document.getElementById('checkbox');
    if (toggle) toggle.checked = (theme === 'dark');
    document.querySelectorAll('.settings-theme-btn').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById('theme-btn-' + theme);
    if (btn) btn.classList.add('active');
    const logo = document.getElementById('header-logo');
    if (logo) {
        logo.src = theme === 'dark' ? '/static/img/logo-dark.png' : '/static/img/logo-light.png';
    }
    const aboutLogo = document.getElementById('about-logo');
    if (aboutLogo) {
        aboutLogo.src = theme === 'dark' ? '/static/img/logo-dark.png' : '/static/img/logo-light.png';
    }
    const statusEl = document.getElementById('app-status-msg');
    if (statusEl) {
        if (current === theme) {
            statusEl.textContent = '';
            statusEl.className = 'settings-status';
        } else {
            statusEl.textContent = theme.charAt(0).toUpperCase() + theme.slice(1) + ' theme applied';
            statusEl.className = 'settings-status success';
        }
    }
}


document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        const modal = document.getElementById('settings-modal');
        if (modal && modal.style.display !== 'none') {
            closeSettingsModal();
        }
    }
});

// ── REST API Token Management ──────────────────────────────────────────────

function loadAPITokens() {
    fetch('/api/tokens')
        .then(r => r.json())
        .then(tokens => renderAPITokens(tokens))
        .catch(() => {});
}

function renderAPITokens(tokens) {
    const list = document.getElementById('api-tokens-list');
    const empty = document.getElementById('api-tokens-empty');
    if (!list) return;

     
    list.querySelectorAll('.api-token-row').forEach(el => el.remove());

    if (!tokens || tokens.length === 0) {
        if (empty) empty.style.display = '';
        return;
    }
    if (empty) empty.style.display = 'none';

    tokens.forEach(tok => {
        const row = document.createElement('div');
        row.className = 'api-token-row';
        row.style.cssText = 'display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--surface-color);border:1px solid var(--border-color);border-radius:8px;';

        const lastUsed = tok.last_used_at && tok.last_used_at !== '0001-01-01T00:00:00Z'
            ? new Date(tok.last_used_at).toLocaleString()
            : 'Never';
        const permBadges = (tok.permissions || []).map(p =>
            `<span style="font-size:10px;padding:2px 7px;border-radius:999px;background:var(--primary-color);color:var(--button-text-color);font-weight:600;">${p}</span>`
        ).join(' ');

        let expiryHtml = '';
        if (tok.expires_at) {
            const expDate = new Date(tok.expires_at);
            const expired = expDate < new Date();
            const expStr = expDate.toLocaleString();
            expiryHtml = expired
                ? `&nbsp;·&nbsp; <span style="color:var(--danger-color);font-weight:600;">Expired ${expStr}</span>`
                : `&nbsp;·&nbsp; Expires: ${expStr}`;
        }

        row.innerHTML = `
            <div style="flex:1;min-width:0;">
                <div style="font-weight:600;font-size:13px;margin-bottom:3px;">${escapeHtml(tok.name)}</div>
                <div style="font-size:11px;color:var(--light-text-color);">
                    Created: ${new Date(tok.created_at).toLocaleString()} &nbsp;·&nbsp; Last used: ${lastUsed}${expiryHtml}
                </div>
                <div style="margin-top:4px;">${permBadges}</div>
            </div>
            <button onclick="viewAPIToken('${escapeHtml(tok.id)}', '${escapeHtml(tok.name)}')"
                style="background:none;border:1px solid var(--primary-color);border-radius:6px;padding:6px 12px;cursor:pointer;color:var(--primary-color);font-size:12px;font-weight:600;white-space:nowrap;margin-right:6px;">
                View
            </button>
            <button onclick="revokeAPIToken('${escapeHtml(tok.id)}')"
                style="background:none;border:1px solid var(--danger-color);border-radius:6px;padding:6px 12px;cursor:pointer;color:var(--danger-color);font-size:12px;font-weight:600;white-space:nowrap;">
                Revoke
            </button>`;
        list.appendChild(row);
    });
}

function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function onTokenExpiryChange() {
    const sel = document.getElementById('api-token-expiry');
    const custom = document.getElementById('api-token-expiry-custom');
    if (!sel || !custom) return;
    custom.style.display = sel.value === 'custom' ? '' : 'none';
    if (sel.value === 'custom') custom.focus();
}

function createAPIToken() {
    const name = (document.getElementById('api-token-name').value || '').trim();
    if (!name) {
        setAPIStatus('Token name is required.', false);
        return;
    }

    const perms = [];
    if (document.getElementById('api-perm-read').checked) perms.push('read');
    if (document.getElementById('api-perm-write').checked) perms.push('write');
    if (document.getElementById('api-perm-admin').checked) perms.push('admin');
    if (perms.length === 0) perms.push('read');

    const expirySel = document.getElementById('api-token-expiry');
    let ttlHours = 0;
    if (expirySel) {
        if (expirySel.value === 'custom') {
            const customVal = parseInt(document.getElementById('api-token-expiry-custom').value || '0', 10);
            if (customVal > 0) ttlHours = customVal;
        } else {
            ttlHours = parseInt(expirySel.value, 10) || 0;
        }
    }

    fetch('/api/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, permissions: perms, ttl_hours: ttlHours })
    })
    .then(r => {
        if (!r.ok) return r.json().then(e => Promise.reject(e.error || 'Error'));
        return r.json();
    })
    .then(tok => {
         
        const revealBox = document.getElementById('api-token-reveal');
        const revealVal = document.getElementById('api-token-reveal-value');
        if (revealBox && revealVal) {
            revealVal.textContent = tok.token;
            revealBox.style.display = '';
            startTokenRevealTimer(60);
        }
        document.getElementById('api-token-name').value = '';
        setAPIStatus('Token created. Copy it now, it will not be shown again.', true);
        loadAPITokens();
    })
    .catch(err => setAPIStatus('Failed to create token: ' + err, false));
}

function copyAPIToken() {
    const val = document.getElementById('api-token-reveal-value');
    if (!val) return;
    navigator.clipboard.writeText(val.textContent).then(() => {
        setAPIStatus('Token copied to clipboard.', true);
    });
}

// Token visibility toggle  
var _tokenVisible = false;
var _tokenHideTimer = null;
var _tokenCountdownInterval = null;

function toggleTokenVisibility() {
    _tokenVisible = !_tokenVisible;
    const code = document.getElementById('api-token-reveal-value');
    const icon = document.getElementById('api-token-eye-icon');
    if (!code) return;
    code.style.filter = _tokenVisible ? 'none' : 'blur(4px)';
    code.style.userSelect = _tokenVisible ? 'text' : 'none';
    if (icon) {
        icon.outerHTML = _tokenVisible
            ? '<svg id="api-token-eye-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
            : '<svg id="api-token-eye-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    }
}

function startTokenRevealTimer(seconds) {
    if (_tokenHideTimer) clearTimeout(_tokenHideTimer);
    if (_tokenCountdownInterval) clearInterval(_tokenCountdownInterval);
    _tokenVisible = false;
    const code = document.getElementById('api-token-reveal-value');
    if (code) { code.style.filter = 'blur(4px)'; code.style.userSelect = 'none'; }
    let remaining = seconds;
    const timerEl = document.getElementById('api-token-reveal-timer');
    function updateTimer() {
        if (timerEl) timerEl.textContent = 'Hides in ' + remaining + 's';
        remaining--;
    }
    updateTimer();
    _tokenCountdownInterval = setInterval(() => {
        if (remaining <= 0) {
            clearInterval(_tokenCountdownInterval);
            hideTokenReveal();
        } else {
            updateTimer();
        }
    }, 1000);
    _tokenHideTimer = setTimeout(hideTokenReveal, seconds * 1000);
}

function hideTokenReveal() {
    if (_tokenHideTimer) { clearTimeout(_tokenHideTimer); _tokenHideTimer = null; }
    if (_tokenCountdownInterval) { clearInterval(_tokenCountdownInterval); _tokenCountdownInterval = null; }
    _tokenVisible = false;
    const reveal = document.getElementById('api-token-reveal');
    if (reveal) reveal.style.display = 'none';
    const val = document.getElementById('api-token-reveal-value');
    if (val) { val.textContent = ''; val.style.filter = 'blur(4px)'; }
}

function revokeAPIToken(id) {
    const confirmFn = window.showConfirm || ((t, m) => Promise.resolve(confirm(m)));
    confirmFn('Revoke Token', 'Revoke this token? Any scripts using it will lose access immediately.')
        .then(ok => {
            if (!ok) return;
            fetch('/api/tokens/revoke?id=' + encodeURIComponent(id), { method: 'DELETE' })
                .then(r => {
                    if (!r.ok) return r.json().then(e => Promise.reject(e.error || 'Error'));
                    return r.json();
                })
                .then(() => {
                    setAPIStatus('Token revoked.', true);
                    const reveal = document.getElementById('api-token-reveal');
                    if (reveal) reveal.style.display = 'none';
                    loadAPITokens();
                })
                .catch(err => setAPIStatus('Failed to revoke: ' + err, false));
        });
}

function setAPIStatus(msg, ok) {
    const el = document.getElementById('api-status-msg');
    if (!el) return;
    el.textContent = msg;
    el.className = 'settings-status ' + (ok ? 'success' : 'error');
    setTimeout(() => { if (el.textContent === msg) { el.textContent = ''; el.className = 'settings-status'; } }, 6000);
}

 
const _origShowSettingsSection = typeof showSettingsSection === 'function' ? showSettingsSection : null;
 
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.settings-nav-link[data-section="api"]').forEach(link => {
        link.addEventListener('click', () => loadAPITokens());
    });
});

// ── Per-token view (fetches token value from server, shows for 60s) ──
var _viewTokenVisible = false;
var _viewTokenHideTimer = null;
var _viewTokenCountdownInterval = null;

function viewAPIToken(id, name) {
    fetch('/api/tokens/view?id=' + encodeURIComponent(id))
        .then(r => {
            if (!r.ok) return r.json().then(e => Promise.reject(e.error || 'Error'));
            return r.json();
        })
        .then(data => {
            const reveal = document.getElementById('api-token-view-reveal');
            const val = document.getElementById('api-token-view-value');
            const label = document.getElementById('api-token-view-label');
            if (!reveal || !val) return;
            val.textContent = data.token;
            val.style.filter = 'blur(4px)';
            val.style.userSelect = 'none';
            if (label) label.textContent = 'Token: ' + name + '  ·  ID: ' + id;
            _viewTokenVisible = false;
            const eyeBtn = document.getElementById('api-token-view-eye-btn');
            if (eyeBtn) eyeBtn.innerHTML = '<svg id="api-token-view-eye-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
            reveal.style.display = '';
            reveal.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            startViewTokenTimer(60);
        })
        .catch(err => setAPIStatus('Failed to view token: ' + err, false));
}

function startViewTokenTimer(seconds) {
    if (_viewTokenHideTimer) clearTimeout(_viewTokenHideTimer);
    if (_viewTokenCountdownInterval) clearInterval(_viewTokenCountdownInterval);
    let remaining = seconds;
    const timerEl = document.getElementById('api-token-view-timer');
    function updateTimer() {
        if (timerEl) timerEl.textContent = 'Hides in ' + remaining + 's';
        remaining--;
    }
    updateTimer();
    _viewTokenCountdownInterval = setInterval(() => {
        if (remaining <= 0) {
            clearInterval(_viewTokenCountdownInterval);
            hideViewTokenReveal();
        } else {
            updateTimer();
        }
    }, 1000);
    _viewTokenHideTimer = setTimeout(hideViewTokenReveal, seconds * 1000);
}

function hideViewTokenReveal() {
    if (_viewTokenHideTimer) { clearTimeout(_viewTokenHideTimer); _viewTokenHideTimer = null; }
    if (_viewTokenCountdownInterval) { clearInterval(_viewTokenCountdownInterval); _viewTokenCountdownInterval = null; }
    _viewTokenVisible = false;
    const reveal = document.getElementById('api-token-view-reveal');
    if (reveal) reveal.style.display = 'none';
    const val = document.getElementById('api-token-view-value');
    if (val) { val.textContent = ''; val.style.filter = 'blur(4px)'; }
}

function toggleViewTokenVisibility() {
    _viewTokenVisible = !_viewTokenVisible;
    const code = document.getElementById('api-token-view-value');
    if (!code) return;
    code.style.filter = _viewTokenVisible ? 'none' : 'blur(4px)';
    code.style.userSelect = _viewTokenVisible ? 'text' : 'none';
    const eyeBtn = document.getElementById('api-token-view-eye-btn');
    if (eyeBtn) {
        eyeBtn.innerHTML = _viewTokenVisible
            ? '<svg id="api-token-view-eye-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
            : '<svg id="api-token-view-eye-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    }
}

function copyViewToken() {
    const val = document.getElementById('api-token-view-value');
    if (!val) return;
    navigator.clipboard.writeText(val.textContent).then(() => {
        setAPIStatus('Token copied to clipboard.', true);
    });
}


// ── CLI panel vertical resize ──────────────────────────────────────────────
(function () {
    var MIN_H = 100;
    var STORAGE_KEY = 'cliPanelHeight';

    function panel()  { return document.getElementById('cli-panel'); }
    function handle() { return document.getElementById('cli-resize-handle'); }

    function setHeight(h) {
        var p = panel();
        if (!p) return;
        var maxH = Math.floor(window.innerHeight * 0.85);
        h = Math.max(MIN_H, Math.min(maxH, h));
        p.style.height = h + 'px';
         
        document.body.style.paddingBottom = h + 'px';
    }

    function saveH() {
        var p = panel();
        if (!p) return;
        try { localStorage.setItem(STORAGE_KEY, p.offsetHeight); } catch(e) {}
    }

    function initResize() {
        var p = panel();
        var h = handle();
        if (!p || !h) return;

       
        try {
            var saved = parseInt(localStorage.getItem(STORAGE_KEY), 10);
            if (saved > 0) setHeight(saved);
        } catch(e) {}

        var dragStartY = 0;
        var dragStartH = 0;
        var dragging   = false;

        function startDrag(clientY) {
            dragging    = true;
            dragStartY  = clientY;
            dragStartH  = p.offsetHeight;
            h.classList.add('dragging');
            document.body.style.userSelect   = 'none';
            document.body.style.cursor       = 'ns-resize';
        }

        function moveDrag(clientY) {
            if (!dragging) return;
            var delta = dragStartY - clientY;   
            setHeight(dragStartH + delta);
        }

        function endDrag() {
            if (!dragging) return;
            dragging = false;
            h.classList.remove('dragging');
            document.body.style.userSelect = '';
            document.body.style.cursor     = '';
            saveH();
        }

        
        h.addEventListener('mousedown', function (e) {
            e.preventDefault();
            startDrag(e.clientY);
        });
        document.addEventListener('mousemove', function (e) { moveDrag(e.clientY); });
        document.addEventListener('mouseup',   endDrag);

         
        h.addEventListener('touchstart', function (e) {
            startDrag(e.touches[0].clientY);
        }, { passive: true });
        document.addEventListener('touchmove', function (e) {
            if (dragging) moveDrag(e.touches[0].clientY);
        }, { passive: true });
        document.addEventListener('touchend', endDrag);

         
        window.addEventListener('resize', function () {
            setHeight(p.offsetHeight);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initResize);
    } else {
        initResize();
    }
})();
