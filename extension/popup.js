// global variable
const activeConfirmCleanupFns = [];
let currentLogType = 'server';

function closeAllInlineConfirms() {
  while (activeConfirmCleanupFns.length > 0) {
    const cleanup = activeConfirmCleanupFns.pop();
    cleanup();
  }
}

// ── Utilities ──────────────────────────────────────
const $ = id => document.getElementById(id);

function show(el) { if (el) el.style.display = ''; }
function hide(el) { if (el) el.style.display = 'none'; }

function setStatus(el, msg, type) {
  if (!el) return;
  el.textContent = msg;
  el.className = 'status-msg ' + (type || '');
}

function timeAgo(isoStr) {
  if (!isoStr) return '—';
  const s = Math.floor((Date.now() - new Date(isoStr)) / 1000);
  if (s < 5)    return 'just now';
  if (s < 60)   return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  return Math.floor(s / 3600) + 'h ago';
}

function fmtUptime(sec) {
  if (!sec) return '—';
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}


function createCustomSelect(options, defaultVal) {
  const container = document.createElement('div');
  container.className = 'custom-select';

  const trigger = document.createElement('div');
  trigger.className = 'custom-select-trigger';

  const dropdown = document.createElement('div');
  dropdown.className = 'custom-select-options';

  let selectedVal = defaultVal || options[0].value;

  function renderOptions() {
    dropdown.innerHTML = '';
    options.forEach(opt => {
      const div = document.createElement('div');
      div.className = 'custom-select-option' + (opt.value === selectedVal ? ' selected' : '');
      div.textContent = opt.label;
      div.dataset.value = opt.value;
      div.addEventListener('click', (e) => {
        e.stopPropagation();
        selectedVal = opt.value;
        trigger.textContent = opt.label;
        container.querySelectorAll('.custom-select-option').forEach(o => o.classList.remove('selected'));
        div.classList.add('selected');
        container.classList.remove('open');
      });
      dropdown.appendChild(div);
    });
  }

  const defaultOpt = options.find(o => o.value === selectedVal) || options[0];
  trigger.textContent = defaultOpt.label;

  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    container.classList.toggle('open');
  });

  document.addEventListener('click', () => container.classList.remove('open'));

  renderOptions();
  container.appendChild(trigger);
  container.appendChild(dropdown);

  return { container, getValue: () => selectedVal, setValue: (v) => { selectedVal = v; const opt = options.find(o => o.value === v); if (opt) trigger.textContent = opt.label; } };
}

function escHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}


function stripAnsi(s) {
  return String(s || '').replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');
}

function osIconSrc(os) {
  const o = (os || '').toLowerCase();
  if (o.includes('windows'))                      return 'os-icons/OS_Windows.png';
  if (o.includes('linux'))                        return 'os-icons/linux_os.png';
  if (o.includes('darwin') || o.includes('mac'))  return 'os-icons/mac-os.png';
  return 'os-icons/os-unknown.png';
}

function parseErr(text, status) {
  try { const j = JSON.parse(text); return j.error || `HTTP ${status}`; } catch {}
  return (text || '').trim().slice(0, 120) || `HTTP ${status}`;
}

// ── API fetch helper ────────────────────────────────
async function api(path, opts = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(bearerToken ? { 'Authorization': 'Bearer ' + bearerToken } : {}),
    ...(opts.headers || {})
  };
  const res = await fetch(serverUrl + path, { ...opts, headers });
  if (res.status === 401) {
    await refreshToken();
    if (!bearerToken) throw new Error('Session expired — log in again.');
    headers['Authorization'] = 'Bearer ' + bearerToken;
    return fetch(serverUrl + path, { ...opts, headers });
  }
  return res;
}

async function apiJSON(path, opts = {}) {
  const res = await api(path, opts);
  if (!res.ok) {
    const t = await res.text().catch(() => '');
    throw new Error(parseErr(t, res.status));
  }
  return res.json();
}

// ── Auth ────────────────────────────────────────────
async function doLogin(ip, port, key) {
  const base = `http://${ip}:${port}`;
  let resp;
  try {
    resp = await fetch(base + '/api/v1/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key })
    });
  } catch (e) { throw new Error('Cannot reach server at ' + base); }
  if (resp.status === 401) throw new Error('Invalid key');
  if (!resp.ok) { const t = await resp.text(); throw new Error(parseErr(t, resp.status)); }
  const data = await resp.json();
  if (!data.token) throw new Error('Server did not return a token');
  return { base, token: data.token };
}

async function refreshToken() {
  const s = await chrome.storage.local.get(['serverUrl','key']).catch(() => ({}));
  if (!s.serverUrl || !s.key) { bearerToken = ''; return; }
  try {
    const r = await fetch(s.serverUrl + '/api/v1/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: s.key })
    });
    if (!r.ok) { bearerToken = ''; return; }
    const d = await r.json();
    bearerToken = d.token || '';
    if (bearerToken) await chrome.storage.local.set({ token: bearerToken });
  } catch { bearerToken = ''; }
}

async function checkAuth() {
  try {
    const r = await fetch(serverUrl + '/api/v1/status', {
      headers: bearerToken ? { 'Authorization': 'Bearer ' + bearerToken } : {}
    });
    return r.ok;
  } catch { return false; }
}

// ── Theme ───────────────────────────────────────────
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  const logo = $('about-logo');
  if (logo) {
    logo.src = t === 'dark' ? 'img/logo-dark.png' : 'img/logo-light.png';
  }
  const loginLogo = $('login-logo-img');
  if (loginLogo) {
    loginLogo.src = t === 'dark' ? 'img/logo-dark.png' : 'img/logo-light.png';
  }
  const icon = $('theme-icon');
  if (!icon) return;
  icon.innerHTML = t === 'dark'
    ? '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>'
    : '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y1="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>';
}

// ── Tab switching ───────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t =>
    t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-panel').forEach(p =>
    p.style.display = p.id === 'tab-' + name ? '' : 'none');
  if (name === 'forwards') loadForwards();
  if (name === 'routes')   loadRoutes();
  if (name === 'logs')     loadLogs();
  if (name === 'settings') loadSettings();
}


function askConfirm(container, question) {
  closeAllInlineConfirms(); 

  return new Promise(resolve => {
    container.innerHTML = '';
    const bar = document.createElement('div');
    bar.className = 'inline-confirm';
    bar.innerHTML = `
      <span class="confirm-text">${escHtml(question)}</span>
      <button class="btn-sm btn-confirm-yes">Yes</button>
      <button class="btn-sm btn-confirm-no">No</button>`;

    const cleanup = () => {
      container.innerHTML = '';
      const index = activeConfirmCleanupFns.indexOf(cleanup);
      if (index > -1) activeConfirmCleanupFns.splice(index, 1);
    };
    activeConfirmCleanupFns.push(cleanup);

    bar.querySelector('.btn-confirm-yes').addEventListener('click', () => {
      cleanup();
      resolve(true);
    });
    bar.querySelector('.btn-confirm-no').addEventListener('click', () => {
      cleanup();
      resolve(false);
    });
    container.appendChild(bar);
  });
}

// ══════════════════════════════════════════════════
//  AGENTS TAB
// ══════════════════════════════════════════════════
async function loadAgents() {
  const list = $('agents-list');
  list.innerHTML = '<div class="empty-state">Loading…</div>';
  try {
    const [status, agents] = await Promise.all([
      apiJSON('/api/v1/status'),
      apiJSON('/api/v1/agents')
    ]);
    agentsCache = agents || [];
    $('agent-count-badge').textContent = agentsCache.length;
    $('status-dot').className = 'status-dot ' + (status?.ok ? 'online' : 'offline');

    if (!agentsCache.length) {
      list.innerHTML = '<div class="empty-state">No agents connected</div>';
      return;
    }
    list.innerHTML = '';
    agentsCache.forEach(a => list.appendChild(buildAgentCard(a)));
  } catch (e) {
    list.innerHTML = `<div class="empty-state" style="color:var(--danger)">${escHtml(e.message)}</div>`;
    $('status-dot').className = 'status-dot offline';
  }
}

function buildAgentCard(a) {
  const card = document.createElement('div');
  card.className = 'agent-card';
  const hostname = a.hostname || a.id || 'unknown';
  const username = a.username || '—';
  const tag      = a.tag || '';
  const subnets  = (a.subnets || []).join(', ') || '—';

  card.innerHTML = `
    <div class="agent-card-header">
      <img class="agent-os-icon" src="${osIconSrc(a.os)}" alt="${escHtml(a.os||'')}">
      <div class="agent-main-info">
        <div class="agent-hostname">${escHtml(hostname)}</div>
        <div class="agent-meta">${escHtml(username)} · ${timeAgo(a.last_seen)}</div>
      </div>
      ${tag ? `<span class="agent-tag">${escHtml(tag)}</span>` : ''}
      <span class="agent-expand-icon">▶</span>
    </div>
    <div class="agent-details" id="details-${escHtml(a.id)}">
      <div class="agent-info-grid">
        <span class="info-label">ID</span>      <span class="info-val" title="${escHtml(a.id)}">${escHtml(a.id.slice(0,16))}…</span>
        <span class="info-label">OS</span>      <span class="info-val">${escHtml(a.os||'—')}</span>
        <span class="info-label">User</span>    <span class="info-val">${escHtml(username)}</span>
        <span class="info-label">Uptime</span>  <span class="info-val">${escHtml(fmtUptime(Math.floor((Date.now() - new Date(a.connected_at)) / 1000)))}</span>
        <span class="info-label">Subnets</span> <span class="info-val">${escHtml(subnets)}</span>
      </div>
      <div class="agent-actions">
        <button class="btn-sm act-btn" data-act="forward">⇉ Forward</button>
        <button class="btn-sm act-btn" data-act="rforward">⇇ Rev Fwd</button>
        <button class="btn-sm act-btn" data-act="ping">◎ Ping</button>
        <button class="btn-sm act-btn" data-act="scan">⊕ Scan</button>
        <button class="btn-sm act-btn" data-act="tag">✎ Tag</button>
        <button class="btn-sm act-btn" data-act="reconnect">↺ Reconnect</button>
        <button class="btn-sm act-btn danger-btn" data-act="disconnect">✕ Disconnect</button>
      </div>
      <div class="agent-action-panel" id="panel-${escHtml(a.id)}"></div>
    </div>`;

  
  card.querySelector('.agent-card-header').addEventListener('click', () => {
    const det  = card.querySelector('.agent-details');
    const icon = card.querySelector('.agent-expand-icon');
    const open = det.classList.toggle('open');
    icon.classList.toggle('open', open);
    if (!open) clearAgentPanel(a.id);
  });

 
  card.querySelectorAll('.act-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      toggleAgentPanel(a.id, btn.dataset.act, a);
    });
  });

  return card;
}


const openPanels = {};

function clearAgentPanel(agentId) {
  const panel = $(`panel-${agentId}`);
  if (panel) panel.innerHTML = '';
  delete openPanels[agentId];
}

function toggleAgentPanel(agentId, action, agentData) {
  closeAllInlineConfirms(); 
  const panel = $(`panel-${agentId}`);
  if (!panel) return;
  
  
  Object.keys(openPanels).forEach(otherAgentId => {
    if (otherAgentId !== agentId) {
      const otherPanel = $(`panel-${otherAgentId}`);
      if (otherPanel) otherPanel.innerHTML = '';
      delete openPanels[otherAgentId];
    }
  });
  
  
  if (openPanels[agentId] === action) {
    panel.innerHTML = '';
    delete openPanels[agentId];
    return;
  }
  openPanels[agentId] = action;
  panel.innerHTML = '';

  switch (action) {
    case 'forward':    renderForwardForm(panel, agentId);  break;
    case 'rforward':   renderRForwardForm(panel, agentId); break;
    case 'ping':       renderPingForm(panel, agentId);     break;
    case 'scan':       renderScanForm(panel, agentId);     break;
    case 'tag':        renderTagForm(panel, agentId, agentData.tag || ''); break;
    case 'reconnect':  renderReconnectConfirm(panel, agentId); break;
    case 'disconnect': renderDisconnectConfirm(panel, agentId); break;
  }
}

// ── Panel: Port Forward ──────────────────────────────
function renderForwardForm(panel, agentId) {
  panel.innerHTML = `
    <div class="action-form">
      <div class="action-form-title">Port Forward</div>
      <div class="field-row">
        <div class="field">
          <label>Listen Port (agent)</label>
          <input type="number" class="pf-listen" placeholder="8080">
        </div>
        <div class="field field-sm">
          <label>Proto</label>
          <div class="proto-select-mount"></div>
        </div>
      </div>
      <div class="field-row">
        <div class="field">
          <label>Destination Host</label>
          <input type="text" class="pf-host" placeholder="192.168.1.100">
        </div>
        <div class="field field-sm">
          <label>Port</label>
          <input type="number" class="pf-port" placeholder="80">
        </div>
      </div>
      <div class="form-actions">
        <button class="btn-sm btn-primary pf-submit">Add Forward</button>
        <button class="btn-sm pf-cancel">Cancel</button>
      </div>
      <div class="status-msg pf-status"></div>
    </div>`;

  const protoSelect = createCustomSelect([
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' }
  ], 'tcp');
  panel.querySelector('.proto-select-mount').appendChild(protoSelect.container);

  panel.querySelector('.pf-cancel').addEventListener('click', () => clearAgentPanel(agentId));
  panel.querySelector('.pf-submit').addEventListener('click', async () => {
    const listen   = parseInt(panel.querySelector('.pf-listen').value);
    const destHost = panel.querySelector('.pf-host').value.trim();
    const destPort = parseInt(panel.querySelector('.pf-port').value);
    const proto    = protoSelect.getValue();
    const st = panel.querySelector('.pf-status');
    if (!listen || !destHost || !destPort) { setStatus(st, 'Fill in all fields.', 'err'); return; }
    setStatus(st, 'Adding…', '');
    try {
      const res = await api('/api/v1/forwards', {
        method: 'POST',
        body: JSON.stringify({ agent_id: agentId, listen_port: listen, target_host: destHost, target_port: destPort, protocol: proto })
      });
      if (!res.ok) { const t = await res.text(); throw new Error(parseErr(t, res.status)); }
      setStatus(st, 'Forward added.', 'ok');
      setTimeout(() => clearAgentPanel(agentId), 800);
    } catch (e) { setStatus(st, e.message, 'err'); }
  });
}

// ── Panel: Reverse Forward ───────────────────────────
function renderRForwardForm(panel, agentId) {
  panel.innerHTML = `
    <div class="action-form">
      <div class="action-form-title">Reverse Port Forward</div>
      <div class="field">
        <label>Server Listen Port</label>
        <input type="number" class="rf-listen" placeholder="13389">
      </div>
      <div class="field-row">
        <div class="field">
          <label>Target Host (agent side)</label>
          <input type="text" class="rf-host" value="127.0.0.1">
        </div>
        <div class="field field-sm">
          <label>Port</label>
          <input type="number" class="rf-port" placeholder="3389">
        </div>
      </div>
      <div class="form-actions">
        <button class="btn-sm btn-primary rf-submit">Add Rev Forward</button>
        <button class="btn-sm rf-cancel">Cancel</button>
      </div>
      <div class="status-msg rf-status"></div>
    </div>`;

  panel.querySelector('.rf-cancel').addEventListener('click', () => clearAgentPanel(agentId));
  panel.querySelector('.rf-submit').addEventListener('click', async () => {
    const listenPort = parseInt(panel.querySelector('.rf-listen').value);
    const targetHost = panel.querySelector('.rf-host').value.trim();
    const targetPort = parseInt(panel.querySelector('.rf-port').value);
    const st = panel.querySelector('.rf-status');
    if (!listenPort || !targetHost || !targetPort) { setStatus(st, 'Fill in all fields.', 'err'); return; }
    setStatus(st, 'Adding…', '');
    try {
      const res = await api('/api/v1/rforwards', {
        method: 'POST',
        body: JSON.stringify({ agent_id: agentId, listen_port: listenPort, target_host: targetHost, target_port: targetPort })
      });
      if (!res.ok) { const t = await res.text(); throw new Error(parseErr(t, res.status)); }
      setStatus(st, 'Reverse forward added.', 'ok');
      setTimeout(() => clearAgentPanel(agentId), 800);
    } catch (e) { setStatus(st, e.message, 'err'); }
  });
}

// ── Panel: Ping ──────────────────────────────────────
function renderPingForm(panel, agentId) {
  panel.innerHTML = `
    <div class="action-form">
      <div class="action-form-title">Ping via Agent</div>
      <div class="field-row">
        <div class="field">
          <label>Target Host</label>
          <input type="text" class="ping-target" placeholder="192.168.1.1">
        </div>
        <div class="field field-sm">
          <label>Count</label>
          <input type="number" class="ping-count" value="4" min="1" max="20">
        </div>
      </div>
      <div class="form-actions">
        <button class="btn-sm btn-primary ping-submit">Ping</button>
        <button class="btn-sm ping-cancel">Cancel</button>
      </div>
      <div class="status-msg ping-status"></div>
      <pre class="result-box ping-result" style="display:none;"></pre>
    </div>`;

  panel.querySelector('.ping-cancel').addEventListener('click', () => clearAgentPanel(agentId));
  panel.querySelector('.ping-submit').addEventListener('click', async () => {
    const target = panel.querySelector('.ping-target').value.trim();
    const count  = parseInt(panel.querySelector('.ping-count').value) || 4;
    const st     = panel.querySelector('.ping-status');
    const res_el = panel.querySelector('.ping-result');
    if (!target) { setStatus(st, 'Enter a target.', 'err'); return; }
    setStatus(st, 'Pinging…', '');
    hide(res_el);
    try {
      const data = await apiJSON(`/api/v1/agents/${agentId}/ping`, {
        method: 'POST',
        body: JSON.stringify({ target, count })
      });
      setStatus(st, 'Done.', 'ok');
      res_el.textContent = fmtPingResult(data);
      show(res_el);
    } catch (e) { setStatus(st, e.message, 'err'); }
  });
}

function fmtPingResult(data) {
  if (!data) return '(no data)';
  const lines = [];
  if (data.target) lines.push('PING ' + data.target);
  (data.results || []).forEach(r => {
    if (r.success !== undefined)
      lines.push(r.success ? `seq=${r.seq}  rtt=${r.rtt_ms}ms` : `seq=${r.seq}  ${r.error||'timeout'}`);
    else
      lines.push(JSON.stringify(r));
  });
  return lines.join('\n') || JSON.stringify(data, null, 2);
}

// ── Panel: Port Scan ─────────────────────────────────
function renderScanForm(panel, agentId) {
  panel.innerHTML = `
    <div class="action-form">
      <div class="action-form-title">Port Scan via Agent</div>
      <div class="field">
        <label>Target Host</label>
        <input type="text" class="scan-target" placeholder="192.168.1.1">
      </div>
      <div class="field-row">
        <div class="field">
          <label>Ports</label>
          <input type="text" class="scan-ports" placeholder="80,443,8000-8010">
        </div>
        <div class="field-sm">
          <label>Proto</label>
          <div class="proto-select-mount"></div>
        </div>
      </div>
      <div class="form-actions">
        <button class="btn-sm btn-primary scan-submit">Scan</button>
        <button class="btn-sm scan-cancel">Cancel</button>
      </div>
      <div class="status-msg scan-status"></div>
      <pre class="result-box scan-result" style="display:none;"></pre>
    </div>`;

  const protoSelect = createCustomSelect([
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' }
  ], 'tcp');
  panel.querySelector('.proto-select-mount').appendChild(protoSelect.container);

  panel.querySelector('.scan-cancel').addEventListener('click', () => clearAgentPanel(agentId));
  panel.querySelector('.scan-submit').addEventListener('click', async () => {
    const target = panel.querySelector('.scan-target').value.trim();
    const ports  = panel.querySelector('.scan-ports').value.trim();
    const proto  = protoSelect.getValue();
    const st     = panel.querySelector('.scan-status');
    const res_el = panel.querySelector('.scan-result');
    if (!target || !ports) {
      setStatus(st, 'Enter target and ports.', 'err');
      setTimeout(() => { if (st.textContent === 'Enter target and ports.') setStatus(st, ''); }, 5000);
      return;
    }
    setStatus(st, 'Scanning (may take up to 60s)…', '');
    hide(res_el);
    try {
      const data = await apiJSON(`/api/v1/agents/${agentId}/portscan`, {
        method: 'POST',
        body: JSON.stringify({ target, ports, proto })    
      });
      setStatus(st, 'Done.', 'ok');
      res_el.textContent = stripAnsi(data.output || '').trim() || '(no open ports)';
      show(res_el);
    } catch (e) { setStatus(st, e.message, 'err'); }
  });
}

// ── Panel: Tag ───────────────────────────────────────
function renderTagForm(panel, agentId, currentTag) {
  panel.innerHTML = `
    <div class="action-form">
      <div class="action-form-title">Set Tag</div>
      <div class="field">
        <label>Tag (max 64 chars)</label>
        <input type="text" class="tag-input" maxlength="64" placeholder="e.g. DC, pivot-1" value="${escHtml(currentTag)}">
      </div>
      <div class="form-actions">
        <button class="btn-sm btn-primary tag-save">Save</button>
        <button class="btn-sm tag-clear">Clear Tag</button>
        <button class="btn-sm tag-cancel">Cancel</button>
      </div>
      <div class="status-msg tag-status"></div>
    </div>`;

  panel.querySelector('.tag-cancel').addEventListener('click', () => clearAgentPanel(agentId));

  const doTag = async (clear) => {
    const tag = clear ? '' : panel.querySelector('.tag-input').value.trim();
    const st  = panel.querySelector('.tag-status');
    setStatus(st, 'Saving…', '');
    try {
      const res = await api(`/api/v1/agents/${agentId}/tag`, {
        method: 'POST',
        body: JSON.stringify({ tag })
      });
      if (!res.ok) { const t = await res.text(); throw new Error(parseErr(t, res.status)); }
      setStatus(st, clear ? 'Cleared.' : 'Saved.', 'ok');
      setTimeout(() => { clearAgentPanel(agentId); loadAgents(); }, 600);
    } catch (e) { setStatus(st, e.message, 'err'); }
  };

  panel.querySelector('.tag-save').addEventListener('click',  () => doTag(false));
  panel.querySelector('.tag-clear').addEventListener('click', () => doTag(true));
}

// ── Panel: Reconnect / Disconnect confirms ────────────
function renderReconnectConfirm(panel, agentId) {
  const confirm = document.createElement('div');
  confirm.className = 'action-form';
  panel.appendChild(confirm);
  askConfirm(confirm, 'Reconnect this agent?').then(async ok => {
    if (!ok) return;
    const st = document.createElement('div');
    st.className = 'status-msg';
    panel.appendChild(st);
    try {
      const res = await api(`/api/v1/agents/${agentId}/reconnect`, { method: 'POST' });
      if (!res.ok) { const t = await res.text(); throw new Error(parseErr(t, res.status)); }
      setStatus(st, 'Reconnect sent.', 'ok');
      setTimeout(() => clearAgentPanel(agentId), 800);
    } catch (e) { setStatus(st, e.message, 'err'); }
  });
}

function renderDisconnectConfirm(panel, agentId) {
  const confirm = document.createElement('div');
  confirm.className = 'action-form';
  panel.appendChild(confirm);
  askConfirm(confirm, 'Disconnect this agent?').then(async ok => {
    if (!ok) return;
    const st = document.createElement('div');
    st.className = 'status-msg';
    panel.appendChild(st);
    try {
      const res = await api(`/api/v1/agents/${agentId}/disconnect`, { method: 'POST' });
      if (!res.ok) { const t = await res.text(); throw new Error(parseErr(t, res.status)); }
      setStatus(st, 'Disconnected.', 'ok');
      setTimeout(() => { clearAgentPanel(agentId); loadAgents(); }, 800);
    } catch (e) { setStatus(st, e.message, 'err'); }
  });
}

// ══════════════════════════════════════════════════
//  CONNECT TO BIND AGENT
// ══════════════════════════════════════════════════
function openConnectBind() {
  const form = $('connect-bind-form');
  if (form.style.display !== 'none') {
    hide(form); return;
  }
   
  $('cb-host').value  = '';
  $('cb-port').value  = '';
  setStatus($('cb-status'), '');
  show(form);
  $('cb-host').focus();
}

async function submitConnectBind() {
  const host = $('cb-host').value.trim();
  const port = parseInt($('cb-port').value);
  if (!host || !port) { setStatus($('cb-status'), 'Enter host and port.', 'err'); return; }
  setStatus($('cb-status'), 'Sending…', '');
  try {
    const res = await api('/api/v1/connect-bind', {
      method: 'POST',
      body: JSON.stringify({ host, port })
    });
    if (res.status === 409) { setStatus($('cb-status'), 'Already connecting to that address.', 'err'); return; }
    if (!res.ok) { const t = await res.text(); throw new Error(parseErr(t, res.status)); }
     
    setStatus($('cb-status'), `Connecting to ${host}:${port}… (check Logs)`, 'ok');
    setTimeout(() => { hide($('connect-bind-form')); loadAgents(); }, 2500);
  } catch (e) { setStatus($('cb-status'), e.message, 'err'); }
}

// ══════════════════════════════════════════════════
//  FORWARDS TAB
// ══════════════════════════════════════════════════
async function loadForwards() {
  const fl = $('forwards-list'), rl = $('rforwards-list');
  fl.innerHTML = rl.innerHTML = '<div class="empty-state">Loading…</div>';
  try {
    const [fwds, rfwds] = await Promise.all([
      apiJSON('/api/v1/forwards'),
      apiJSON('/api/v1/rforwards')
    ]);
    renderForwardList(fl, fwds, false);
    renderForwardList(rl, rfwds, true);
  } catch (e) {
    const msg = `<div class="empty-state" style="color:var(--danger)">${escHtml(e.message)}</div>`;
    fl.innerHTML = rl.innerHTML = msg;
  }
}

function renderForwardList(container, items, isRev) {
  if (!items?.length) { container.innerHTML = '<div class="empty-state">None</div>'; return; }
  container.innerHTML = '';
  items.forEach(f => {
     
    const listenPort = f.listen_port     ?? f.agent_listen_port;
    const targetHost = f.target_host     ?? f.destination_host;
    const targetPort = f.target_port     ?? f.destination_port;
    const agentId    = f.agent_id        ?? f.destination_agent_id ?? '—';
    const proto = (f.protocol || 'tcp').toLowerCase();
    const bc    = isRev ? 'badge-rev' : proto === 'udp' ? 'badge-udp' : 'badge-tcp';
    const bl    = isRev ? 'REV' : proto.toUpperCase();
    const lbl   = isRev
      ? `Server :${listenPort} → Agent → ${targetHost}:${targetPort}`
      : `Agent  :${listenPort} → ${targetHost}:${targetPort}`;

    const row = document.createElement('div');
    row.className = 'forward-item';
    row.innerHTML = `
      <div class="forward-info">
        <div class="forward-label">${escHtml(lbl)}</div>
        <div class="forward-sub">Agent: ${escHtml(String(agentId).slice(0,8))}</div>
      </div>
      <span class="badge ${bc}">${bl}</span>
      <div class="fwd-del-wrap"></div>`;

     
    const wrap = row.querySelector('.fwd-del-wrap');
    const delBtn = document.createElement('button');
    delBtn.className = 'delete-btn';
    delBtn.title = 'Delete';
    delBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>`;
    wrap.appendChild(delBtn);

    delBtn.addEventListener('click', () => {
      closeAllInlineConfirms();  

      const originalDelBtnParent = delBtn.parentNode;
      const originalDelBtn = delBtn;

       
      wrap.innerHTML = '';
      const bar = document.createElement('div');
      bar.className = 'inline-confirm-sm';
      bar.innerHTML = `<button class="btn-sm btn-confirm-yes">Yes</button><button class="btn-sm btn-confirm-no">No</button>`;

      const cleanup = () => {
        wrap.innerHTML = '';
        if (originalDelBtnParent && originalDelBtn) {
          originalDelBtnParent.appendChild(originalDelBtn);
        }
        const index = activeConfirmCleanupFns.indexOf(cleanup);
        if (index > -1) activeConfirmCleanupFns.splice(index, 1);
      };
      activeConfirmCleanupFns.push(cleanup);

      bar.querySelector('.btn-confirm-no').addEventListener('click', () => {
        cleanup();
      });
      bar.querySelector('.btn-confirm-yes').addEventListener('click', async () => {
        const fid = f.id || f.listener_id || '';
        if (!fid) { cleanup(); wrap.innerHTML = 'No ID!'; return; }
        const ep = isRev ? '/api/v1/rforwards' : '/api/v1/forwards';
        try {
          const res = await api(`${ep}?id=${encodeURIComponent(fid)}`, { method: 'DELETE' });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          cleanup();
          loadForwards();
        } catch (e) { cleanup(); wrap.textContent = 'Error: ' + e.message; }
      });
      wrap.appendChild(bar);
    });

    container.appendChild(row);
  });
}

// ══════════════════════════════════════════════════
//  ROUTES TAB
// ══════════════════════════════════════════════════
async function loadRoutes() {
  const list = $('routes-list');
  list.innerHTML = '<div class="empty-state">Loading…</div>';
  try {
    const routes = await apiJSON('/api/v1/routes');
    if (!routes?.length) { list.innerHTML = '<div class="empty-state">No routes</div>'; return; }
    list.innerHTML = '';
    routes.forEach(r => {
      const item = document.createElement('div');
      item.className = 'route-item';
      item.innerHTML = `
        <span class="route-subnet">${escHtml(r.subnet)}</span>
        <span class="route-agent">${escHtml((r.agent_id||'').slice(0,8))}</span>
        <button class="route-toggle ${r.disabled?'':'enabled'}" data-subnet="${escHtml(r.subnet)}">
          <div class="track"></div><div class="knob"></div>
        </button>`;
      item.querySelector('.route-toggle').addEventListener('click', async function() {
        const subnet     = this.dataset.subnet;
        const nowDisable = this.classList.contains('enabled');
        try {
          const res = await api('/api/v1/routes', {
            method: 'PATCH',
            body: JSON.stringify({ subnet, disabled: nowDisable })
          });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          this.classList.toggle('enabled', !nowDisable);
        } catch (e) { alert(e.message); }
      });
      list.appendChild(item);
    });
  } catch (e) {
    list.innerHTML = `<div class="empty-state" style="color:var(--danger)">${escHtml(e.message)}</div>`;
  }
}

// ══════════════════════════════════════════════════
//  LOGS TAB
// ══════════════════════════════════════════════════
async function loadLogs() {
  const out = $('log-output');
  out.textContent = 'Loading…';
  try {
    const data = await apiJSON('/api/dashboard-data');
    renderLogOutput(data);
  } catch (e) { out.textContent = 'Error: ' + e.message; }
}

function renderLogOutput(data) {
  if (!data) return;
  const lines = currentLogType === 'server'
    ? (data.server_log || [])
    : (data.cli_log    || []);
  const out = $('log-output');
   
  out.textContent = lines.map(stripAnsi).join('\n') || '(no entries)';
  out.scrollTop = out.scrollHeight;
}

// ══════════════════════════════════════════════════
//  SETTINGS TAB
// ══════════════════════════════════════════════════
async function loadSettings() {
  const { key } = await chrome.storage.local.get('key').catch(() => ({}));
  $('s-current-key').textContent = key || '—';

  try {
    const d = await apiJSON('/api/v1/settings');
    $('s-http-port').value = d.http_port || '';
    $('s-tcp-port').value  = d.tcp_port  || '';
    $('s-udp-port').value  = d.udp_port  || '';
    $('s-dns-port').value  = d.dns_port  || '';
  } catch { /* best-effort */ }
}

async function savePorts() {
  const http = parseInt($('s-http-port').value);
  const tcp  = parseInt($('s-tcp-port').value);
  const udp  = parseInt($('s-udp-port').value);
  const dns  = parseInt($('s-dns-port').value);
  const st   = $('ports-status');

  if ([http, tcp, udp, dns].some(p => !p || p < 1 || p > 65535)) {
    setStatus(st, 'Invalid port value.', 'err'); return;
  }
  setStatus(st, 'Saving…', '');
  try {
    const res = await api('/api/v1/settings', {
      method: 'PATCH',
      body: JSON.stringify({ http_port: http, tcp_port: tcp, udp_port: udp, dns_port: dns })
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || `HTTP ${res.status}`);
    setStatus(st, 'Ports saved.', 'ok');
  } catch (e) { setStatus(st, e.message, 'err'); }
}

async function regenKey() {
  const wrap = $('regen-confirm-wrap');
  askConfirm(wrap, 'Regenerate key? All agents will disconnect.').then(async ok => {
    if (!ok) return;
    setStatus($('settings-status'), 'Regenerating…', '');
    try {
      const res = await api('/api/v1/settings', {
        method: 'PATCH',
        body: JSON.stringify({ action: 'regenerate' })
      });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || `HTTP ${res.status}`);
      if (d.new_key) {
        $('s-current-key').textContent = d.new_key;
        await chrome.storage.local.set({ key: d.new_key });
      }
      setStatus($('settings-status'), 'Key regenerated.', 'ok');
      setTimeout(loadAgents, 1000);
    } catch (e) { setStatus($('settings-status'), e.message, 'err'); }
  });
}

async function doShutdown() {
  const wrap = $('shutdown-confirm-wrap');
  askConfirm(wrap, 'Shut down the server?').then(async ok => {
    if (!ok) return;
    setStatus($('settings-status'), 'Shutting down…', '');
    try {
      const res = await api('/api/v1/shutdown', { method: 'POST' });
      setStatus($('settings-status'), res.ok ? 'Shutdown initiated.' : `Error: HTTP ${res.status}`, res.ok ? 'ok' : 'err');
    } catch (e) { setStatus($('settings-status'), e.message, 'err'); }
  });
}

// ══════════════════════════════════════════════════
//  SCREEN MANAGEMENT
// ══════════════════════════════════════════════════
function showLoginScreen() {
  hide($('dashboard-screen'));
  $('login-screen').style.display = '';
}

async function showDashboardScreen() {
  hide($('login-screen'));
  $('dashboard-screen').style.display = '';
  const { theme } = await chrome.storage.local.get('theme').catch(() => ({}));
  applyTheme(theme || 'dark');
  const url = new URL(serverUrl);
  $('server-label').textContent = url.hostname + ':' + url.port;
  switchTab('agents');
  await loadAgents();
}

async function doLogout() {
  await chrome.storage.local.remove(['serverUrl','token','key']);
  serverUrl = bearerToken = '';
  showLoginScreen();
}

// ══════════════════════════════════════════════════
//  INIT
// ══════════════════════════════════════════════════
async function init() {
  const s = await chrome.storage.local.get(['serverUrl','token','theme']).catch(() => ({}));
  if (s.theme) applyTheme(s.theme);
  if (s.serverUrl && s.token) {
    serverUrl = s.serverUrl; bearerToken = s.token;
    if (await checkAuth()) { await showDashboardScreen(); return; }
    await refreshToken();
    if (bearerToken)       { await showDashboardScreen(); return; }
    try { const u = new URL(s.serverUrl); $('login-ip').value = u.hostname; $('login-port').value = u.port; } catch {}
  }
  showLoginScreen();
}

// ══════════════════════════════════════════════════
//  EVENT LISTENERS
// ══════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {

  // Login
  $('login-form').addEventListener('submit', async e => {
    e.preventDefault();
    const ip = $('login-ip').value.trim(), port = $('login-port').value.trim(), key = $('login-key').value.trim();
    const errEl = $('login-error'), btn = $('login-btn');
    if (!ip || !port || !key) { errEl.textContent = 'Fill in all fields.'; show(errEl); return; }
    btn.disabled = true; btn.textContent = 'Logging in…'; hide(errEl);
    try {
      const { base, token } = await doLogin(ip, port, key);
      serverUrl = base; bearerToken = token;
      await chrome.storage.local.set({ serverUrl: base, token, key });
      await showDashboardScreen();
    } catch (err) { errEl.textContent = err.message; show(errEl); }
    finally { btn.disabled = false; btn.textContent = 'Login'; }
  });

  $('toggle-key-vis').addEventListener('click', () => {
    const inp = $('login-key'); inp.type = inp.type === 'password' ? 'text' : 'password';
  });

  // Tabs
  document.querySelectorAll('.tab').forEach(t =>
    t.addEventListener('click', () => switchTab(t.dataset.tab)));

  // Log sub-tabs
  document.querySelectorAll('.log-tab').forEach(b =>
    b.addEventListener('click', () => {
      document.querySelectorAll('.log-tab').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      currentLogType = b.dataset.log;
      loadLogs();
    }));

  // Header
  $('open-dashboard-btn').addEventListener('click', () => chrome.tabs.create({ url: serverUrl + '/dashboard' }));
  $('theme-btn').addEventListener('click', async () => {
    const t = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(t);
    await chrome.storage.local.set({ theme: t });
  });
  $('logout-btn').addEventListener('click', doLogout);

  // Agents tab
  $('connect-bind-btn').addEventListener('click', openConnectBind);
  $('refresh-btn').addEventListener('click',      loadAgents);
  $('cb-submit-btn').addEventListener('click',    submitConnectBind);
  $('cb-cancel-btn').addEventListener('click',    () => hide($('connect-bind-form')));

  // Forwards
  $('forwards-refresh-btn').addEventListener('click', loadForwards);

  // Routes
  $('routes-refresh-btn').addEventListener('click', loadRoutes);

  // Logs
  $('logs-refresh-btn').addEventListener('click', loadLogs);
  $('logs-clear-btn').addEventListener('click',   () => { $('log-output').textContent = ''; });

  // Settings
  $('regen-key-btn').addEventListener('click',   regenKey);
  $('save-ports-btn').addEventListener('click',  savePorts);
  $('shutdown-btn').addEventListener('click',    doShutdown);
  $('switch-server-btn').addEventListener('click', doLogout);
  $('copy-key-btn').addEventListener('click', () => {
    const k = $('s-current-key').textContent;
    if (k && k !== '—') navigator.clipboard.writeText(k).then(() => {
      setStatus($('settings-status'), 'Copied!', 'ok');
      setTimeout(() => setStatus($('settings-status'), ''), 1200);
    });
  });

  init();
});