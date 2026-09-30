/**
 * SentinelLog - Frontend SOC Dashboard Application Logic
 * Real-time WebSocket event ingestion, Chart.js visualizations, alert triage, and simulation controls.
 */

// Global State
const state = {
  ws: null,
  wsConnected: false,
  autoScroll: true,
  logFilter: '',
  logTypeFilter: 'ALL',
  alertFilter: 'ALL',
  logs: [],
  alerts: [],
  metrics: {},
  maxDisplayLogs: 200,
  velocityChart: null,
  severityChart: null,
  attackersChart: null,
  activeAlertModal: null
};

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  initWebSocket();
  initEventListeners();
  fetchInitialData();
  setupDropzone();
});

/**
 * Initialize Chart.js instances
 */
function initCharts() {
  Chart.defaults.color = '#94a3b8';
  Chart.defaults.font.family = "'Inter', sans-serif";

  // 1. Live Event Velocity Line Chart
  const velocityCtx = document.getElementById('velocityChart')?.getContext('2d');
  if (velocityCtx) {
    const gradient = velocityCtx.createLinearGradient(0, 0, 0, 180);
    gradient.addColorStop(0, 'rgba(99, 102, 241, 0.45)');
    gradient.addColorStop(1, 'rgba(99, 102, 241, 0.0)');

    state.velocityChart = new Chart(velocityCtx, {
      type: 'line',
      data: {
        labels: Array(20).fill(''),
        datasets: [{
          label: 'Events / Sec',
          data: Array(20).fill(0),
          borderColor: '#818cf8',
          borderWidth: 2,
          backgroundColor: gradient,
          fill: true,
          tension: 0.35,
          pointRadius: 2,
          pointHoverRadius: 5,
          pointBackgroundColor: '#6366f1'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 400 },
        scales: {
          x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { maxTicksLimit: 6, font: { size: 10 } } },
          y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, beginAtZero: true, suggestedMax: 10, ticks: { font: { size: 10 } } }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0f172a',
            borderColor: 'rgba(255, 255, 255, 0.1)',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#cbd5e1'
          }
        }
      }
    });
  }

  // 2. Alert Severity Doughnut Chart
  const severityCtx = document.getElementById('severityChart')?.getContext('2d');
  if (severityCtx) {
    state.severityChart = new Chart(severityCtx, {
      type: 'doughnut',
      data: {
        labels: ['High', 'Medium', 'Low / Info'],
        datasets: [{
          data: [0, 0, 0],
          backgroundColor: ['#f43f5e', '#f59e0b', '#06b6d4'],
          borderColor: '#0d1322',
          borderWidth: 2,
          hoverOffset: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: {
          legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 }, padding: 12 } }
        }
      }
    });
  }

  // 3. Top Attackers Bar Chart
  const attackersCtx = document.getElementById('attackersChart')?.getContext('2d');
  if (attackersCtx) {
    state.attackersChart = new Chart(attackersCtx, {
      type: 'bar',
      data: {
        labels: ['No Data'],
        datasets: [{
          label: 'Alerts',
          data: [0],
          backgroundColor: '#f43f5e',
          borderRadius: 4
        }, {
          label: 'Total Requests',
          data: [0],
          backgroundColor: '#38bdf8',
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        scales: {
          x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, beginAtZero: true },
          y: { grid: { display: false } }
        },
        plugins: {
          legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 10 } } }
        }
      }
    });
  }
}

/**
 * Setup WebSocket Client Connection
 */
function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  updateConnectionStatus('connecting');

  try {
    state.ws = new WebSocket(wsUrl);

    state.ws.onopen = () => {
      state.wsConnected = true;
      updateConnectionStatus('connected');
      showToast('WebSocket connected to SentinelLog SOC engine.', 'success');
    };

    state.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleWsMessage(msg);
      } catch (err) {
        console.error('Error parsing WebSocket message:', err);
      }
    };

    state.ws.onclose = () => {
      state.wsConnected = false;
      updateConnectionStatus('disconnected');
      // Auto-reconnect after 3s
      setTimeout(initWebSocket, 3000);
    };

    state.ws.onerror = (err) => {
      console.warn('WebSocket encountered error:', err);
      state.wsConnected = false;
      updateConnectionStatus('disconnected');
    };
  } catch (err) {
    console.error('Failed to initialize WebSocket:', err);
    setTimeout(initWebSocket, 4000);
  }
}

/**
 * Handle incoming WebSocket messages from backend
 */
function handleWsMessage(msg) {
  switch (msg.type) {
    case 'INIT_STATE':
      if (msg.metrics) updateMetricsDisplay(msg.metrics);
      if (msg.alerts && Array.isArray(msg.alerts)) {
        state.alerts = msg.alerts;
        renderAlertsTable();
      }
      if (msg.recentLogs && Array.isArray(msg.recentLogs)) {
        state.logs = msg.recentLogs.slice().reverse();
        renderLogFeed();
      }
      break;

    case 'LOG_INGESTED':
      if (msg.log) {
        appendLogEvent(msg.log);
      }
      break;

    case 'ALERT_TRIGGERED':
      if (msg.alert) {
        handleNewAlert(msg.alert);
      }
      if (msg.metrics) updateMetricsDisplay(msg.metrics);
      break;

    case 'METRICS_UPDATE':
      if (msg.metrics) updateMetricsDisplay(msg.metrics);
      break;

    case 'SIMULATION_UPDATE':
      showToast(`Simulation step ${msg.step}/${msg.total}: ${msg.scenario}`, 'info');
      break;

    case 'LOGS_CLEARED':
      state.logs = [];
      renderLogFeed();
      break;

    default:
      break;
  }
}

/**
 * Update Connection Status Indicator in UI
 */
function updateConnectionStatus(status) {
  const dot = document.getElementById('connectionDot');
  const label = document.getElementById('connectionLabel');

  if (!dot || !label) return;

  if (status === 'connected') {
    dot.className = 'h-2.5 w-2.5 rounded-full bg-emerald-400 pulse-emerald';
    label.innerText = 'ONLINE / STREAMING';
    label.className = 'text-xs font-semibold text-emerald-400 tracking-wider';
  } else if (status === 'connecting') {
    dot.className = 'h-2.5 w-2.5 rounded-full bg-amber-400 animate-ping';
    label.innerText = 'CONNECTING...';
    label.className = 'text-xs font-semibold text-amber-400 tracking-wider';
  } else {
    dot.className = 'h-2.5 w-2.5 rounded-full bg-rose-500';
    label.innerText = 'DISCONNECTED';
    label.className = 'text-xs font-semibold text-rose-500 tracking-wider';
  }
}

/**
 * Update Top Metric Counters & Charts
 */
function updateMetricsDisplay(metrics) {
  state.metrics = metrics;

  // Counters
  document.getElementById('totalEventsCount').innerText = Number(metrics.totalEvents || 0).toLocaleString();
  document.getElementById('highAlertsCount').innerText = metrics.activeHighAlerts || 0;
  document.getElementById('mediumAlertsCount').innerText = metrics.activeMediumAlerts || 0;
  document.getElementById('lowAlertsCount').innerText = metrics.activeLowAlerts || 0;
  document.getElementById('epsValue').innerText = `${metrics.currentEps || 0} EPS`;

  // Pulse high alerts box if > 0
  const highBox = document.getElementById('highAlertsBox');
  if (highBox) {
    if (metrics.activeHighAlerts > 0) {
      highBox.classList.add('pulse-rose');
    } else {
      highBox.classList.remove('pulse-rose');
    }
  }

  // Update Velocity Chart
  if (state.velocityChart && Array.isArray(metrics.velocityHistory)) {
    const labels = metrics.velocityHistory.map(h => h.time);
    const data = metrics.velocityHistory.map(h => h.eps);
    state.velocityChart.data.labels = labels;
    state.velocityChart.data.datasets[0].data = data;
    state.velocityChart.update('none');
  }

  // Update Severity Doughnut Chart
  if (state.severityChart && metrics.severityBreakdown) {
    state.severityChart.data.datasets[0].data = [
      (metrics.severityBreakdown.High || 0) + (metrics.severityBreakdown.Critical || 0),
      metrics.severityBreakdown.Medium || 0,
      (metrics.severityBreakdown.Low || 0) + (metrics.severityBreakdown.Info || 0)
    ];
    state.severityChart.update();
  }

  // Update Top Attackers Bar Chart
  if (state.attackersChart && Array.isArray(metrics.topAttackers)) {
    if (metrics.topAttackers.length === 0) {
      state.attackersChart.data.labels = ['No Threat IPs'];
      state.attackersChart.data.datasets[0].data = [0];
      state.attackersChart.data.datasets[1].data = [0];
    } else {
      state.attackersChart.data.labels = metrics.topAttackers.map(a => a.ip);
      state.attackersChart.data.datasets[0].data = metrics.topAttackers.map(a => a.alerts);
      state.attackersChart.data.datasets[1].data = metrics.topAttackers.map(a => a.requests);
    }
    state.attackersChart.update();
  }
}

/**
 * Append a single log to the terminal stream
 */
function appendLogEvent(log) {
  state.logs.push(log);
  if (state.logs.length > state.maxDisplayLogs) {
    state.logs.shift();
  }

  if (matchesLogFilter(log)) {
    const feed = document.getElementById('terminalFeed');
    if (feed) {
      const lineEl = document.createElement('div');
      lineEl.className = 'terminal-line py-1 px-2 border-b border-white/5 hover:bg-white/5 flex items-start space-x-2 font-mono text-xs';
      lineEl.innerHTML = formatLogLineHtml(log);
      feed.appendChild(lineEl);

      // Auto-scroll if enabled
      if (state.autoScroll) {
        feed.scrollTop = feed.scrollHeight;
      }
    }
  }

  document.getElementById('logStreamCount').innerText = `${state.logs.length} events buffered`;
}

/**
 * Render all current logs in buffer to terminal
 */
function renderLogFeed() {
  const feed = document.getElementById('terminalFeed');
  if (!feed) return;

  feed.innerHTML = '';
  const filtered = state.logs.filter(matchesLogFilter);

  if (filtered.length === 0) {
    feed.innerHTML = `<div class="text-slate-500 text-center py-8 text-xs font-mono">No log events in buffer. Click "Simulate Attack" or upload log files above to stream events.</div>`;
    return;
  }

  for (const log of filtered) {
    const lineEl = document.createElement('div');
    lineEl.className = 'terminal-line py-1 px-2 border-b border-white/5 hover:bg-white/5 flex items-start space-x-2 font-mono text-xs';
    lineEl.innerHTML = formatLogLineHtml(log);
    feed.appendChild(lineEl);
  }

  if (state.autoScroll) {
    feed.scrollTop = feed.scrollHeight;
  }
}

/**
 * Filter matching logic for logs
 */
function matchesLogFilter(log) {
  if (state.logTypeFilter === 'ACCESS' && log.type !== 'access_log') return false;
  if (state.logTypeFilter === 'AUTH' && log.type !== 'auth_log') return false;
  if (state.logTypeFilter === 'MALFORMED' && log.parsed !== false) return false;

  if (state.logFilter) {
    const q = state.logFilter.toLowerCase();
    const raw = (log.raw || JSON.stringify(log)).toLowerCase();
    const ip = (log.ip || '').toLowerCase();
    return raw.includes(q) || ip.includes(q);
  }
  return true;
}

/**
 * HTML Syntax Highlighter for Log Line
 */
function formatLogLineHtml(log) {
  const time = log.timestamp ? log.timestamp.split('T')[1]?.substring(0, 8) || '00:00:00' : '00:00:00';
  const timeHtml = `<span class="log-time text-slate-500 select-none">[${time}]</span>`;

  if (log.type === 'access_log') {
    const methodClass = log.method === 'GET' ? 'log-method-get' : 'log-method-post';
    const statusClass = log.statusCode < 300 ? 'log-status-200' : log.statusCode === 404 ? 'log-status-404' : 'log-status-403';
    
    // Highlight potential SQLi / Traversal signatures in path
    let highlightedPath = escapeHtml(log.path || '/');
    if (/(?:union\s+select|or\s+1=1|\.\.\/|win\.ini|\/etc\/passwd)/i.test(highlightedPath)) {
      highlightedPath = `<span class="log-threat">${highlightedPath}</span>`;
    }

    return `
      ${timeHtml}
      <span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-300">HTTP</span>
      <span class="log-ip">${escapeHtml(log.ip || '0.0.0.0')}</span>
      <span class="${methodClass}">${log.method || 'GET'}</span>
      <span class="log-path flex-1 truncate">${highlightedPath}</span>
      <span class="${statusClass} font-mono font-semibold">${log.statusCode || 200}</span>
      <span class="text-slate-500 text-[11px]">${log.bytes || 0}B</span>
    `;
  }

  if (log.type === 'auth_log') {
    const isFailed = log.authStatus === 'FAILED';
    const badgeClass = isFailed ? 'log-auth-failed' : 'log-auth-ok';
    const authText = isFailed ? 'AUTH FAILED' : 'AUTH OK';

    return `
      ${timeHtml}
      <span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300">AUTH</span>
      <span class="log-ip">${escapeHtml(log.ip || '127.0.0.1')}</span>
      <span class="text-slate-400 font-semibold">${escapeHtml(log.daemon || 'sshd')}:</span>
      <span class="${badgeClass} text-[11px]">${authText}</span>
      <span class="text-slate-300 flex-1 truncate">${escapeHtml(log.message || log.raw || '')}</span>
    `;
  }

  return `
    ${timeHtml}
    <span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-700 text-slate-300">RAW</span>
    <span class="text-slate-400 font-mono flex-1 truncate">${escapeHtml(log.raw || '')}</span>
  `;
}

/**
 * Handle incoming new alert
 */
function handleNewAlert(alert) {
  // Prepend to state
  state.alerts.unshift(alert);
  if (state.alerts.length > 200) state.alerts.pop();

  renderAlertsTable();

  // Play audio / show visual toast
  const audio = document.getElementById('alertAudio');
  if (audio && alert.severity === 'High') {
    audio.play().catch(() => {}); // Audio autoplay might be blocked
  }

  showToast(`🚨 ${alert.severity.toUpperCase()} ALERT: ${alert.ruleName} from ${alert.attackerIp}`, alert.severity.toLowerCase());
}

/**
 * Render Alerts Table
 */
function renderAlertsTable() {
  const tbody = document.getElementById('alertsTableBody');
  if (!tbody) return;

  const filtered = state.alerts.filter(a => {
    if (state.alertFilter === 'ALL') return true;
    return a.severity.toUpperCase() === state.alertFilter;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="px-4 py-8 text-center text-slate-500 font-mono text-xs">
          No security alerts recorded. Ingest logs or trigger a simulation.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = '';
  for (const alert of filtered) {
    const tr = document.createElement('tr');
    tr.className = 'border-b border-white/5 hover:bg-white/5 transition-colors text-xs font-mono';
    
    let badgeClass = 'badge-info';
    if (alert.severity === 'High') badgeClass = 'badge-high';
    else if (alert.severity === 'Medium') badgeClass = 'badge-medium';
    else if (alert.severity === 'Low') badgeClass = 'badge-low';

    const timeStr = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'Just now';
    const evidenceSnippet = alert.evidence && alert.evidence.length > 0
      ? alert.evidence[0].substring(0, 65) + (alert.evidence[0].length > 65 ? '...' : '')
      : 'Rule threshold criteria met';

    tr.innerHTML = `
      <td class="px-4 py-3 whitespace-nowrap">
        <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${badgeClass}">${alert.severity}</span>
      </td>
      <td class="px-4 py-3 whitespace-nowrap">
        <div class="font-bold text-slate-200">${escapeHtml(alert.ruleId)}</div>
        <div class="text-[11px] text-slate-400">${escapeHtml(alert.ruleName)}</div>
      </td>
      <td class="px-4 py-3 whitespace-nowrap">
        <div class="flex items-center space-x-1.5">
          <span class="font-bold text-sky-400">${escapeHtml(alert.attackerIp)}</span>
          <button onclick="copyToClipboard('${alert.attackerIp}', 'IP copied')" class="text-slate-500 hover:text-slate-300 text-[11px] p-1" title="Copy IP">
            📋
          </button>
        </div>
      </td>
      <td class="px-4 py-3 whitespace-nowrap text-slate-400">
        ${timeStr}
      </td>
      <td class="px-4 py-3 max-w-xs truncate text-slate-300" title="${escapeHtml(alert.evidence ? alert.evidence.join('\n') : '')}">
        ${escapeHtml(evidenceSnippet)}
      </td>
      <td class="px-4 py-3 whitespace-nowrap text-right">
        <button onclick="openTriageModal('${alert.id}')" class="px-2.5 py-1 rounded bg-indigo-600/30 hover:bg-indigo-600/60 text-indigo-300 hover:text-white border border-indigo-500/40 text-[11px] transition-all">
          Triage / Mitigate
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

/**
 * Open Alert Triage Modal
 */
window.openTriageModal = function(alertId) {
  const alert = state.alerts.find(a => a.id === alertId);
  if (!alert) return;

  state.activeAlertModal = alert;

  document.getElementById('triageAlertId').innerText = alert.id;
  document.getElementById('triageRuleId').innerText = alert.ruleId;
  document.getElementById('triageRuleName').innerText = alert.ruleName;
  document.getElementById('triageSeverity').innerText = alert.severity;
  document.getElementById('triageSeverity').className = `px-2 py-0.5 rounded text-xs font-bold uppercase ${alert.severity === 'High' ? 'badge-high' : alert.severity === 'Medium' ? 'badge-medium' : 'badge-low'}`;
  document.getElementById('triageAttackerIp').innerText = alert.attackerIp;
  document.getElementById('triageTarget').innerText = alert.target || 'N/A';
  document.getElementById('triageTimestamp').innerText = new Date(alert.timestamp).toLocaleString();
  document.getElementById('triageMitre').innerText = alert.mitreTechnique || 'N/A';
  document.getElementById('triageDescription').innerText = alert.description || '';
  
  // Format Evidence
  const evidenceContainer = document.getElementById('triageEvidence');
  if (evidenceContainer) {
    if (alert.evidence && alert.evidence.length > 0) {
      evidenceContainer.innerHTML = alert.evidence.map(e => `<div class="py-1 border-b border-white/5 font-mono text-xs text-rose-300/90 whitespace-pre-wrap">${escapeHtml(e)}</div>`).join('');
    } else {
      evidenceContainer.innerHTML = `<div class="text-slate-500 text-xs font-mono">No raw log lines attached.</div>`;
    }
  }

  // Format Suggested Mitigation
  document.getElementById('triageMitigationText').innerText = alert.mitigation || 'Isolate IP at network boundary.';

  const modal = document.getElementById('triageModal');
  modal.classList.remove('hidden');
};

window.closeTriageModal = function() {
  const modal = document.getElementById('triageModal');
  modal.classList.add('hidden');
};

window.copyMitigationCommand = function() {
  if (state.activeAlertModal && state.activeAlertModal.mitigation) {
    const lines = state.activeAlertModal.mitigation.split('\n');
    const cmd = lines[0].replace(/^(Execute firewall isolation:|Add iptables drop rule:|Sanitize URL.*Add immediate WAF filter or drop rule:)\s*/i, '');
    copyToClipboard(cmd.trim() || state.activeAlertModal.mitigation, 'Remediation command copied to clipboard!');
  }
};

/**
 * Trigger an automated attack simulation
 */
window.triggerSimulation = async function(scenarioId = 'ssh-brute-force') {
  try {
    showToast(`Starting attack simulation: ${scenarioId}...`, 'info');
    const res = await fetch('/api/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: scenarioId })
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Simulation '${scenarioId}' successfully launched!`, 'success');
    } else {
      showToast(`Simulation failed: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast(`Error triggering simulation: ${err.message}`, 'error');
  }
};

/**
 * Load Sample Log Files
 */
window.loadSampleFixture = async function(fixtureName) {
  try {
    showToast(`Loading sample ${fixtureName}...`, 'info');
    let sampleContent = '';

    if (fixtureName === 'auth.log') {
      sampleContent = `Sep 30 14:10:00 sec-srv-01 sshd[1301]: Failed password for invalid user admin from 198.51.100.42 port 52001 ssh2\n` +
        `Sep 30 14:10:01 sec-srv-01 sshd[1302]: Failed password for root from 198.51.100.42 port 52002 ssh2\n` +
        `Sep 30 14:10:01 sec-srv-01 sshd[1303]: Failed password for invalid user ubuntu from 198.51.100.42 port 52003 ssh2\n` +
        `Sep 30 14:10:02 sec-srv-01 sshd[1304]: Failed password for invalid user deploy from 198.51.100.42 port 52004 ssh2\n` +
        `Sep 30 14:10:02 sec-srv-01 sshd[1305]: Failed password for invalid user postgres from 198.51.100.42 port 52005 ssh2\n` +
        `Sep 30 14:10:03 sec-srv-01 sshd[1306]: Failed password for root from 198.51.100.42 port 52006 ssh2`;
    } else if (fixtureName === 'access.log') {
      sampleContent = `185.220.101.5 - - [30/Sep/2026:14:05:01 +0000] "GET /static/../../../../etc/passwd HTTP/1.1" 403 512 "-" "DirBuster"\n` +
        `203.0.113.88 - - [30/Sep/2026:14:06:10 +0000] "GET /api/v1/users?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 3420 "-" "Sqlmap"\n` +
        `203.0.113.88 - - [30/Sep/2026:14:06:11 +0000] "GET /products/search?query=test%27%20UNION%20SELECT%20null,password%20FROM%20users-- HTTP/1.1" 200 4890 "-" "Sqlmap"`;
    } else if (fixtureName === 'mixed.log') {
      sampleContent = `Sep 30 15:01:00 gateway sshd[2310]: Failed password for invalid user admin from 198.51.100.42 port 51001 ssh2\n` +
        `Sep 30 15:01:01 gateway sshd[2311]: Failed password for root from 198.51.100.42 port 51002 ssh2\n` +
        `Sep 30 15:01:02 gateway sshd[2312]: Failed password for invalid user guest from 198.51.100.42 port 51003 ssh2\n` +
        `Sep 30 15:01:02 gateway sshd[2313]: Failed password for invalid user support from 198.51.100.42 port 51004 ssh2\n` +
        `Sep 30 15:01:03 gateway sshd[2314]: Failed password for invalid user db from 198.51.100.42 port 51005 ssh2\n` +
        `203.0.113.88 - - [30/Sep/2026:15:02:10 +0000] "GET /search?q=1%27%20UNION%20SELECT%20user,password%20FROM%20users-- HTTP/1.1" 200 2100 "-" "Sqlmap"\n` +
        `185.220.101.5 - - [30/Sep/2026:15:02:20 +0000] "GET /view?page=../../../../etc/passwd HTTP/1.1" 403 230 "-" "curl"`;
    }

    await ingestRawText(sampleContent);
  } catch (err) {
    showToast(`Failed to load fixture: ${err.message}`, 'error');
  }
};

/**
 * Ingest raw log string via API
 */
async function ingestRawText(text) {
  if (!text || !text.trim()) {
    showToast('No log text provided.', 'error');
    return;
  }

  const res = await fetch('/api/logs/ingest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ logs: text })
  });

  const data = await res.json();
  if (data.success) {
    showToast(`Ingested ${data.totalLines} lines (${data.parsedCount} parsed, ${data.alertsTriggered} alerts triggered)`, 'success');
  } else {
    showToast(`Ingestion error: ${data.error}`, 'error');
  }
}

/**
 * Reset entire dashboard state
 */
window.resetDashboard = async function() {
  if (!confirm('Are you sure you want to reset the SIEM dashboard state?')) return;
  try {
    const res = await fetch('/api/reset', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      state.logs = [];
      state.alerts = [];
      renderLogFeed();
      renderAlertsTable();
      fetchInitialData();
      showToast('Dashboard reset successfully.', 'info');
    }
  } catch (err) {
    showToast(`Reset failed: ${err.message}`, 'error');
  }
};

/**
 * Export Alerts as JSON
 */
window.exportAlertsJson = function() {
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.alerts, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `sentinellog-alerts-${Date.now()}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
};

/**
 * Fetch initial metrics & alerts from REST API
 */
async function fetchInitialData() {
  try {
    const [metricsRes, alertsRes] = await Promise.all([
      fetch('/api/metrics'),
      fetch('/api/alerts')
    ]);

    const metricsData = await metricsRes.json();
    const alertsData = await alertsRes.json();

    if (metricsData.success) updateMetricsDisplay(metricsData.metrics);
    if (alertsData.success) {
      state.alerts = alertsData.alerts;
      renderAlertsTable();
    }
  } catch (err) {
    console.error('Error fetching initial data:', err);
  }
}

/**
 * Setup Drag-and-Drop Ingestion Dropzone
 */
function setupDropzone() {
  const dropzone = document.getElementById('logDropzone');
  const fileInput = document.getElementById('logFileInput');

  if (!dropzone || !fileInput) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.add('dropzone-active');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.remove('dropzone-active');
    }, false);
  });

  dropzone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
      handleFileUpload(files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (fileInput.files.length > 0) {
      handleFileUpload(fileInput.files[0]);
    }
  });
}

/**
 * Upload log file via FormData
 */
async function handleFileUpload(file) {
  showToast(`Uploading ${file.name} (${Math.round(file.size / 1024)} KB)...`, 'info');
  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/logs/ingest', {
      method: 'POST',
      body: formData
    });

    const data = await res.json();
    if (data.success) {
      showToast(`Processed ${file.name}: ${data.totalLines} lines (${data.alertsTriggered} alerts triggered)`, 'success');
    } else {
      showToast(`Upload failed: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast(`Upload error: ${err.message}`, 'error');
  }
}

/**
 * Setup UI Event Listeners
 */
function initEventListeners() {
  // Auto-scroll toggle
  const autoScrollBtn = document.getElementById('toggleAutoScroll');
  if (autoScrollBtn) {
    autoScrollBtn.addEventListener('click', () => {
      state.autoScroll = !state.autoScroll;
      autoScrollBtn.innerText = state.autoScroll ? '⏸ Pause Scroll' : '▶ Resume Scroll';
      autoScrollBtn.className = state.autoScroll ? 'px-2 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs' : 'px-2 py-1 rounded bg-amber-600/30 text-amber-300 border border-amber-500/40 text-xs';
    });
  }

  // Clear Terminal Feed
  const clearFeedBtn = document.getElementById('clearFeedBtn');
  if (clearFeedBtn) {
    clearFeedBtn.addEventListener('click', () => {
      state.logs = [];
      renderLogFeed();
    });
  }

  // Terminal Filter Input
  const logSearchInput = document.getElementById('logSearchInput');
  if (logSearchInput) {
    logSearchInput.addEventListener('input', (e) => {
      state.logFilter = e.target.value;
      renderLogFeed();
    });
  }

  // Terminal Log Type Filter
  const logTypeSelect = document.getElementById('logTypeSelect');
  if (logTypeSelect) {
    logTypeSelect.addEventListener('change', (e) => {
      state.logTypeFilter = e.target.value;
      renderLogFeed();
    });
  }

  // Alerts Severity Filter
  const alertSeveritySelect = document.getElementById('alertSeverityFilter');
  if (alertSeveritySelect) {
    alertSeveritySelect.addEventListener('change', (e) => {
      state.alertFilter = e.target.value;
      renderAlertsTable();
    });
  }

  // Raw Log Ingestion Modal controls
  const pasteLogsBtn = document.getElementById('pasteLogsBtn');
  const pasteModal = document.getElementById('pasteLogsModal');
  const submitPasteBtn = document.getElementById('submitPasteBtn');
  const cancelPasteBtn = document.getElementById('cancelPasteBtn');
  const pasteTextarea = document.getElementById('pasteLogsTextarea');

  if (pasteLogsBtn && pasteModal) {
    pasteLogsBtn.addEventListener('click', () => pasteModal.classList.remove('hidden'));
    cancelPasteBtn?.addEventListener('click', () => pasteModal.classList.add('hidden'));
    submitPasteBtn?.addEventListener('click', async () => {
      const text = pasteTextarea?.value || '';
      if (text.trim()) {
        await ingestRawText(text);
        if (pasteTextarea) pasteTextarea.value = '';
        pasteModal.classList.add('hidden');
      }
    });
  }
}

/**
 * Toast Notification Utility
 */
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  let bg = 'bg-slate-800 border-slate-700 text-slate-200';
  if (type === 'success') bg = 'bg-emerald-950/90 border-emerald-600/50 text-emerald-200';
  if (type === 'error' || type === 'high') bg = 'bg-rose-950/90 border-rose-600/50 text-rose-200';
  if (type === 'medium') bg = 'bg-amber-950/90 border-amber-600/50 text-amber-200';

  toast.className = `p-3 rounded-lg border shadow-xl flex items-center space-x-2 text-xs font-mono transition-all transform duration-300 translate-y-2 opacity-0 ${bg}`;
  toast.innerHTML = `<span>${message}</span>`;
  container.appendChild(toast);

  // Trigger animation
  requestAnimationFrame(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  });

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-x-4');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

/**
 * Clipboard Copy Utility
 */
window.copyToClipboard = function(text, successMsg = 'Copied to clipboard') {
  navigator.clipboard.writeText(text).then(() => {
    showToast(successMsg, 'success');
  }).catch(() => {
    showToast('Failed to copy', 'error');
  });
};

/**
 * String HTML escape
 */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
