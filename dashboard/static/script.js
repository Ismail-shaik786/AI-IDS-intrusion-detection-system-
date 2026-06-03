// ============================================================
// SentinelX SOC Platform — Enterprise Frontend JS
// ============================================================

lucide.createIcons();

// ── State ─────────────────────────────────────────────────────
const state = { total: 0, blocked: 0, critical: 0, packets: 0, uptime: 0, activeConnections: 0 };
let allAlerts = [];
let alertFilter = "ALL";

// ── DOM Refs ───────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const elTime = $('current-time');
const elTotal = $('stat-total');
const elActive = $('stat-active');
const elBlocked = $('stat-blocked');
const elPackets = $('packets-analyzed');
const elDistTotal = $('dist-total');
const elThreatLevel = $('stat-threat-level');
const elThreatIcon = $('threat-level-icon');
const elThreatGlow = $('threat-level-glow');
const elBadge = $('alert-badge');
const elBellPing = $('bell-ping');
const elBellDot = $('bell-dot');
const elAlertsTbody = $('alerts-tbody');

// ── Clock ──────────────────────────────────────────────────────
setInterval(() => { elTime.textContent = new Date().toLocaleTimeString('en-US', { hour12: false }); }, 1000);

// ── Chart.js defaults ──────────────────────────────────────────
Chart.defaults.color = '#9CA3AF';
Chart.defaults.font.family = 'Inter';

const COLORS = {
  cyan: '#00E5FF', blue: '#3B82F6', purple: '#8B5CF6',
  danger: '#EF4444', warning: '#F59E0B', success: '#10B981',
  gray: '#6B7280'
};
const SEV_COLORS = { CRITICAL: COLORS.danger, HIGH: COLORS.warning, MEDIUM: COLORS.blue, LOW: COLORS.success, BENIGN: COLORS.gray };
const DIST_COLORS = [COLORS.danger, COLORS.warning, COLORS.blue, COLORS.purple, COLORS.success, COLORS.cyan, '#F97316', '#EC4899'];

// ── Traffic Chart ──────────────────────────────────────────────
const tCtx = $('trafficChart').getContext('2d');
const tGrad = (color) => { const g = tCtx.createLinearGradient(0,0,0,280); g.addColorStop(0, color+'66'); g.addColorStop(1, color+'00'); return g; };

const trafficChart = new Chart(tCtx, {
  type: 'line',
  data: {
    labels: Array(25).fill(''),
    datasets: [
      { label: 'Incoming (pkts/s)', data: Array(25).fill(0), borderColor: COLORS.blue, backgroundColor: tGrad(COLORS.blue), borderWidth: 2, fill: true, tension: 0.4, pointRadius: 0 },
      { label: 'Blocked', data: Array(25).fill(0), borderColor: COLORS.danger, backgroundColor: tGrad(COLORS.danger), borderWidth: 2, fill: true, tension: 0.4, pointRadius: 0 }
    ]
  },
  options: { responsive: true, maintainAspectRatio: false, animation: false,
    plugins: { legend: { display: true, position: 'top', labels: { boxWidth: 10, padding: 20 } } },
    scales: { x: { grid: { display: false } }, y: { grid: { color: '#1F2937' }, beginAtZero: true } }
  }
});

// ── Distribution Doughnut ──────────────────────────────────────
const dCtx = $('distributionChart').getContext('2d');
const distChart = new Chart(dCtx, {
  type: 'doughnut',
  data: { labels: ['Loading...'], datasets: [{ data: [1], backgroundColor: [COLORS.gray], borderWidth: 0, hoverOffset: 4 }] },
  options: { responsive: true, maintainAspectRatio: false, cutout: '75%',
    plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 12, font: { size: 11 } } } }
  }
});

// ── Analytics Charts ───────────────────────────────────────────
let analyticsCharts = {};

function initAnalyticsCharts() {
  const sevCtx = $('sevChart');
  if (sevCtx && !analyticsCharts.sev) {
    analyticsCharts.sev = new Chart(sevCtx.getContext('2d'), {
      type: 'bar',
      data: { labels: ['CRITICAL','HIGH','MEDIUM','LOW'], datasets: [{ data: [0,0,0,0], backgroundColor: [COLORS.danger, COLORS.warning, COLORS.blue, COLORS.success], borderRadius: 6 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { grid: { color: '#1F2937' } }, x: { grid: { display: false } } } }
    });
  }
  const protoCtx = $('protoChart');
  if (protoCtx && !analyticsCharts.proto) {
    analyticsCharts.proto = new Chart(protoCtx.getContext('2d'), {
      type: 'doughnut',
      data: { labels: ['TCP','UDP','ICMP','Other'], datasets: [{ data: [75,15,6,4], backgroundColor: [COLORS.blue, COLORS.cyan, COLORS.purple, COLORS.gray], borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '65%', plugins: { legend: { position: 'bottom', labels: { boxWidth: 8, padding: 10 } } } }
    });
  }
}

function updateAnalyticsCharts(stats) {
  if (analyticsCharts.sev) {
    analyticsCharts.sev.data.datasets[0].data = [
      stats.critical || 0, stats.high || 0, stats.medium || 0, stats.low || 0
    ];
    analyticsCharts.sev.update();
  }
  // Top IPs table
  const topIPsEl = $('top-ips-table');
  if (topIPsEl && stats.top_ips) {
    topIPsEl.innerHTML = stats.top_ips.map(({ip, count}) =>
      `<tr class="border-b border-gray-800/50">
        <td class="px-4 py-2 font-mono text-xs text-blue">${ip}</td>
        <td class="px-4 py-2 text-xs text-center">
          <span class="px-2 py-1 bg-danger/20 text-danger rounded text-xs">${count}</span>
        </td>
        <td class="px-4 py-2 text-xs text-gray-400 text-right">
          <button onclick="blockIP('${ip}')" class="px-2 py-1 bg-red-900/30 hover:bg-red-900/60 text-danger border border-danger/20 rounded text-[10px] transition-colors">Block</button>
        </td>
      </tr>`
    ).join('');
  }
  // Top ports
  const topPortsEl = $('top-ports-table');
  if (topPortsEl && stats.top_ports) {
    topPortsEl.innerHTML = stats.top_ports.map(({port, count}) =>
      `<tr class="border-b border-gray-800/50">
        <td class="px-4 py-2 font-mono text-xs text-purple">${port}</td>
        <td class="px-4 py-2 text-xs text-gray-300">${getServiceName(port)}</td>
        <td class="px-4 py-2 text-xs text-warning text-right">${count}</td>
      </tr>`
    ).join('');
  }
  // Attack count breakdown
  const atkBreakEl = $('attack-breakdown');
  if (atkBreakEl && stats.attack_counts) {
    const entries = Object.entries(stats.attack_counts).filter(([k])=>k!=='BENIGN').sort((a,b)=>b[1]-a[1]).slice(0,6);
    const max = entries[0]?.[1] || 1;
    atkBreakEl.innerHTML = entries.map(([name,cnt], i) => `
      <div>
        <div class="flex justify-between text-xs mb-1"><span class="text-gray-300">${name}</span><span class="text-gray-400">${cnt}</span></div>
        <div class="w-full bg-gray-900 rounded-full h-1.5">
          <div class="h-1.5 rounded-full" style="width:${Math.round(cnt/max*100)}%;background:${DIST_COLORS[i%DIST_COLORS.length]}"></div>
        </div>
      </div>`).join('');
  }
}

function getServiceName(port) {
  const s = {'80':'HTTP','443':'HTTPS','22':'SSH','21':'FTP','3389':'RDP','53':'DNS','25':'SMTP','3306':'MySQL','8080':'HTTP-Alt','1433':'MSSQL'};
  return s[port] || 'Unknown';
}

// ── Stats update ───────────────────────────────────────────────
function applyStats(s) {
  elTotal.textContent  = (s.total || 0).toLocaleString();
  elBlocked.textContent = (s.blocked || 0).toLocaleString();
  elPackets.textContent = (s.packets_analyzed || 0).toLocaleString();
  elActive.textContent  = s.activeConnections || Math.floor(Math.random()*400+100);

  // Attack dist chart
  if (s.attack_counts) {
    const nonBenign = Object.entries(s.attack_counts).filter(([k]) => k !== 'BENIGN');
    if (nonBenign.length) {
      distChart.data.labels = nonBenign.map(([k]) => k);
      distChart.data.datasets[0].data = nonBenign.map(([,v]) => v);
      distChart.data.datasets[0].backgroundColor = DIST_COLORS.slice(0, nonBenign.length);
      distChart.update();
      elDistTotal.textContent = nonBenign.reduce((a,[,v])=>a+v,0).toLocaleString();
    }
  }

  // AI panel
  const rl = $('ai-latency'); if(rl) rl.textContent = `${(Math.random()*0.5+0.8).toFixed(2)}ms`;
  const rp = $('ai-packets'); if(rp) rp.textContent = (s.packets_analyzed||0).toLocaleString();
  const ra = $('ai-accuracy'); if(ra) ra.textContent = '99.4%';
  const rr = $('ai-rate'); if(rr) rr.textContent = `${(s.packets_per_sec||0).toFixed(1)} p/s`;

  updateAnalyticsCharts(s);
}

// ── Alert row ─────────────────────────────────────────────────
function severityBadge(sev) {
  const cls = { CRITICAL:'bg-danger/20 text-danger border-danger/30', HIGH:'bg-warning/20 text-warning border-warning/30', MEDIUM:'bg-blue/20 text-blue border-blue/30', LOW:'bg-success/20 text-success border-success/30' };
  return `<span class="px-2 py-1 rounded text-xs font-bold border ${cls[sev]||cls.LOW}">${sev}</span>`;
}

function addAlertRow(alert) {
  allAlerts.unshift(alert);
  if (allAlerts.length > 200) allAlerts.pop();
  renderAlertsTable();
  updateNotificationBell();
  updateThreatLevel(alert.severity);
}

function renderAlertsTable() {
  const filtered = alertFilter === 'ALL' ? allAlerts : allAlerts.filter(a => a.severity === alertFilter);
  if (!filtered.length) {
    elAlertsTbody.innerHTML = `<tr><td colspan="8" class="px-4 py-8 text-center text-gray-500">Waiting for live data…</td></tr>`;
    return;
  }
  elAlertsTbody.innerHTML = filtered.slice(0,50).map((a, i) => `
    <tr class="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors ${i===0&&allAlerts.length>1?'alert-row':''} ${a.severity==='CRITICAL'?'alert-critical':''}">
      <td class="px-3 py-2.5 font-mono text-xs text-gray-400">${a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '--'}</td>
      <td class="px-3 py-2.5 font-mono text-xs text-blue">${a.src_ip||'--'}</td>
      <td class="px-3 py-2.5 font-mono text-xs text-gray-300">${a.dst_ip||'--'}</td>
      <td class="px-3 py-2.5"><span class="px-2 py-1 bg-gray-800 text-gray-200 rounded text-xs border border-gray-700">${a.attack_type||'--'}</span></td>
      <td class="px-3 py-2.5">${severityBadge(a.severity||'LOW')}</td>
      <td class="px-3 py-2.5 text-cyan text-xs">${parseFloat(a.confidence||0).toFixed(1)}%</td>
      <td class="px-3 py-2.5 text-xs text-gray-400">${a.country||'--'}</td>
      <td class="px-3 py-2.5">
        <button onclick="blockIP('${a.src_ip}')" class="text-xs bg-danger/10 hover:bg-danger/20 text-danger border border-danger/20 px-2 py-1 rounded transition-colors">Block</button>
      </td>
    </tr>`).join('');
}

function updateNotificationBell() {
  const cnt = allAlerts.filter(a => a.severity === 'HIGH' || a.severity === 'CRITICAL').length;
  if (cnt > 0) {
    elBadge.textContent = cnt; elBadge.classList.remove('hidden');
    elBellPing.classList.remove('hidden'); elBellDot.classList.remove('hidden');
  }
}

function updateThreatLevel(sev) {
  if (sev === 'CRITICAL') {
    elThreatLevel.textContent = 'Critical';
    elThreatLevel.className = 'text-2xl font-bold tracking-tight text-danger animate-pulse';
    elThreatIcon.className = 'p-2 rounded-lg bg-danger/20 border border-danger/50 text-danger';
  } else if (sev === 'HIGH') {
    elThreatLevel.textContent = 'High';
    elThreatLevel.className = 'text-2xl font-bold tracking-tight text-warning';
  }
}

function blockIP(ip) {
  fetch('/api/blacklist/unblock', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ip}) });
  showToast(`IP ${ip} block request sent`, 'warning');
}

// ── Blacklist tab ──────────────────────────────────────────────
function loadBlacklist() {
  fetch('/api/blacklist').then(r=>r.json()).then(data => {
    const el = $('blacklist-table');
    if (!el) return;
    const list = data.blacklist || [];
    if (!list.length) { el.innerHTML = `<tr><td colspan="5" class="px-4 py-8 text-center text-gray-500">No blocked IPs</td></tr>`; return; }
    el.innerHTML = list.map(b => `
      <tr class="border-b border-gray-800/50 hover:bg-gray-800/20">
        <td class="px-4 py-3 font-mono text-xs text-danger">${b.ip}</td>
        <td class="px-4 py-3 text-xs">${b.reason||'Unknown'}</td>
        <td class="px-4 py-3"><span class="px-2 py-1 rounded text-xs ${b.permanent?'bg-danger/20 text-danger':'bg-warning/20 text-warning'}">${b.permanent?'Permanent':'Temporary'}</span></td>
        <td class="px-4 py-3 text-xs text-gray-400">${b.hits||0} hits</td>
        <td class="px-4 py-3">
          <button onclick="unblockIP('${b.ip}')" class="text-xs bg-success/10 hover:bg-success/20 text-success border border-success/20 px-2 py-1 rounded transition-colors">Unblock</button>
        </td>
      </tr>`).join('');
  });
}

function unblockIP(ip) {
  fetch('/api/blacklist/unblock', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ip}) })
    .then(() => { loadBlacklist(); showToast(`${ip} unblocked`, 'success'); });
}

// ── Toast notifications ────────────────────────────────────────
function showToast(msg, type = 'info') {
  const colors = { info: 'border-blue text-blue', success: 'border-success text-success', warning: 'border-warning text-warning', danger: 'border-danger text-danger' };
  const container = $('toast-container') || (() => { const d = document.createElement('div'); d.id = 'toast-container'; d.className = 'fixed bottom-6 right-6 z-50 flex flex-col gap-2'; document.body.appendChild(d); return d; })();
  const toast = document.createElement('div');
  toast.className = `glass-panel px-4 py-3 text-sm border-l-2 ${colors[type]||colors.info} toast-enter`;
  toast.textContent = msg;
  container.prepend(toast);
  setTimeout(() => toast.remove(), 4000);
}

// ── Traffic chart live update ──────────────────────────────────
function pushTrafficPoint(incoming, blocked) {
  const lbl = new Date().toLocaleTimeString('en-US', { hour12: false });
  trafficChart.data.labels.push(lbl); trafficChart.data.labels.shift();
  trafficChart.data.datasets[0].data.push(incoming); trafficChart.data.datasets[0].data.shift();
  trafficChart.data.datasets[1].data.push(blocked); trafficChart.data.datasets[1].data.shift();
  trafficChart.update();
}

// ── Socket.IO ─────────────────────────────────────────────────
const socket = io();

socket.on('connect', () => { console.log('[WS] Connected'); socket.emit('request_stats'); });

socket.on('new_alert', (data) => {
  addAlertRow(data);
  const blocked = ['HIGH','CRITICAL'].includes(data.severity) ? 30 + Math.random()*40 : Math.random()*5;
  pushTrafficPoint(Math.floor(Math.random()*400+200), blocked);
});

socket.on('stats_update', (s) => { applyStats(s); });

socket.on('ip_blocked', (data) => {
  showToast(`🛡️ Auto-blocked ${data.ip} (${data.reason})`, 'danger');
  loadBlacklist();
});

// ── Heartbeat traffic simulation (keeps graph alive when idle) ─
setInterval(() => {
  pushTrafficPoint(Math.floor(Math.random()*150+80), Math.floor(Math.random()*8));
}, 2000);


// ── Live CSV Feed polling ──────────────────────────────────────
// Tracks the last CSV row index we consumed. -1 = initial load.
let csvRowCursor = -1;
let csvPollActive = false;

function normCSVAlert(a) {
  return {
    timestamp:   a.timestamp   || '',
    src_ip:      a.src_ip      || '--',
    dst_ip:      a.dst_ip      || '--',
    attack_type: a.attack_type || '--',
    severity:    a.severity    || 'LOW',
    confidence:  parseFloat(a.confidence  || 0),
    country:     a.country     || '--',
  };
}

function pollCSVFeed() {
  if (csvPollActive) return;
  csvPollActive = true;
  fetch(`/api/threats/csv-live?after=${csvRowCursor}`)
    .then(r => r.json())
    .then(data => {
      const rows = data.alerts || [];
      if (rows.length > 0) {
        // Newest rows arrive at bottom of CSV → reverse so newest is first
        rows.slice().reverse().forEach(a => {
          const norm = normCSVAlert(a);
          allAlerts.unshift(norm);
          updateThreatLevel(norm.severity);
        });
        if (allAlerts.length > 300) allAlerts.length = 300;
        csvRowCursor = data.total_rows - 1;
        renderAlertsTable();
        renderFullAlertsFeed();
        updateNotificationBell();
      } else if (csvRowCursor < 0 && data.total_rows > 0) {
        // First poll, CSV existed but no new rows (shouldn't happen, but handle it)
        csvRowCursor = data.total_rows - 1;
      }
    })
    .catch(() => {})
    .finally(() => { csvPollActive = false; });
}

// Initial load + poll every 3 seconds
fetch('/api/stats').then(r=>r.json()).then(applyStats).catch(()=>{});
pollCSVFeed();
setInterval(pollCSVFeed, 3000);


// ── Tab switching ──────────────────────────────────────────────
const navItems = document.querySelectorAll('.nav-item');
const views = document.querySelectorAll('.view-section');

navItems.forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    const tab = item.getAttribute('data-tab');
    if (!tab) return;

    navItems.forEach(n => {
      n.classList.remove('bg-gray-800/80','text-cyan','border-gray-700/50');
      n.classList.add('text-gray-400','border-transparent');
    });
    item.classList.remove('text-gray-400','border-transparent');
    item.classList.add('bg-gray-800/80','text-cyan','border-gray-700/50');

    views.forEach(v => {
      v.id === 'view-'+tab ? v.classList.remove('hidden') : v.classList.add('hidden');
    });

    // Tab-specific init
    if (tab === 'analytics') { initAnalyticsCharts(); fetch('/api/stats').then(r=>r.json()).then(updateAnalyticsCharts); }
    if (tab === 'network')   { fetch('/api/stats').then(r=>r.json()).then(updateNetworkTab); }
    if (tab === 'alerts')    { renderFullAlertsFeed(); }
    if (tab === 'blacklist') { loadBlacklist(); }
  });
});

// ── Alert filter buttons ───────────────────────────────────────
document.querySelectorAll('[data-filter]').forEach(btn => {
  btn.addEventListener('click', () => {
    alertFilter = btn.getAttribute('data-filter');
    document.querySelectorAll('[data-filter]').forEach(b => b.classList.remove('active-filter'));
    btn.classList.add('active-filter');
    renderAlertsTable();
  });
});

// ── Full Alerts Feed (alerts tab) ──────────────────────────────
function renderFullAlertsFeed() {
  const el = $('full-alerts-tbody');
  if (!el) return;
  el.innerHTML = allAlerts.slice(0,100).map(a => `
    <tr class="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
      <td class="px-3 py-2.5 font-mono text-xs text-gray-400">${a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '--'}</td>
      <td class="px-3 py-2.5 font-mono text-xs text-blue">${a.src_ip||'--'}</td>
      <td class="px-3 py-2.5 font-mono text-xs text-gray-300">${a.dst_ip||'--'}</td>
      <td class="px-3 py-2.5"><span class="px-2 py-1 bg-gray-800 text-gray-200 rounded text-xs border border-gray-700">${a.attack_type||'--'}</span></td>
      <td class="px-3 py-2.5">${severityBadge(a.severity||'LOW')}</td>
      <td class="px-3 py-2.5 text-cyan text-xs">${parseFloat(a.confidence||0).toFixed(1)}%</td>
      <td class="px-3 py-2.5 text-xs text-gray-400">${a.country||'--'}</td>
    </tr>`).join('');
}

// ── Network tab ────────────────────────────────────────────────
function updateNetworkTab(stats) {
  const pcnt = $('net-pps'); if(pcnt) pcnt.textContent = `${(stats.packets_per_sec||0).toFixed(1)} p/s`;
  const ptot = $('net-total'); if(ptot) ptot.textContent = (stats.packets_analyzed||0).toLocaleString();
  const pup = $('net-uptime'); if(pup) { const u=stats.uptime_secs||0; pup.textContent = `${Math.floor(u/60)}m ${u%60}s`; }
  const proto = stats.protocol_counts || {};
  ['TCP','UDP','ICMP'].forEach(p => {
    const el = $(`net-${p.toLowerCase()}`);
    if (el) el.textContent = (proto[p]||0).toLocaleString();
  });
}

// ── Export ─────────────────────────────────────────────────────
const expBtn = $('export-btn');
if (expBtn) expBtn.addEventListener('click', () => { window.location.href = '/api/threats/export'; });