/**
 * Honeypot Statistics - fetches logs from github.com/seckid/logs and renders charts/tables.
 * Log files: folder/yyyy-mm-dd_logname.log (e.g. fortipot/2026-02-18_fortipot.log).
 * FortiPot log line format: timestamp|level|ip_address|message
 */

const LOGS_REPO = 'seckid/logs';
const GITHUB_API_BASE = 'https://api.github.com/repos';

/** Strip leading ('ip', port) or ("ip", port) from log message for event type display */
function stripAddrPrefix(s) {
  if (!s || typeof s !== "string") return s;
  return s.replace(/^\s*\(\s*['"]?[\d.]+['"]?\s*,\s*\d+\)\s*/, "").trim();
}

const LOG_PARSERS = {
  fortipot(line) {
    const parts = line.split("|");
    if (parts.length < 4) return null;
    const ts = parts[0].trim();
    const ip = parts[2].trim();
    const rawMessage = parts.slice(3).join("|").trim();
    const message = stripAddrPrefix(rawMessage);
    const dateMatch = ts.match(/^(\d{4}-\d{2}-\d{2})/);
    const date = dateMatch ? dateMatch[1] : null;
    let eventType = message;
    let loginUsername = null;
    let loginPassword = null;
    if (eventType.includes("LOGIN username=")) {
      eventType = "LOGIN";
      const loginMatch = message.match(/LOGIN username=(.+?) password=(.*)$/);
      if (loginMatch) {
        loginUsername = loginMatch[1].trim();
        loginPassword = loginMatch[2].trim();
      }
    } else if (eventType.startsWith("GET ")) {
      const path = eventType.slice(4).split(/\s/)[0] || "";
      eventType = "GET " + (path || "/");
    } else if (/CVE-\d{4}-\d+/.test(eventType)) eventType = (eventType.match(/CVE-\d{4}-\d+/)?.[0] || eventType);
    const out = { date, ip, eventType: eventType || "other", ts };
    if (loginUsername != null || loginPassword != null) {
      out.loginUsername = loginUsername;
      out.loginPassword = loginPassword;
    }
    return out;
  },
  ssh(_line) { return null; },
  rdp(_line) { return null; },
  ftp(_line) { return null; }
};

let chartTraffic = null;
let chartTopIps = null;
let chartEvents = null;

function show(el, visible) {
  if (!el) return;
  el.classList.toggle('hidden', !visible);
}

function escapeHtml(s) {
  if (!s) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function parseLogLines(text, honeypotType) {
  const parser = LOG_PARSERS[honeypotType] || LOG_PARSERS.fortipot;
  const entries = [];
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parsed = parser(trimmed);
    if (parsed) entries.push(parsed);
  }
  return entries;
}

/** Cache-bust query string so updated repo content is fetched after you push changes */
function cacheBust() {
  return "?nocache=" + Date.now();
}

async function listLogFiles(folder) {
  const url = `${GITHUB_API_BASE}/${LOGS_REPO}/contents/${folder}${cacheBust()}`;
  const res = await fetch(url, {
    headers: { Accept: "application/vnd.github.v3+json" },
    cache: "no-store"
  });
  if (!res.ok) throw new Error(`Failed to list ${folder}: ${res.status}`);
  const data = await res.json();
  if (!Array.isArray(data)) throw new Error("Invalid API response");
  const logFiles = data
    .filter(f => f.type === "file" && /^\d{4}-\d{2}-\d{2}_.*\.log$/.test(f.name))
    .map(f => f.name)
    .sort();
  return logFiles;
}

/**
 * Fetch log file content. Uses GitHub API with raw media type so large files
 * (e.g. 12k+ events, 1–100 MB) are returned in full; default JSON+base64 is limited to 1 MB.
 */
async function fetchLogContent(folder, filename) {
  const path = `${folder}/${encodeURIComponent(filename)}`;
  const url = `${GITHUB_API_BASE}/${LOGS_REPO}/contents/${path}${cacheBust()}`;
  const res = await fetch(url, {
    headers: { Accept: "application/vnd.github.v3.raw" },
    cache: "no-store"
  });
  if (!res.ok) return "";
  try {
    return await res.text();
  } catch (_) {
    return "";
  }
}

function aggregate(entries) {
  const byDate = {};
  const byIp = {};
  const byEvent = {};
  const loginAttempts = [];
  for (const e of entries) {
    if (e.date) byDate[e.date] = (byDate[e.date] || 0) + 1;
    if (e.ip) byIp[e.ip] = (byIp[e.ip] || 0) + 1;
    const ev = e.eventType || 'other';
    byEvent[ev] = (byEvent[ev] || 0) + 1;
    if (e.loginUsername !== undefined || e.loginPassword !== undefined) {
      loginAttempts.push({
        ts: e.ts,
        date: e.date,
        ip: e.ip,
        username: e.loginUsername ?? '',
        password: e.loginPassword ?? ''
      });
    }
  }
  return { byDate, byIp, byEvent, total: entries.length, loginAttempts };
}

function getDateRange(days) {
  const end = new Date();
  const start = new Date();
  if (days === 'all') return { start: new Date(2000, 0, 1), end };
  start.setDate(start.getDate() - parseInt(days, 10));
  return { start, end };
}

function filterFilesByDate(files, dateRange) {
  const { start, end } = dateRange;
  const startStr = start.toISOString().slice(0, 10);
  const endStr = end.toISOString().slice(0, 10);
  return files.filter(f => {
    const dateStr = f.slice(0, 10);
    return dateStr >= startStr && dateStr <= endStr;
  });
}

async function loadAndParseLogs(folder, dateRange) {
  const files = await listLogFiles(folder);
  const filtered = filterFilesByDate(files, dateRange);
  const allEntries = [];
  for (const filename of filtered) {
    const text = await fetchLogContent(folder, filename);
    const entries = parseLogLines(text, folder === 'fortipot' ? 'fortipot' : folder);
    allEntries.push(...entries);
  }
  return aggregate(allEntries);
}

function renderSummary(stats, folder) {
  const el = document.getElementById('stats-summary');
  if (!el) return;
  el.innerHTML = `
    <div class="stats-summary-grid">
      <div class="stats-summary-card">
        <span class="stats-summary-value">${stats.total.toLocaleString()}</span>
        <span class="stats-summary-label">Total events</span>
      </div>
      <div class="stats-summary-card">
        <span class="stats-summary-value">${Object.keys(stats.byIp).length}</span>
        <span class="stats-summary-label">Unique IPs</span>
      </div>
      <div class="stats-summary-card">
        <span class="stats-summary-value">${Object.keys(stats.byDate).length}</span>
        <span class="stats-summary-label">Days with data</span>
      </div>
    </div>
  `;
}

function renderTrafficChart(byDate) {
  const dates = Object.keys(byDate).sort();
  const counts = dates.map(d => byDate[d]);
  const ctx = document.getElementById('chart-traffic');
  if (!ctx) return;
  if (chartTraffic) chartTraffic.destroy();
  chartTraffic = new Chart(ctx, {
    type: 'line',
    data: {
      labels: dates,
      datasets: [{
        label: 'Events per day',
        data: counts,
        borderColor: 'rgb(59, 130, 246)',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        fill: true,
        tension: 0.2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, grid: { color: 'rgba(45, 55, 72, 0.5)' }, ticks: { color: '#9ca3af' } },
        x: { grid: { color: 'rgba(45, 55, 72, 0.5)' }, ticks: { color: '#9ca3af', maxRotation: 45 } }
      }
    }
  });
}

function renderTopIps(byIp, limit = 15) {
  const sorted = Object.entries(byIp).sort((a, b) => b[1] - a[1]).slice(0, limit);
  const labels = sorted.map(([ip]) => ip);
  const data = sorted.map(([, n]) => n);
  const ctx = document.getElementById('chart-top-ips');
  const tbody = document.querySelector('#table-top-ips tbody');
  if (ctx) {
    if (chartTopIps) chartTopIps.destroy();
    chartTopIps = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{ label: "Requests", data: data, backgroundColor: "rgba(139, 92, 246, 0.7)", borderColor: "rgb(139, 92, 246)", borderWidth: 1 }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, grid: { color: "rgba(45, 55, 72, 0.5)" }, ticks: { color: "#9ca3af" } },
          y: { grid: { display: false }, ticks: { color: "#9ca3af", font: { family: "JetBrains Mono" } } }
        }
      }
    });
  }
  if (tbody) {
    tbody.innerHTML = sorted.map(([ip, n]) => `<tr><td><code>${ip}</code></td><td>${n.toLocaleString()}</td></tr>`).join('');
  }
}

function renderEvents(byEvent, limit = 12) {
  const sorted = Object.entries(byEvent).sort((a, b) => b[1] - a[1]).slice(0, limit);
  const fullLabels = sorted.map(([ev]) => ev);
  const shortLabel = (s, maxLen) => (s.length <= maxLen ? s : s.slice(0, maxLen - 1) + "\u2026");
  const chartLabels = fullLabels.map((s) => shortLabel(s, 40));
  const data = sorted.map(([, n]) => n);
  const colors = ['#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444', '#06b6d4', '#ec4899', '#84cc16', '#6366f1', '#14b8a6', '#f97316', '#a855f7'];
  const ctx = document.getElementById('chart-events');
  const tbody = document.querySelector('#table-events tbody');
  if (ctx) {
    if (chartEvents) chartEvents.destroy();
    chartEvents = new Chart(ctx, {
      type: "pie",
      data: {
        labels: chartLabels,
        datasets: [{ data, backgroundColor: colors.slice(0, data.length), borderColor: "var(--bg-secondary)", borderWidth: 1 }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: "right", labels: { color: "#9ca3af", padding: 8 } },
          tooltip: {
            callbacks: {
              label: function (context) {
                const full = fullLabels[context.dataIndex];
                const count = context.parsed;
                const total = context.dataset.data.reduce(function (a, b) { return a + b; }, 0);
                const pctStr = total ? ((100 * count) / total).toFixed(1) : "0";
                return full + " \u2014 " + count.toLocaleString() + " (" + pctStr + "%)";
              }
            }
          }
        }
      }
    });
  }
  if (tbody) {
    tbody.innerHTML = sorted
      .map(
        ([ev, n]) =>
          '<tr><td class="event-cell" title="' +
          escapeHtml(ev) +
          '"><code class="event-text">' +
          escapeHtml(ev) +
          "</code></td><td>" +
          n.toLocaleString() +
          "</td></tr>"
      )
      .join("");
  }
}

function renderLoginAttempts(loginAttempts, limit = 200) {
  const tbody = document.querySelector('#table-login-attempts tbody');
  if (!tbody) return;
  const sorted = (loginAttempts || []).slice().reverse().slice(0, limit);
  tbody.innerHTML = sorted
    .map(
      (row) =>
        '<tr><td class="login-ts">' +
        escapeHtml(row.ts || '') +
        '</td><td><code>' +
        escapeHtml(row.ip || '') +
        '</code></td><td class="login-username">' +
        escapeHtml(row.username || '') +
        '</td><td class="login-password">' +
        escapeHtml(row.password || '') +
        '</td></tr>'
    )
    .join('');
}

function renderCharts(stats) {
  if (typeof Chart === 'undefined') {
    console.error('Chart.js did not load');
    return;
  }
  try {
    renderSummary(stats, 'fortipot');
  } catch (e) {
    console.error('renderSummary', e);
  }
  try {
    renderTrafficChart(stats.byDate);
  } catch (e) {
    console.error('renderTrafficChart', e);
  }
  try {
    renderTopIps(stats.byIp);
  } catch (e) {
    console.error('renderTopIps', e);
  }
  try {
    renderEvents(stats.byEvent);
  } catch (e) {
    console.error('renderEvents', e);
  }
  try {
    renderLoginAttempts(stats.loginAttempts);
  } catch (e) {
    console.error('renderLoginAttempts', e);
  }
}

async function runStats() {
  const honeypotType = document.getElementById('honeypot-type').value;
  const dateRangeVal = document.getElementById('date-range').value;
  const loadBtn = document.getElementById('load-stats');
  const loadingEl = document.getElementById('stats-loading');
  const errorEl = document.getElementById('stats-error');
  const contentEl = document.getElementById('stats-content');

  if (honeypotType !== 'fortipot') {
    show(contentEl, false);
    show(loadingEl, false);
    show(errorEl, true);
    errorEl.innerHTML = '<p>Only FortiPot logs are available at the moment. SSH, RDP, and FTP will be added when logs are available in the repo.</p>';
    return;
  }

  show(errorEl, false);
  show(contentEl, false);
  show(loadingEl, true);
  if (loadBtn) loadBtn.disabled = true;

  try {
    if (typeof Chart === 'undefined') {
      throw new Error('Chart.js failed to load. Check your connection or try disabling ad blockers.');
    }

    const dateRange = getDateRange(dateRangeVal);
    const stats = await loadAndParseLogs('fortipot', dateRange);

    show(loadingEl, false);
    if (loadBtn) loadBtn.disabled = false;

    if (stats.total === 0) {
      show(errorEl, true);
      errorEl.innerHTML = '<p>No log entries found for the selected period. Data is pulled from <a href="https://github.com/seckid/logs" target="_blank" rel="noopener">github.com/seckid/logs</a>.</p>';
      return;
    }

    show(contentEl, true);
    // Defer chart creation so layout is complete and canvas has dimensions
    requestAnimationFrame(() => {
      requestAnimationFrame(() => renderCharts(stats));
    });
  } catch (err) {
    show(loadingEl, false);
    if (loadBtn) loadBtn.disabled = false;
    show(errorEl, true);
    errorEl.innerHTML = `<p><strong>Error:</strong> ${err.message}. GitHub API may be rate-limited (60 req/hour unauthenticated). Try again later or check the repo <a href="https://github.com/seckid/logs" target="_blank" rel="noopener">seckid/logs</a>.</p>`;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('load-stats')?.addEventListener('click', runStats);
  runStats();
});
