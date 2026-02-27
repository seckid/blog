/**
 * Honeypot Statistics — reads stats/stats.json from github.com/seckid/logs
 * and renders charts/tables. No raw log parsing; all aggregation done server-side
 * by generate_and_upload_stats.py on threatapp-01 (updated hourly).
 */

const STATS_RAW_URL =
  'https://raw.githubusercontent.com/seckid/logs/main/stats/stats.json';

// Chart.js colour palette
const COLOURS = [
  '#3b82f6', '#8b5cf6', '#10b981', '#f59e0b',
  '#ef4444', '#06b6d4', '#ec4899', '#84cc16',
  '#6366f1', '#14b8a6', '#f97316', '#a855f7',
];

const SOURCE_COLOURS = {
  fortipot:       '#3b82f6',
  centrestackpot: '#8b5cf6',
  rdppot:         '#10b981',
  ivantipot:      '#f59e0b',
  unknown:        '#6b7280',
};

function sourceColour(name) {
  return SOURCE_COLOURS[name] || COLOURS[Object.keys(SOURCE_COLOURS).length % COLOURS.length];
}

// Destroy and replace a chart instance safely
const _charts = {};
function makeChart(id, config) {
  const ctx = document.getElementById(id);
  if (!ctx) return null;
  if (_charts[id]) _charts[id].destroy();
  _charts[id] = new Chart(ctx, config);
  return _charts[id];
}

function countryFlag(code) {
  if (!code || code.length !== 2) return '';
  const lower = code.toLowerCase();
  return `<img src="https://flagcdn.com/16x12/${lower}.png"
               srcset="https://flagcdn.com/32x24/${lower}.png 2x"
               width="16" height="12"
               alt="${escHtml(code.toUpperCase())}"
               style="vertical-align:middle;margin-right:4px;border-radius:2px">`;
}

function escHtml(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fmtNum(n) {
  return Number(n || 0).toLocaleString();
}

function show(id, visible) {
  const el = typeof id === 'string' ? document.getElementById(id) : id;
  if (el) el.classList.toggle('hidden', !visible);
}

// -------------------------------------------------------------------------
// Data fetch
// -------------------------------------------------------------------------

async function fetchStats() {
  // Append a timestamp query param so each request is a unique URL — this busts
  // Fastly's CDN cache on raw.githubusercontent.com without adding custom headers
  // (custom headers like Cache-Control trigger a CORS preflight that GitHub rejects).
  const url = `${STATS_RAW_URL}?t=${Date.now()}`;
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) {
    if (res.status === 404) {
      throw new Error('stats.json not found — the first hourly upload may not have run yet.');
    }
    throw new Error(`HTTP ${res.status} fetching stats.json`);
  }
  return res.json();
}

// -------------------------------------------------------------------------
// Date-range filter for events_per_day
// -------------------------------------------------------------------------

function filterDays(eventsPerDay, days) {
  if (!eventsPerDay) return {};
  const allDays = Object.keys(eventsPerDay).sort();
  if (days === 'all') return eventsPerDay;
  const n = parseInt(days, 10);
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - n);
  const cutStr = cutoff.toISOString().slice(0, 10);
  const filtered = {};
  for (const d of allDays) {
    if (d >= cutStr) filtered[d] = eventsPerDay[d];
  }
  return filtered;
}

// -------------------------------------------------------------------------
// Render helpers
// -------------------------------------------------------------------------

function renderSummary(stats) {
  const el = document.getElementById('summary-grid');
  if (!el) return;
  const daysWithData = Object.keys(stats.events_per_day || {}).length;
  const honeypots = (stats.honeypots || []).join(', ') || '—';
  el.innerHTML = [
    ['Total events',   fmtNum(stats.total_events)],
    ['Unique IPs',     fmtNum(stats.unique_ips)],
    ['Days with data', fmtNum(daysWithData)],
    ['CVEs detected',  fmtNum((stats.cve_attempts || []).length)],
    ['ASNs observed',  fmtNum((stats.top_asns || []).length)],
  ].map(([label, value]) => `
    <div class="summary-card">
      <span class="summary-value">${value}</span>
      <span class="summary-label">${escHtml(label)}</span>
    </div>`).join('');
}

function renderMeta(stats) {
  const el = document.getElementById('meta-line');
  if (!el) return;
  const ts = stats.generated_at
    ? new Date(stats.generated_at).toUTCString()
    : 'unknown';
  const honeypots = (stats.honeypots || []).map(h =>
    `<span class="badge badge-source">${escHtml(h)}</span>`).join(' ');
  el.innerHTML = `Stats generated: ${escHtml(ts)} &nbsp;|&nbsp; Honeypots: ${honeypots || '—'} &nbsp;|&nbsp;
    Source: <a href="https://github.com/seckid/logs/blob/main/stats/stats.json" target="_blank" rel="noopener">seckid/logs/stats/stats.json</a>`;
}

function renderTrafficChart(eventsPerDay, honeypots) {
  const filtered = eventsPerDay;
  const days = Object.keys(filtered).sort();
  if (!days.length) return;

  const sources = (honeypots || []).filter(s => s !== 'total');

  const datasets = sources.map(src => ({
    label: src,
    data: days.map(d => (filtered[d] || {})[src] || 0),
    borderColor: sourceColour(src),
    backgroundColor: sourceColour(src) + '22',
    borderWidth: 2,
    pointRadius: days.length > 60 ? 0 : 3,
    pointHoverRadius: 5,
    tension: 0.3,
    fill: false,
  }));

  makeChart('chart-traffic', {
    type: 'line',
    data: { labels: days, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { position: 'top', labels: { color: '#9ca3af', padding: 10 } },
        tooltip: {
          callbacks: {
            footer: (items) => {
              const total = items.reduce((s, i) => s + i.parsed.y, 0);
              return `Total: ${total.toLocaleString()}`;
            },
          },
        },
      },
      scales: {
        x: { grid: { color: 'rgba(45,55,72,.4)' }, ticks: { color: '#9ca3af', maxRotation: 45 } },
        y: { beginAtZero: true, grid: { color: 'rgba(45,55,72,.4)' }, ticks: { color: '#9ca3af' } },
      },
    },
  });
}

function renderSourcesChart(totals) {
  const entries = Object.entries(totals || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return;
  makeChart('chart-sources', {
    type: 'doughnut',
    data: {
      labels: entries.map(([k]) => k),
      datasets: [{
        data: entries.map(([, v]) => v),
        backgroundColor: entries.map(([k]) => sourceColour(k)),
        borderColor: 'var(--bg-secondary,#1a1f2e)',
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#9ca3af', padding: 8 } },
        tooltip: { callbacks: { label: (c) => ` ${c.label}: ${c.parsed.toLocaleString()}` } },
      },
    },
  });
}

function renderMethodsChart(methods) {
  const entries = Object.entries(methods || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return;
  makeChart('chart-methods', {
    type: 'bar',
    data: {
      labels: entries.map(([k]) => k),
      datasets: [{
        label: 'Count',
        data: entries.map(([, v]) => v),
        backgroundColor: entries.map((_, i) => COLOURS[i % COLOURS.length]),
        borderWidth: 0,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, grid: { color: 'rgba(45,55,72,.4)' }, ticks: { color: '#9ca3af' } },
        y: { grid: { display: false }, ticks: { color: '#9ca3af', font: { family: 'JetBrains Mono' } } },
      },
    },
  });
}

function renderAsnsChart(asns) {
  const top = (asns || []).slice(0, 15);
  if (!top.length) return;
  makeChart('chart-asns', {
    type: 'bar',
    data: {
      labels: top.map(a => a.asn || a.name || '?'),
      datasets: [{
        label: 'Events',
        data: top.map(a => a.event_count),
        backgroundColor: 'rgba(139,92,246,.75)',
        borderColor: 'rgb(139,92,246)',
        borderWidth: 1,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, grid: { color: 'rgba(45,55,72,.4)' }, ticks: { color: '#9ca3af' } },
        y: { grid: { display: false }, ticks: { color: '#9ca3af', font: { family: 'JetBrains Mono', size: 11 } } },
      },
    },
  });
}

function renderTable(tableId, rows) {
  const tbody = document.querySelector(`#${tableId} tbody`);
  if (!tbody) return;
  tbody.innerHTML = rows.join('');
}

function severityColour(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'critical': return '#ef4444';
    case 'high':     return '#f97316';
    case 'medium':   return '#f59e0b';
    case 'low':      return '#10b981';
    default:         return '#6b7280';
  }
}

function renderCves(cves) {
  if (!cves || !cves.length) {
    renderTable('table-cves', ['<tr><td colspan="6" style="color:#6b7280">No CVE attempts recorded.</td></tr>']);
    return;
  }
  renderTable('table-cves', cves.map(c => {
    const severityBadge = c.severity
      ? `<span style="color:${severityColour(c.severity)};font-weight:600;font-size:.72rem">${escHtml(c.severity)}</span>${c.cvss_score ? ` <span style="color:#9ca3af;font-size:.72rem">(${c.cvss_score})</span>` : ''}`
      : '—';
    const paths = (c.sample_paths || []).map(p =>
      `<code style="display:block;font-size:.72rem;word-break:break-all;color:#93c5fd">${escHtml(p)}</code>`
    ).join('') || '<span style="color:#6b7280">—</span>';
    const ips = (c.sample_ips || []).map(ip =>
      `<code style="display:block;font-size:.72rem">${escHtml(ip)}</code>`
    ).join('') || '<span style="color:#6b7280">—</span>';
    return `
    <tr>
      <td style="white-space:nowrap">
        <span class="badge badge-cve">${escHtml(c.cve)}</span>
      </td>
      <td style="font-size:.78rem;color:#d1d5db;max-width:260px">
        ${c.description ? escHtml(c.description) : '<span style="color:#6b7280">—</span>'}
      </td>
      <td>${severityBadge}</td>
      <td>${fmtNum(c.count)}</td>
      <td>${(c.sources || []).map(s => `<span class="badge badge-source">${escHtml(s)}</span>`).join(' ')}</td>
      <td>${paths}</td>
      <td>${ips}</td>
    </tr>`;
  }));
}

function renderAsnsTable(asns) {
  if (!asns || !asns.length) {
    renderTable('table-asns', ['<tr><td colspan="5" style="color:#6b7280">No ASN data yet.</td></tr>']);
    return;
  }
  renderTable('table-asns', asns.map(a => `
    <tr>
      <td><code>${escHtml(a.asn)}</code></td>
      <td>${escHtml(a.name)}</td>
      <td>${countryFlag(a.country)} ${escHtml(a.country)}</td>
      <td>${fmtNum(a.event_count)}</td>
      <td>${fmtNum(a.ip_count)}</td>
    </tr>`));
}

function renderPaths(paths) {
  if (!paths || !paths.length) {
    renderTable('table-paths', ['<tr><td colspan="3" style="color:#6b7280">No path data.</td></tr>']);
    return;
  }
  renderTable('table-paths', paths.map(p => `
    <tr>
      <td><code>${escHtml(p.path)}</code></td>
      <td><span class="badge badge-source">${escHtml(p.source)}</span></td>
      <td>${fmtNum(p.count)}</td>
    </tr>`));
}

function renderUserAgents(uas) {
  if (!uas || !uas.length) {
    renderTable('table-uas', ['<tr><td colspan="2" style="color:#6b7280">No user agent data.</td></tr>']);
    return;
  }
  renderTable('table-uas', uas.map(u => `
    <tr>
      <td style="word-break:break-all;font-size:.8rem">${escHtml(u.user_agent)}</td>
      <td>${fmtNum(u.count)}</td>
    </tr>`));
}

function renderCredentials(creds) {
  if (!creds || !creds.length) {
    renderTable('table-creds', ['<tr><td colspan="3" style="color:#6b7280">No credentials captured.</td></tr>']);
    return;
  }
  renderTable('table-creds', creds.map(c => `
    <tr>
      <td><code>${escHtml(c.username)}</code></td>
      <td><code>${escHtml(c.password)}</code></td>
      <td>${fmtNum(c.count)}</td>
    </tr>`));
}

// -------------------------------------------------------------------------
// Main render orchestrator
// -------------------------------------------------------------------------

function renderAll(stats, days) {
  renderMeta(stats);
  renderSummary(stats);

  const filtered = filterDays(stats.events_per_day, days);
  renderTrafficChart(filtered, stats.honeypots);
  renderSourcesChart(stats.totals_by_source);
  renderMethodsChart(stats.method_counts);
  renderAsnsChart(stats.top_asns);
  renderCves(stats.cve_attempts);
  renderAsnsTable(stats.top_asns);
  renderPaths(stats.top_paths);
  renderUserAgents(stats.top_user_agents);
  renderCredentials(stats.top_credentials);
}

// -------------------------------------------------------------------------
// Entry point
// -------------------------------------------------------------------------

let _cachedStats = null;

async function runStats() {
  const days = document.getElementById('date-range')?.value || '30';
  const loadBtn = document.getElementById('load-stats');

  show('stats-error', false);
  show('stats-content', false);
  show('stats-loading', true);
  if (loadBtn) loadBtn.disabled = true;

  try {
    if (typeof Chart === 'undefined') {
      throw new Error('Chart.js failed to load — check your connection or ad-blocker.');
    }

    // Only re-fetch if not cached (date-range changes just re-render from cache)
    if (!_cachedStats || (loadBtn && !loadBtn._fromCache)) {
      _cachedStats = await fetchStats();
    }

    show('stats-loading', false);
    if (loadBtn) { loadBtn.disabled = false; loadBtn._fromCache = false; }

    if (!_cachedStats || !_cachedStats.total_events) {
      show('stats-error', true);
      document.getElementById('stats-error').innerHTML =
        '<p>Stats file is empty or unavailable. Data is updated hourly from ' +
        '<a href="https://github.com/seckid/logs" target="_blank" rel="noopener">github.com/seckid/logs</a>.</p>';
      return;
    }

    show('stats-content', true);
    requestAnimationFrame(() => requestAnimationFrame(() => renderAll(_cachedStats, days)));

  } catch (err) {
    show('stats-loading', false);
    if (loadBtn) { loadBtn.disabled = false; }
    show('stats-error', true);
    document.getElementById('stats-error').innerHTML =
      `<p><strong>Error:</strong> ${escHtml(err.message)}. ` +
      `Stats are pushed hourly to <a href="https://github.com/seckid/logs" ` +
      `target="_blank" rel="noopener">seckid/logs</a> — try again shortly.</p>`;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('load-stats')?.addEventListener('click', () => {
    _cachedStats = null; // force re-fetch on manual refresh
    runStats();
  });

  // Re-render with new date range without re-fetching
  document.getElementById('date-range')?.addEventListener('change', () => {
    if (_cachedStats) {
      const btn = document.getElementById('load-stats');
      if (btn) btn._fromCache = true;
      runStats();
    }
  });

  runStats();
});
