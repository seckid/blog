/**
 * Honeypot Statistics — reads stats/stats.json from github.com/seckid/logs
 * and renders charts/tables. Aggregation is done server-side by
 * generate_and_upload_stats.py on threatapp-01 (updated hourly).
 */

const STATS_RAW_URL =
  'https://raw.githubusercontent.com/seckid/logs/main/stats/stats.json';

const COLOURS = [
  '#3b82f6', '#8b5cf6', '#10b981', '#f59e0b',
  '#ef4444', '#06b6d4', '#ec4899', '#84cc16',
  '#6366f1', '#14b8a6', '#f97316', '#a855f7',
];

const SOURCE_COLOURS = {
  fortipot: '#3b82f6',
  centrestackpot: '#8b5cf6',
  sharepointpot: '#ef4444',
  ivantipot: '#f59e0b',
  bigippot: '#06b6d4',
  front: '#10b981',
  rdppot: '#14b8a6',
  sshppot: '#a855f7',
  sshpot: '#a855f7',
  unknown: '#6b7280',
};

const SEVERITY_COLOURS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#10b981',
  unknown: '#6b7280',
};

const IP_CHIP_LIMIT = 5;
const CHART_GRID = 'rgba(45,55,72,.4)';
const CHART_TICK = '#9ca3af';

function honeypotBaseName(name) {
  if (!name) return 'unknown';
  const raw = String(name).trim();
  const base = raw.split(':')[0].trim().toLowerCase();
  return base || 'unknown';
}

function sourceColour(name) {
  const base = honeypotBaseName(name);
  if (SOURCE_COLOURS[base]) return SOURCE_COLOURS[base];
  let hash = 0;
  for (let i = 0; i < base.length; i++) {
    hash = ((hash << 5) - hash + base.charCodeAt(i)) | 0;
  }
  return COLOURS[Math.abs(hash) % COLOURS.length];
}

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

function truncateLabel(s, max = 42) {
  const t = String(s || '');
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function show(id, visible) {
  const el = typeof id === 'string' ? document.getElementById(id) : id;
  if (el) el.classList.toggle('hidden', !visible);
}

function axisOpts(horizontal = false) {
  const valueAxis = {
    beginAtZero: true,
    grid: { color: CHART_GRID },
    ticks: { color: CHART_TICK },
  };
  const catAxis = {
    grid: { display: false },
    ticks: { color: CHART_TICK, font: { family: 'JetBrains Mono', size: 11 } },
  };
  return horizontal
    ? { x: valueAxis, y: catAxis }
    : { x: catAxis, y: valueAxis };
}

async function fetchStats() {
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

/** Prefer server `events_by_country`; else roll up from ASN event_count. */
function countryEventCounts(stats) {
  if (stats.events_by_country && typeof stats.events_by_country === 'object') {
    return Object.entries(stats.events_by_country)
      .map(([country, count]) => ({ country, count: Number(count) || 0 }))
      .filter((r) => r.country && r.count > 0)
      .sort((a, b) => b.count - a.count);
  }
  const map = {};
  for (const a of stats.top_asns || []) {
    const c = (a.country || '??').toUpperCase();
    map[c] = (map[c] || 0) + (Number(a.event_count) || 0);
  }
  return Object.entries(map)
    .map(([country, count]) => ({ country, count }))
    .sort((a, b) => b.count - a.count);
}

/** Prefer server `cve_severity_counts`; else roll up from attempts. */
function severityCounts(stats) {
  if (stats.cve_severity_counts && typeof stats.cve_severity_counts === 'object') {
    return Object.entries(stats.cve_severity_counts)
      .map(([severity, count]) => ({ severity, count: Number(count) || 0 }))
      .filter((r) => r.count > 0)
      .sort((a, b) => b.count - a.count);
  }
  const map = {};
  for (const c of stats.cve_attempts || []) {
    const sev = (c.severity || 'Unknown').trim() || 'Unknown';
    map[sev] = (map[sev] || 0) + (Number(c.count) || 0);
  }
  return Object.entries(map)
    .map(([severity, count]) => ({ severity, count }))
    .sort((a, b) => b.count - a.count);
}

function peakDay(eventsPerDay) {
  let bestDay = null;
  let bestTotal = 0;
  for (const [day, row] of Object.entries(eventsPerDay || {})) {
    const total = Number(row.total != null ? row.total : Object.entries(row)
      .filter(([k]) => k !== 'total')
      .reduce((s, [, v]) => s + (Number(v) || 0), 0));
    if (total > bestTotal) {
      bestTotal = total;
      bestDay = day;
    }
  }
  return { day: bestDay, total: bestTotal };
}

function renderSummary(stats) {
  const el = document.getElementById('summary-grid');
  if (!el) return;

  const daysWithData = Object.keys(stats.events_per_day || {}).length;
  const honeypotCount = (stats.honeypots || []).length;
  const cves = stats.cve_attempts || [];
  const cveAttempts = cves.reduce((s, c) => s + (Number(c.count) || 0), 0);
  const criticalCves = cves.filter((c) => String(c.severity || '').toLowerCase() === 'critical').length;
  const peak = peakDay(stats.events_per_day);
  const countries = countryEventCounts(stats);
  const asns = stats.top_asns || [];
  const topAsn = asns[0];
  const asnEvents = asns.reduce((s, a) => s + (Number(a.event_count) || 0), 0);
  const topAsnShare = topAsn && asnEvents
    ? `${Math.round((topAsn.event_count / asnEvents) * 100)}%`
    : '—';

  const methods = stats.method_counts || {};
  const methodTotal = Object.values(methods).reduce((s, v) => s + (Number(v) || 0), 0);
  const getCount = Number(methods.GET || 0);
  const getShare = methodTotal ? `${Math.round((getCount / methodTotal) * 100)}%` : '—';

  const cards = [
    ['Total events', fmtNum(stats.total_events)],
    ['Unique IPs', fmtNum(stats.unique_ips)],
    ['Active honeypots', fmtNum(honeypotCount)],
    ['Days with data', fmtNum(daysWithData)],
    ['Peak day volume', peak.day ? fmtNum(peak.total) : '—', peak.day || 'No peak yet', true],
    ['CVE IDs / attempts', `${fmtNum(cves.length)} / ${fmtNum(cveAttempts)}`, null, true],
    ['Critical CVEs', fmtNum(criticalCves)],
    ['ASNs observed', fmtNum(asns.length)],
    ['Top ASN share', topAsn ? `${escHtml(topAsn.asn)} · ${topAsnShare}` : '—', topAsn?.name || null, true],
    ['GET share', getShare],
    ['Countries (ASN)', fmtNum(countries.length)],
  ];

  el.innerHTML = cards.map(([label, value, title, small]) => `
    <div class="summary-card"${title ? ` title="${escHtml(title)}"` : ''}>
      <span class="summary-value${small ? ' sm' : ''}">${value}</span>
      <span class="summary-label">${escHtml(label)}</span>
    </div>`).join('');
}

function renderMeta(stats) {
  const el = document.getElementById('meta-line');
  if (!el) return;
  const ts = stats.generated_at
    ? new Date(stats.generated_at).toUTCString()
    : 'unknown';
  const honeypots = (stats.honeypots || []).map((h) =>
    `<span class="badge badge-source">${escHtml(h)}</span>`).join(' ');
  el.innerHTML = `Stats generated: ${escHtml(ts)} &nbsp;|&nbsp; Honeypots: ${honeypots || '—'} &nbsp;|&nbsp;
    Source: <a href="https://github.com/seckid/logs/blob/main/stats/stats.json" target="_blank" rel="noopener">seckid/logs/stats/stats.json</a>`;
}

function renderTrafficChart(eventsPerDay, honeypots) {
  const days = Object.keys(eventsPerDay || {}).sort();
  if (!days.length) return;

  const sources = (honeypots || []).filter((s) => s !== 'total');
  const datasets = sources.map((src) => ({
    label: src,
    data: days.map((d) => (eventsPerDay[d] || {})[src] || 0),
    borderColor: sourceColour(src),
    backgroundColor: sourceColour(src) + '22',
    borderWidth: 2,
    pointRadius: days.length > 60 ? 0 : 3,
    pointHoverRadius: 5,
    tension: 0.3,
    fill: false,
  }));

  datasets.push({
    label: 'Total',
    data: days.map((d) => {
      const row = eventsPerDay[d] || {};
      if (row.total != null) return Number(row.total) || 0;
      return Object.entries(row)
        .filter(([k]) => k !== 'total')
        .reduce((s, [, v]) => s + (Number(v) || 0), 0);
    }),
    borderColor: '#e2e8f0',
    backgroundColor: 'transparent',
    borderWidth: 2.5,
    borderDash: [6, 4],
    pointRadius: 0,
    pointHoverRadius: 4,
    tension: 0.25,
    fill: false,
    order: 0,
  });

  makeChart('chart-traffic', {
    type: 'line',
    data: { labels: days, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { position: 'top', labels: { color: CHART_TICK, padding: 10 } },
        tooltip: {
          callbacks: {
            footer: (items) => {
              const totalItem = items.find((i) => i.dataset.label === 'Total');
              if (totalItem) return '';
              const total = items.reduce((s, i) => s + i.parsed.y, 0);
              return `Total: ${total.toLocaleString()}`;
            },
          },
        },
      },
      scales: {
        x: { grid: { color: CHART_GRID }, ticks: { color: CHART_TICK, maxRotation: 45 } },
        y: { beginAtZero: true, grid: { color: CHART_GRID }, ticks: { color: CHART_TICK } },
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
        borderColor: '#141b2d',
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position: 'bottom', labels: { color: CHART_TICK, padding: 8 } },
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
      scales: axisOpts(true),
    },
  });
}

function renderCountriesChart(stats) {
  const rows = countryEventCounts(stats).slice(0, 12);
  if (!rows.length) return;
  makeChart('chart-countries', {
    type: 'doughnut',
    data: {
      labels: rows.map((r) => r.country),
      datasets: [{
        data: rows.map((r) => r.count),
        backgroundColor: rows.map((_, i) => COLOURS[i % COLOURS.length]),
        borderColor: '#141b2d',
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position: 'bottom', labels: { color: CHART_TICK, padding: 8 } },
        tooltip: { callbacks: { label: (c) => ` ${c.label}: ${c.parsed.toLocaleString()}` } },
      },
    },
  });
}

function renderCvesChart(cves) {
  const top = [...(cves || [])].sort((a, b) => b.count - a.count).slice(0, 12);
  if (!top.length) return;
  makeChart('chart-cves', {
    type: 'bar',
    data: {
      labels: top.map((c) => c.cve),
      datasets: [{
        label: 'Attempts',
        data: top.map((c) => c.count),
        backgroundColor: top.map((c) => severityColour(c.severity) + 'cc'),
        borderWidth: 0,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: { legend: { display: false } },
      scales: axisOpts(true),
    },
  });
}

function renderSeverityChart(stats) {
  const rows = severityCounts(stats);
  if (!rows.length) return;
  makeChart('chart-severity', {
    type: 'doughnut',
    data: {
      labels: rows.map((r) => r.severity),
      datasets: [{
        data: rows.map((r) => r.count),
        backgroundColor: rows.map((r) =>
          SEVERITY_COLOURS[String(r.severity).toLowerCase()] || SEVERITY_COLOURS.unknown),
        borderColor: '#141b2d',
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position: 'bottom', labels: { color: CHART_TICK, padding: 8 } },
        tooltip: { callbacks: { label: (c) => ` ${c.label}: ${c.parsed.toLocaleString()}` } },
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
      labels: top.map((a) => a.asn || a.name || '?'),
      datasets: [{
        label: 'Events',
        data: top.map((a) => a.event_count),
        backgroundColor: 'rgba(139,92,246,.75)',
        borderColor: 'rgb(139,92,246)',
        borderWidth: 1,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: { legend: { display: false } },
      scales: axisOpts(true),
    },
  });
}

function renderPathsChart(paths) {
  const top = (paths || []).slice(0, 12);
  if (!top.length) return;
  makeChart('chart-paths', {
    type: 'bar',
    data: {
      labels: top.map((p) => truncateLabel(p.path, 36)),
      datasets: [{
        label: 'Count',
        data: top.map((p) => p.count),
        backgroundColor: 'rgba(6,182,212,.75)',
        borderWidth: 0,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title: (items) => {
              const i = items[0]?.dataIndex;
              return i != null ? (top[i].path || '') : '';
            },
          },
        },
      },
      scales: axisOpts(true),
    },
  });
}

function renderUserAgentsChart(uas) {
  const top = (uas || []).slice(0, 8);
  if (!top.length) return;
  makeChart('chart-uas', {
    type: 'bar',
    data: {
      labels: top.map((u) => truncateLabel(u.user_agent, 34)),
      datasets: [{
        label: 'Count',
        data: top.map((u) => u.count),
        backgroundColor: 'rgba(236,72,153,.7)',
        borderWidth: 0,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title: (items) => {
              const i = items[0]?.dataIndex;
              return i != null ? (top[i].user_agent || '') : '';
            },
          },
        },
      },
      scales: axisOpts(true),
    },
  });
}

function renderCredentialsChart(stats) {
  const usernames = stats.top_usernames;
  let labels;
  let data;
  if (Array.isArray(usernames) && usernames.length) {
    const top = usernames.slice(0, 10);
    labels = top.map((u) => truncateLabel(u.username || '(empty)', 24));
    data = top.map((u) => u.count);
  } else {
    const map = {};
    for (const c of stats.top_credentials || []) {
      const u = c.username || '(empty)';
      map[u] = (map[u] || 0) + (Number(c.count) || 0);
    }
    const top = Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, 10);
    if (!top.length) return;
    labels = top.map(([u]) => truncateLabel(u, 24));
    data = top.map(([, n]) => n);
  }

  makeChart('chart-creds', {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Attempts',
        data,
        backgroundColor: 'rgba(245,158,11,.75)',
        borderWidth: 0,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: { legend: { display: false } },
      scales: axisOpts(true),
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
    case 'high': return '#f97316';
    case 'medium': return '#f59e0b';
    case 'low': return '#10b981';
    default: return '#6b7280';
  }
}

function chipList(items, { limit = IP_CHIP_LIMIT, chipClass = 'ip-chip' } = {}) {
  const list = items || [];
  if (!list.length) return '<span style="color:#6b7280">—</span>';
  const shown = list.slice(0, limit);
  const rest = list.length - shown.length;
  const chips = shown.map((v) =>
    `<code class="${chipClass}">${escHtml(v)}</code>`).join('');
  const more = rest > 0
    ? `<span class="chip-more" title="${escHtml(list.slice(limit).join(', '))}">+${rest} more</span>`
    : '';
  return `<div class="chip-row">${chips}${more}</div>`;
}

function renderCves(cves) {
  if (!cves || !cves.length) {
    renderTable('table-cves', ['<tr><td colspan="7" style="color:#6b7280">No CVE attempts recorded.</td></tr>']);
    return;
  }
  renderTable('table-cves', cves.map((c) => {
    const severityBadge = c.severity
      ? `<span style="color:${severityColour(c.severity)};font-weight:600;font-size:.72rem">${escHtml(c.severity)}</span>${c.cvss_score ? ` <span style="color:#9ca3af;font-size:.72rem">(${c.cvss_score})</span>` : ''}`
      : '—';
    return `
    <tr>
      <td><span class="badge badge-cve">${escHtml(c.cve)}</span></td>
      <td class="cell-break" style="font-size:.78rem;color:#d1d5db">
        ${c.description ? escHtml(c.description) : '<span style="color:#6b7280">—</span>'}
      </td>
      <td>${severityBadge}</td>
      <td>${fmtNum(c.count)}</td>
      <td>${(c.sources || []).map((s) => `<span class="badge badge-source">${escHtml(s)}</span>`).join(' ') || '—'}</td>
      <td>${chipList(c.sample_paths, { limit: 5, chipClass: 'path-chip' })}</td>
      <td>${chipList(c.sample_ips, { limit: IP_CHIP_LIMIT, chipClass: 'ip-chip' })}</td>
    </tr>`;
  }));
}

function renderAsnsTable(asns) {
  if (!asns || !asns.length) {
    renderTable('table-asns', ['<tr><td colspan="5" style="color:#6b7280">No ASN data yet.</td></tr>']);
    return;
  }
  renderTable('table-asns', asns.map((a) => `
    <tr>
      <td><code class="ip-chip">${escHtml(a.asn)}</code></td>
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
  renderTable('table-paths', paths.map((p) => `
    <tr>
      <td><code class="path-chip">${escHtml(p.path)}</code></td>
      <td><span class="badge badge-source">${escHtml(p.source)}</span></td>
      <td>${fmtNum(p.count)}</td>
    </tr>`));
}

function renderUserAgents(uas) {
  if (!uas || !uas.length) {
    renderTable('table-uas', ['<tr><td colspan="2" style="color:#6b7280">No user agent data.</td></tr>']);
    return;
  }
  renderTable('table-uas', uas.map((u) => `
    <tr>
      <td class="ua-cell">${escHtml(u.user_agent)}</td>
      <td>${fmtNum(u.count)}</td>
    </tr>`));
}

function renderCredentials(creds) {
  if (!creds || !creds.length) {
    renderTable('table-creds', ['<tr><td colspan="3" style="color:#6b7280">No credentials captured.</td></tr>']);
    return;
  }
  renderTable('table-creds', creds.map((c) => `
    <tr>
      <td><code class="ip-chip">${escHtml(c.username)}</code></td>
      <td><code class="ip-chip">${escHtml(c.password)}</code></td>
      <td>${fmtNum(c.count)}</td>
    </tr>`));
}

function renderAll(stats, days) {
  renderMeta(stats);
  renderSummary(stats);

  const filtered = filterDays(stats.events_per_day, days);
  renderTrafficChart(filtered, stats.honeypots);
  renderSourcesChart(stats.totals_by_source);
  renderMethodsChart(stats.method_counts);
  renderCountriesChart(stats);
  renderCvesChart(stats.cve_attempts);
  renderSeverityChart(stats);
  renderAsnsChart(stats.top_asns);
  renderPathsChart(stats.top_paths);
  renderUserAgentsChart(stats.top_user_agents);
  renderCredentialsChart(stats);
  renderCves(stats.cve_attempts);
  renderAsnsTable(stats.top_asns);
  renderPaths(stats.top_paths);
  renderUserAgents(stats.top_user_agents);
  renderCredentials(stats.top_credentials);
}

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
    _cachedStats = null;
    runStats();
  });

  document.getElementById('date-range')?.addEventListener('change', () => {
    if (_cachedStats) {
      const btn = document.getElementById('load-stats');
      if (btn) btn._fromCache = true;
      runStats();
    }
  });

  runStats();
});
