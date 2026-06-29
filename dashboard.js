const HEADERS = { 'Authorization': 'Bearer ' + CTL_TOKEN, 'X-SurgicalFS-Ctl': '1' };

const LAT_BUCKETS = [
  ['lt_1ms', '<1ms'], ['lt_10ms', '<10ms'], ['lt_50ms', '<50ms'], ['lt_100ms', '<100ms'],
  ['lt_500ms', '<500ms'], ['lt_1s', '<1s'], ['lt_5s', '<5s'], ['gte_5s', '≥5s'],
];
let MAX_FEED = 100;                  // user-selectable via the feed line-limit select
let READ_ONLY = false;               // set from /ready; disables toggle buttons when true
let POLL_MS = 5000;                  // user-selectable via the auto-refresh select
let pollTimer = null, toolsTimer = null;
let pollFailures = 0;                // consecutive poll failures (for the recovery panel)
let shuttingDown = false;            // true after a restart/stop is confirmed

// ── Theme (no localStorage / sessionStorage; system preference + manual) ──
function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  document.getElementById('themeBtn').innerHTML = t === 'dark' ? '&#9728;' : '&#9790;';
}
function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme');
  setTheme(cur === 'dark' ? 'light' : 'dark');
}
setTheme(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');

// ── Helpers ──
function $(id) { return document.getElementById(id); }
// Escapes for BOTH text and attribute contexts (tool descriptions contain quotes).
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function fmtBytes(b) {
  if (b == null) return '—';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}
function fmtUptime(s) {
  if (s == null) return '—';
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (d) return `${d}d ${h}h ${m}m`;
  if (h) return `${h}h ${m}m ${sec}s`;
  if (m) return `${m}m ${sec}s`;
  return `${sec}s`;
}
function nowHms() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// ── Status ──
function setStatus(ok) {
  // Once a shutdown is requested, the status text is frozen (Restarting…/Stopped)
  // until a page reload — the banners drive recovery from here.
  if (shuttingDown) return;
  const dot = $('statusDot'), txt = $('statusText');
  dot.className = 'status-dot ' + (ok ? 'ok' : 'down');
  txt.textContent = ok ? 'connected' : 'unreachable';
}

// ── Recovery / stale-token banners ──
function showStaleToken() { $('staleToken').style.display = 'flex'; }
function hideStaleToken() { $('staleToken').style.display = 'none'; }
function showRecovery(summary) {
  if (summary) $('recoverySummary').textContent = summary;
  $('recoveryPanel').style.display = 'block';
}
function hideRecovery() { $('recoveryPanel').style.display = 'none'; }

// ── Health + metrics polling ──
async function poll() {
  try {
    const [health, metrics] = await Promise.all([
      fetch('/health', { headers: HEADERS }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); }),
      fetch('/metrics', { headers: HEADERS }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); }),
    ]);
    renderHealth(health);
    renderMetrics(metrics);
    setStatus(true);
    pollFailures = 0;
    hideRecovery();
    hideStaleToken();
  } catch (e) {
    pollFailures++;
    setStatus(false);
    // 401 ⇒ the server rebooted and minted a new per-boot token (ours is stale):
    // a refresh is the only path back. Other failures ⇒ likely down → recovery hint.
    if (String(e && e.message) === '401') {
      showStaleToken();
    } else if (pollFailures >= 3) {
      showRecovery();
    }
  }
}

function renderHealth(h) {
  $('versionBadge').textContent = 'v' + (h.version || '—');
  $('mUptime').textContent = fmtUptime(h.uptime_secs);
  $('mPid').textContent = h.pid != null ? h.pid : '—';
  if (h.rss_bytes != null) $('mRss').textContent = fmtBytes(h.rss_bytes);
  if (h.handle_count != null) $('mHandles').textContent = h.handle_count;
}

function renderMetrics(m) {
  const req = m.requests || {}, lat = m.latency || {}, proc = m.process || {};
  const total = req.total != null ? req.total : 0;
  const errors = req.errors != null ? req.errors : 0;
  $('mRequests').textContent = req.total != null ? req.total : '—';
  const errEl = $('mErrors');
  errEl.textContent = req.errors != null ? req.errors : '—';
  errEl.className = 'value' + (errors > 0 ? ' alert' : '');
  // Error rate: green <1%, amber 1–5%, red >5%.
  const rateEl = $('mErrRate');
  const rate = total > 0 ? (errors / total * 100) : 0;
  rateEl.textContent = total > 0 ? rate.toFixed(1) + '%' : '0%';
  rateEl.style.color = rate > 5 ? 'var(--danger)' : (rate >= 1 ? 'var(--amber)' : 'var(--green)');
  $('mErrRateSub').textContent = `(${errors} / ${total})`;
  $('mInflight').textContent = req.in_flight != null ? req.in_flight : '—';
  $('mInflightSub').textContent = req.max_concurrent != null ? ('max ' + req.max_concurrent) : '';
  // Avg latency = sum_us / total.
  if (lat.sum_us != null && req.total) {
    const avgUs = lat.sum_us / req.total;
    $('mAvgLat').textContent = avgUs >= 1000 ? (avgUs / 1000).toFixed(1) + ' ms' : Math.round(avgUs) + ' µs';
  } else {
    $('mAvgLat').textContent = '0 µs';
  }
  if (proc.rss_bytes != null) $('mRss').textContent = fmtBytes(proc.rss_bytes);
  if (proc.handle_count != null) $('mHandles').textContent = proc.handle_count;
  // Sparklines (Phase 3): push this sample, then redraw.
  const avgUs = (lat.sum_us != null && req.total) ? lat.sum_us / req.total : 0;
  pushSpark('requests', total);
  pushSpark('errors', errors);
  pushSpark('rss', proc.rss_bytes != null ? proc.rss_bytes : 0);
  pushSpark('latency_avg', avgUs);
  renderSparklines(rate);
  // Latency histogram (Phase 3.5): record this poll's cumulative buckets, redraw.
  pushLatencyBuckets(lat.buckets || {});
  renderHistogram();
}

// ── Sparklines (client-side ring buffer; data from the existing /metrics poll) ──
const SPARKLINE_MAX = 60;
// latency_buckets holds an 8-element cumulative snapshot per poll, with a larger
// cap so the longest recent window (1h) has samples at typical poll rates.
const LATENCY_HISTORY_MAX = 1200;
let sparkHistory = { requests: [], rss: [], errors: [], latency_avg: [], latency_buckets: [] };
let lastMetricsBuckets = [0, 0, 0, 0, 0, 0, 0, 0]; // current cumulative /metrics buckets (Session)
let histAnalytics = null; // cached { today:[8], week:[8] } from /analytics, for comparison bars
function pushSpark(key, val) {
  const a = sparkHistory[key];
  a.push(val == null ? 0 : val);
  while (a.length > SPARKLINE_MAX) a.shift();
}
// Consecutive non-negative deltas (for cumulative rate metrics).
function deltas(arr) {
  const d = [];
  for (let i = 1; i < arr.length; i++) d.push(Math.max(0, arr[i] - arr[i - 1]));
  return d;
}
function sparkline(values, color) {
  if (!values || values.length < 2) return '';
  const w = 40, h = 16;
  const min = Math.min(...values), max = Math.max(...values), range = (max - min) || 1;
  const step = w / (values.length - 1);
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(h - ((v - min) / range) * h).toFixed(1)}`).join(' ');
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5"/></svg>`;
}
function renderSparklines(errRate) {
  const errColor = errRate >= 1 ? 'var(--danger)' : 'var(--accent)';
  $('sparkRequests').innerHTML = sparkline(deltas(sparkHistory.requests), 'var(--accent)');
  $('sparkErrors').innerHTML = sparkline(deltas(sparkHistory.errors), errColor);
  $('sparkRss').innerHTML = sparkline(sparkHistory.rss, 'var(--accent)');
  $('sparkLat').innerHTML = sparkline(sparkHistory.latency_avg, 'var(--accent)');
}

// ── Latency histogram (Phase 3.5: vertical, percentage-based, period comparison) ──
function bucketsToArray(obj) { return LAT_BUCKETS.map(([k]) => (obj || {})[k] || 0); }
function pushLatencyBuckets(buckets) {
  lastMetricsBuckets = bucketsToArray(buckets);
  sparkHistory.latency_buckets.push(lastMetricsBuckets);
  while (sparkHistory.latency_buckets.length > LATENCY_HISTORY_MAX) sparkHistory.latency_buckets.shift();
}
// "last N minutes" delta from the cumulative-bucket ring buffer (per §2.3).
function latencyDelta(minutes) {
  const samplesBack = Math.round((minutes * 60 * 1000) / POLL_MS);
  const h = sparkHistory.latency_buckets;
  if (h.length < 2) return null;
  const current = h[h.length - 1];
  const past = h[Math.max(0, h.length - 1 - samplesBack)];
  return current.map((v, i) => Math.max(0, v - past[i]));
}
function pctArray(counts) {
  const total = counts.reduce((a, b) => a + b, 0);
  return total > 0 ? counts.map(c => c / total * 100) : counts.map(() => 0);
}
async function onHistCompareChange() {
  // Comparison data comes from /analytics (cached after the first fetch).
  if ($('histCompare').value !== 'none' && !histAnalytics) await loadAnalytics();
  renderHistogram();
}
function renderHistogram() {
  const recentSel = $('histRecent').value;
  const cmp = $('histCompare').value;
  let recent, sub = '';
  if (recentSel === '0') { recent = lastMetricsBuckets; sub = 'session'; }
  else {
    const mins = parseInt(recentSel, 10);
    const d = latencyDelta(mins);
    recent = d || [0, 0, 0, 0, 0, 0, 0, 0];
    const samplesBack = Math.round((mins * 60 * 1000) / POLL_MS);
    const have = sparkHistory.latency_buckets.length - 1;
    sub = (d && have < samplesBack)
      ? `last ${mins}m (partial — ${Math.max(0, Math.round(have * POLL_MS / 60000))} min of data)`
      : `last ${mins}m`;
  }
  const series = [{ label: 'Recent (' + (recentSel === '0' ? 'session' : recentSel + 'm') + ')', color: 'var(--accent)', counts: recent }];
  if ((cmp === '24h' || cmp === 'both') && histAnalytics && histAnalytics.today) series.push({ label: 'Last 24h', color: 'var(--amber)', counts: histAnalytics.today });
  if ((cmp === '7d' || cmp === 'both') && histAnalytics && histAnalytics.week) series.push({ label: 'Last 7 days', color: 'var(--text-dim)', counts: histAnalytics.week });
  $('histSub').textContent = sub;
  drawHistogram(series);
  $('histLegend').innerHTML = series.map(s => `<span><span class="swatch" style="background:${s.color}"></span>${escHtml(s.label)}</span>`).join('');
}
function drawHistogram(series) {
  if (!series.some(s => s.counts.reduce((a, b) => a + b, 0) > 0)) {
    $('histChart').innerHTML = '<div class="hist-empty">No latency data yet</div>';
    return;
  }
  // Wider viewBox + roomier bottom margin so the monospace axis labels (set via
  // the .hist-svg text CSS rule) render legibly and don't clip (Phase 4 §2.3).
  const W = 520, H = 190, ml = 38, mr = 8, mt = 10, mb = 30;
  const pw = W - ml - mr, ph = H - mt - mb, groupW = pw / 8, n = series.length, barW = (groupW * 0.62) / n;
  const pcts = series.map(s => pctArray(s.counts));
  let svg = `<svg class="hist-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">`;
  for (let p = 0; p <= 100; p += 25) {
    const y = mt + ph - (p / 100) * ph;
    svg += `<line x1="${ml}" y1="${y}" x2="${W - mr}" y2="${y}" stroke="var(--border-light)" stroke-width="0.5"/>`;
    svg += `<text x="${ml - 4}" y="${y.toFixed(1)}" text-anchor="end" dominant-baseline="middle" font-size="9">${p}%</text>`;
  }
  LAT_BUCKETS.forEach(([k, label], i) => {
    const gx = ml + i * groupW + groupW * 0.19;
    series.forEach((s, si) => {
      const pct = pcts[si][i], bh = (pct / 100) * ph, x = gx + si * barW, y = mt + ph - bh;
      svg += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${bh.toFixed(1)}" fill="${s.color}"><title>${escHtml(s.label)}: ${s.counts[i]} calls (${pct.toFixed(1)}%)</title></rect>`;
    });
    svg += `<text x="${(ml + i * groupW + groupW / 2).toFixed(1)}" y="${(H - 9).toFixed(1)}" text-anchor="middle" dominant-baseline="hanging" font-size="10">${escHtml(label)}</text>`;
  });
  $('histChart').innerHTML = svg + '</svg>';
}

// ── Tool inventory ──
async function loadTools() {
  try {
    const data = await fetch('/admin/tools', { headers: HEADERS }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); });
    renderTools(data);
  } catch (e) { /* leave previous render */ }
}
function renderTools(data) {
  const roBadge = READ_ONLY ? ' <span class="ro-badge">read-only</span>' : '';
  $('toolSummary').innerHTML = `· ${data.enabled_count}/${data.total_count} enabled${roBadge}`;
  $('tools').innerHTML = (data.categories || []).map((cat, idx) => {
    const tools = (cat.tools || []).map(t => {
      const desc = t.description || '';
      const tnameTitle = desc ? ` title="${escHtml(desc)}"` : '';
      const info = desc ? ` <span class="tinfo" title="${escHtml(desc)}">&#9432;</span>` : '';
      return `
      <div class="tool ${t.enabled ? '' : 'disabled'}">
        <span class="dot ${t.enabled ? 'on' : 'off'}"></span>
        <span class="tname"${tnameTitle}>${escHtml(t.name)}</span>${info}
      </div>`;
    }).join('');
    // Category names come from a fixed server-side allowlist (no special chars),
    // so they are safe to inline into the onclick handler.
    // Show the current STATE (Phase 4.5): green "Enabled" when fully enabled, red
    // "Disabled" otherwise. The button still toggles on click (the title hints the
    // action). A partially-enabled category reads "Disabled"; the X/Y count shows
    // the partial state, and clicking enables the remainder.
    const fullyEnabled = cat.enabled_count === cat.total_count;
    const label = fullyEnabled ? 'Enabled' : 'Disabled';
    const stateCls = fullyEnabled ? 'on' : 'off';
    const hint = READ_ONLY ? 'Read-only mode' : (fullyEnabled ? 'Click to disable' : 'Click to enable');
    const btn = `<button class="cat-toggle ${stateCls}" ${READ_ONLY ? 'disabled' : ''} title="${hint}"` +
      ` onclick="toggleCategory(event, '${cat.category}', ${fullyEnabled})">${label}</button>`;
    return `<div class="cat">
      <div class="cat-head" onclick="toggleCat(${idx})">
        <span class="chev" id="chev-${idx}">&#9654;</span>
        <span class="cat-name">${escHtml(cat.category)}</span>
        <span class="cat-count">${cat.enabled_count}/${cat.total_count}</span>
        ${btn}
      </div>
      <div class="cat-body" id="catbody-${idx}">${tools}</div>
    </div>`;
  }).join('');
}
function toggleCat(idx) {
  $('catbody-' + idx).classList.toggle('open');
  $('chev-' + idx).classList.toggle('open');
}
async function toggleCategory(ev, category, fullyEnabled) {
  ev.stopPropagation(); // don't also expand/collapse the card
  if (READ_ONLY) return;
  try {
    await fetch('/admin/tools', {
      method: 'POST',
      headers: { ...HEADERS, 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: fullyEnabled ? 'disable' : 'enable', targets: [category] }),
    }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); });
    loadTools(); // refresh the panel immediately (SSE will also fire)
  } catch (e) { /* ignore — the next SSE event / poll reconciles */ }
}

// ── Activity feed (SSE) ──
function addActivity(ev) {
  const feed = $('feed');
  const empty = $('feedEmpty');
  if (empty) empty.remove();
  const row = document.createElement('div');
  row.className = 'feed-row';
  const st = ev.status === 'ok' ? 'ok' : 'error';
  row.innerHTML =
    `<span class="ts">${nowHms()}</span>` +
    `<span class="tool">${escHtml(ev.tool || '?')}</span>` +
    `<span class="args" title="${escHtml(ev.args_summary || '')}">${escHtml(ev.args_summary || '')}</span>` +
    `<span class="dur">${ev.duration_ms != null ? ev.duration_ms + 'ms' : ''}</span>` +
    `<span class="st ${st}">${st}</span>`;
  feed.insertBefore(row, feed.firstChild);
  while (feed.children.length > MAX_FEED) feed.removeChild(feed.lastChild);
}

function startEvents() {
  // EventSource cannot send custom headers, so the token rides the query string
  // (localhost-only; the token is URL-safe so encoding is a no-op). The browser
  // auto-reconnects on error.
  const es = new EventSource('/events?token=' + encodeURIComponent(CTL_TOKEN));
  es.addEventListener('tool_call', e => {
    try { addActivity(JSON.parse(e.data)); } catch (_) {}
  });
  es.addEventListener('health', e => {
    try {
      const h = JSON.parse(e.data);
      if (h.in_flight != null) $('mInflight').textContent = h.in_flight;
      if (h.rss_bytes != null) $('mRss').textContent = fmtBytes(h.rss_bytes);
      if (h.handle_count != null) $('mHandles').textContent = h.handle_count;
    } catch (_) {}
  });
  es.addEventListener('tool_toggle', () => {
    // A toggle happened (possibly from another operator) — re-fetch inventory.
    loadTools();
  });
}

// ── /ready (one-shot: footer context + read-only state) ──
async function loadReady() {
  try {
    const r = await fetch('/ready', { headers: HEADERS }).then(r => r.json());
    READ_ONLY = !!r.read_only;
    $('ftControlBind').textContent = 'control: ' + (r.control_bind || '') + ' · mcp: ' + (r.mcp_bind || '');
    // Auth status — red when the /mcp data plane has no bearer token. Clickable:
    // scrolls to and highlights the MCP Authentication panel (Phase 4 §2.2).
    const authEl = $('ftAuth');
    authEl.textContent = 'auth: ' + (r.auth_enabled ? 'bearer' : 'none');
    authEl.style.color = r.auth_enabled ? '' : 'var(--danger)';
    authEl.style.cursor = 'pointer';
    authEl.title = 'Manage MCP auth →';
    authEl.onclick = scrollToAuth;
    // Read-only mode — shown only when active.
    const modeEl = $('ftMode');
    if (r.read_only) { modeEl.textContent = 'mode: read-only'; modeEl.style.display = ''; }
    else { modeEl.style.display = 'none'; }
    $('ftConfigSource').textContent = r.config_source ? ('config: ' + r.config_source) : 'config: (directory args)';
    // Recovery panel: surface the log directory if /ready exposes one.
    $('recoveryLog').textContent = r.log_dir ? ('Log files: ' + r.log_dir) : '';
    // Connection trace: full topology when a tunnel URL is configured (Phase 3).
    const ct = $('connTrace');
    if (r.tunnel_url) {
      ct.style.display = '';
      ct.innerHTML = 'Connection: Claude.ai &rarr; CF edge (WAF/TLS) &rarr; cloudflared &rarr; '
        + escHtml(r.mcp_bind || '') + ' (MCP) &rarr; ' + escHtml(r.control_bind || '') + ' (Control)<br>Tunnel: ' + escHtml(r.tunnel_url);
    } else {
      ct.style.display = 'none';
    }
  } catch (e) {
  } finally {
    // Render the tool panel once READ_ONLY is known (so toggle buttons reflect it).
    loadTools();
  }
}

// ── Feed line-limit selector ──
function setFeedLimit(n) {
  MAX_FEED = parseInt(n, 10) || 100;
  $('feedLimitLabel').textContent = MAX_FEED;
  const feed = $('feed');
  while (feed.children.length > MAX_FEED) feed.removeChild(feed.lastChild);
}

// ── Auto-refresh interval selector ──
function setRefreshInterval(ms) {
  POLL_MS = parseInt(ms, 10) || 5000;
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(poll, POLL_MS);
  // The tool inventory refreshes 6× slower than the health poll, floor 10s.
  if (toolsTimer) clearInterval(toolsTimer);
  toolsTimer = setInterval(loadTools, Math.max(10000, POLL_MS * 6));
}

// ── Server restart / stop ──
function confirmServerAction(action) {
  if (shuttingDown) return;
  const t = $('modalTitle'), b = $('modalBody'), c = $('modalConfirm');
  if (action === 'restart') {
    t.textContent = 'Restart server?';
    b.textContent = 'Restart SurgicalFS server? The server will shut down and Shawl will restart it automatically. All active MCP connections will be interrupted. The dashboard will reconnect when the server is back.';
    c.textContent = 'Restart';
    c.className = 'srv-btn';
  } else {
    t.textContent = 'Stop server?';
    b.textContent = 'Stop SurgicalFS server? The server will shut down and will NOT restart automatically. You will need to start it manually. Are you sure?';
    c.textContent = 'Stop';
    c.className = 'srv-btn danger';
  }
  c.onclick = () => doServerAction(action);
  $('modalOverlay').style.display = 'flex';
}
function closeModal() { $('modalOverlay').style.display = 'none'; }

async function doServerAction(action) {
  closeModal();
  shuttingDown = true;
  $('btnRestart').disabled = true;
  $('btnStop').disabled = true;
  const dot = $('statusDot'), txt = $('statusText');
  dot.className = 'status-dot pulse';
  txt.textContent = action === 'restart' ? 'Restarting…' : 'Stopping…';
  try {
    await fetch('/admin/server', {
      method: 'POST',
      headers: { ...HEADERS, 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    });
  } catch (e) {
    // The connection drops as the server shuts down — expected, not an error.
  }
  if (action === 'stop') {
    txt.textContent = 'Server stopped';
    dot.className = 'status-dot down';
    showRecovery('Server stopped — not running');
  }
  // For restart, the poll loop detects the server going down and returning; the
  // new per-boot token makes polls 401, which raises the stale-token banner.
}

// ── Analytics (loaded on demand — NOT on the auto-refresh timer) ──
let anPerTool = [];
let anSort = { key: 'calls', dir: -1 };

function fmtNum(n) {
  if (n == null) return '—';
  if (n < 1000) return String(n);
  if (n < 1e6) return (n / 1e3).toFixed(1) + 'K';
  if (n < 1e9) return (n / 1e6).toFixed(1) + 'M';
  return (n / 1e9).toFixed(1) + 'G';
}
function fmtTime(iso) {
  try {
    const d = new Date(iso);
    const p = n => String(n).padStart(2, '0');
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  } catch (_) { return iso; }
}

async function loadAnalytics() {
  $('anStatus').textContent = 'loading…';
  try {
    const d = await fetch('/analytics', { headers: HEADERS }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); });
    renderAnalytics(d);
  } catch (e) {
    $('anStatus').textContent = 'failed to load';
    $('anBody').innerHTML = '<div class="feed-empty">Could not load analytics.</div>';
  }
}

function periodCard(label, p) {
  if (!p) return `<div class="card"><div class="label">${label}</div><div class="value small" style="color:var(--text-dim)">N/A</div><div class="sub">enable [analytics] log_dir</div></div>`;
  return `<div class="card">
    <div class="label">${label}</div>
    <div class="value small">${fmtNum(p.estimated_tokens)} tok</div>
    <div class="sub">${fmtBytes(p.total_bytes)}</div>
    <div class="sub">${fmtNum(p.total_calls)} calls</div>
  </div>`;
}

function renderAnalytics(d) {
  $('anStatus').textContent = d.logging_enabled
    ? ('logging: active (' + (d.log_dir || '') + ')')
    : 'logging: disabled';
  anPerTool = d.per_tool || [];
  // Cache the period latency histograms for the histogram comparison bars (§2.2).
  histAnalytics = {
    today: (d.today && d.today.latency_buckets) ? bucketsToArray(d.today.latency_buckets) : null,
    week: (d.last_7_days && d.last_7_days.latency_buckets) ? bucketsToArray(d.last_7_days.latency_buckets) : null,
  };
  renderHistogram();

  const cards = `<div class="cards">
    ${periodCard('Session', d.session)}
    ${periodCard('Today', d.today)}
    ${periodCard('Last 7 Days', d.last_7_days)}
    ${periodCard('Last 30 Days', d.last_30_days)}
  </div>`;

  const pres = d.presentation || { calls: 0, total_bytes: 0, estimated_tokens: 0 };
  const sess = d.session || { total_calls: 0, total_bytes: 0, estimated_tokens: 0 };
  const presPerCall = pres.calls > 0 ? Math.round(pres.estimated_tokens / pres.calls) : 0;
  const contPerCall = sess.total_calls > 0 ? Math.round(sess.estimated_tokens / sess.total_calls) : 0;
  const split = `<div class="an-split">
    <div><span style="color:var(--accent)">Presentation (schema):</span> ${fmtNum(pres.estimated_tokens)} tok (${fmtBytes(pres.total_bytes)}) · ${fmtNum(pres.calls)} calls · ~${fmtNum(presPerCall)} tok/call</div>
    <div><span style="color:var(--accent)">Content (tool output):</span> ${fmtNum(sess.estimated_tokens)} tok (${fmtBytes(sess.total_bytes)}) · ${fmtNum(sess.total_calls)} calls · ~${fmtNum(contPerCall)} tok/call</div>
  </div>`;

  $('anBody').innerHTML = cards + split
    + '<div class="an-sub">Per-tool (session)</div><div id="anToolTable">' + renderToolTable() + '</div>'
    + '<div class="an-sub">Repositories (session)</div>' + renderRepoTable(d.per_repo || []);
}

function renderToolTable() {
  if (!anPerTool.length) return '<div class="feed-empty">No tool calls yet this session.</div>';
  const rows = [...anPerTool].sort((a, b) => {
    const k = anSort.key, av = a[k], bv = b[k];
    if (k === 'tool' || k === 'last_called') return anSort.dir * String(av || '').localeCompare(String(bv || ''));
    return anSort.dir * ((av || 0) - (bv || 0));
  });
  const cols = [
    ['tool', 'Tool', false], ['calls', 'Calls', true], ['estimated_tokens', 'Tokens', true],
    ['total_bytes', 'Bytes', true], ['avg_duration_ms', 'Avg ms', true], ['errors', 'Errors', true],
    ['last_called', 'Last called', false],
  ];
  const ths = cols.map(([k, label, num]) => {
    const arrow = anSort.key === k ? (anSort.dir < 0 ? ' ▾' : ' ▴') : '';
    return `<th class="${num ? 'num' : ''}" onclick="sortTools('${k}')">${label}${arrow}</th>`;
  }).join('');
  const body = rows.map(t => `<tr>
    <td class="tname">${escHtml(t.tool)}</td>
    <td class="num">${fmtNum(t.calls)}</td>
    <td class="num">${fmtNum(t.estimated_tokens)}</td>
    <td class="num">${fmtBytes(t.total_bytes)}</td>
    <td class="num">${(t.avg_duration_ms || 0).toFixed(1)}</td>
    <td class="num">${t.errors || 0}</td>
    <td>${t.last_called ? fmtTime(t.last_called) : '—'}</td>
  </tr>`).join('');
  return `<table class="an-table"><thead><tr>${ths}</tr></thead><tbody>${body}</tbody></table>`;
}
function sortTools(key) {
  if (anSort.key === key) anSort.dir = -anSort.dir;
  else { anSort.key = key; anSort.dir = (key === 'tool' || key === 'last_called') ? 1 : -1; }
  const el = $('anToolTable');
  if (el) el.innerHTML = renderToolTable();
}

function renderRepoTable(repos) {
  if (!repos.length) return '<div class="feed-empty">No repository activity yet.</div>';
  const body = repos.map(r => `<tr>
    <td class="tname">${escHtml(r.repo)}</td>
    <td class="num">${fmtNum(r.calls)}</td>
    <td class="num">${fmtNum(r.estimated_tokens)}</td>
    <td class="num">${fmtBytes(r.total_bytes)}</td>
    <td class="num">${r.tools_used}</td>
  </tr>`).join('');
  return `<table class="an-table"><thead><tr><th>Repository</th><th class="num">Calls</th><th class="num">Tokens</th><th class="num">Bytes</th><th class="num">Tools</th></tr></thead><tbody>${body}</tbody></table>`;
}

async function exportAnalytics(range) {
  if (!range) return;
  try {
    const r = await fetch('/analytics/export?range=' + encodeURIComponent(range), { headers: HEADERS });
    if (!r.ok) throw new Error(r.status);
    const text = await r.text();
    if (!text) {
      // Empty body = nothing to export (logging disabled or no data for the range).
      $('anStatus').textContent = 'nothing to export (logging disabled?)';
      $('anExport').value = '';
      return;
    }
    const blob = new Blob([text], { type: 'application/x-ndjson' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'surgicalfs-analytics-' + range + '.jsonl';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    $('anStatus').textContent = 'export failed (' + (e && e.message) + ')';
  }
  $('anExport').value = ''; // reset to the "Export ▾" placeholder
}

// ── Logs panel (on-demand, not auto-polled) ──
let logFiles = []; // cached file list; download handlers reference entries by index
async function loadLogs() {
  $('logStatus').textContent = 'loading…';
  const n = $('logLines').value;
  try {
    // Fetch the log tail (running state) AND the sidecar status (pending state)
    // together, so the panel can show a "pending: enabled/disabled on restart"
    // banner and resolve any number of enable/disable clicks with ONE restart
    // (Phase 4.6).
    const [d, status] = await Promise.all([
      fetch('/logs?lines=' + encodeURIComponent(n), { headers: HEADERS }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); }),
      fetch('/admin/logging', { headers: HEADERS }).then(r => r.ok ? r.json() : null).catch(() => null),
    ]);
    renderLogs(d, status);
  } catch (e) {
    $('logStatus').textContent = 'failed to load';
    $('logBody').innerHTML = '<div class="feed-empty">Could not load logs.</div>';
  }
}
// Amber "pending change" banner — shown when the on-disk sidecar differs from
// the running state. A restart applies the LATEST sidecar write (Phase 4.6).
function loggingPendingBanner(status) {
  if (!status || !status.restart_required || !status.pending) return '';
  const willBe = status.pending.enabled ? 'enabled' : 'disabled';
  return `<div class="banner warn" style="margin-bottom:10px"><span>Pending: file logging will be <b>${willBe}</b> on restart.</span>`
    + `<button class="srv-btn" style="margin-left:auto" onclick="confirmServerAction('restart')">Restart now</button></div>`;
}
function renderLogs(d, status) {
  const banner = loggingPendingBanner(status);
  // The action button offers the OPPOSITE of the EFFECTIVE next-boot state
  // (pending if staged, else running), so enable<->disable can flip freely
  // before a single restart — both actions stay reachable regardless of state.
  const effEnabled = (status && status.pending) ? status.pending.enabled : d.enabled;
  const actionBtn = effEnabled
    ? `<button class="srv-btn danger" onclick="disableLogging()">Disable Logging</button>`
    : `<button class="srv-btn" onclick="enableLogging()">Enable Logging</button>`;
  if (!d.enabled) {
    // Running logging is OFF — no live files. Show the enable/pending panel.
    const pendingOn = !!(status && status.pending && status.pending.enabled);
    $('logStatus').textContent = pendingOn ? 'logging: off (pending: enabled — restart to apply)' : 'logging: disabled';
    const intro = pendingOn
      ? 'File logging will be <b>enabled</b> on the next restart.'
      : 'File logging is not enabled. Enable it to view logs, unlock analytics history (today/7d/30d), latency comparisons, and export.';
    $('logBody').innerHTML = banner +
      `<div class="auth-box">
        <div style="font-size:13px;margin-bottom:10px">${intro}</div>
        ${actionBtn}
        <span style="font-size:12px;color:var(--text-dim);margin-left:8px">(default: &lt;config dir&gt;\\logs · 30-day retention)</span>
        <div id="loggingResult" style="margin-top:8px"></div>
        <div style="font-size:12px;color:var(--text-dim);margin-top:8px">A server restart is required for the change to take effect.</div>
      </div>`;
    return;
  }
  $('logStatus').textContent = 'logging: active · ' + (d.log_dir || '');
  logFiles = d.files || [];
  // Reference files by index in the inline handler — never inline the filename
  // into a JS-string-in-attribute (avoids any escaping foot-gun).
  const files = logFiles.map((f, i) =>
    `<div class="log-file"><span class="lf-dl" onclick="downloadLog(${i})">&darr;</span>
      <span>${escHtml(f.name)}</span><span style="color:var(--text-dim)">(${fmtBytes(f.size_bytes)})</span></div>`).join('');
  const tail = (d.tail || []).map(renderLogLine).join('');
  $('logBody').innerHTML = banner +
    `<div style="margin-bottom:8px">${actionBtn}<span id="loggingResult" style="margin-left:8px"></span></div>`
    + `<div class="log-files">${files || '<span style="color:var(--text-dim)">no files</span>'}</div>`
    + `<div class="log-tail">${tail || '<span style="color:var(--text-dim)">empty</span>'}</div>`;
}
// Logging enable/disable via the /admin/logging sidecar (Phase 4 §2.1; Phase 4.6
// pending-state UX). Each click overwrites the sidecar; the banner + button
// re-render so the operator can stack changes and restart once.
function enableLogging() { loggingAction({ action: 'enable' }); }
function disableLogging() {
  if (confirm('Disable file logging? Existing log files are kept; new entries stop after the next restart.')) loggingAction({ action: 'disable' });
}
async function loggingAction(body) {
  try {
    const d = await fetch('/admin/logging', {
      method: 'POST', headers: { ...HEADERS, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); });
    // Re-render so the pending banner + action button reflect the new on-disk
    // sidecar (the last write before a restart is what applies).
    await loadLogs();
    const out = $('loggingResult');
    if (out) {
      const msg = body.action === 'enable'
        ? ('Logging will write to ' + escHtml(d.log_dir || '') + '. Restart to apply.')
        : 'Logging will be disabled. Restart to apply.';
      out.innerHTML = `<span style="color:var(--amber);font-size:12px">${msg}</span>`;
    }
  } catch (e) {
    const out = $('loggingResult');
    if (out) out.innerHTML = `<span style="color:var(--danger);font-size:12px">Action failed (${e && e.message}).</span>`;
  }
}
function renderLogLine(line) {
  try {
    const j = JSON.parse(line);
    const ts = j.timestamp ? fmtTime(j.timestamp) : '';
    const lvl = (j.level || '').toUpperCase();
    let msg = (j.fields && j.fields.message != null) ? j.fields.message : (j.message != null ? j.message : line);
    if (typeof msg !== 'string') msg = JSON.stringify(msg); // structured message → legible
    return `<div class="log-line"><span class="lts">${escHtml(ts)}</span><span class="llv ${escHtml(lvl)}">${escHtml(lvl)}</span><span class="lmsg">${escHtml(msg)}</span></div>`;
  } catch (_) {
    return `<div class="log-line"><span class="lmsg">${escHtml(line)}</span></div>`;
  }
}
async function downloadLog(i) {
  const f = logFiles[i];
  if (!f) return;
  const fileEnc = encodeURIComponent(f.name);
  try {
    const r = await fetch('/logs/download?file=' + fileEnc, { headers: HEADERS });
    if (!r.ok) throw new Error(r.status);
    const text = await r.text();
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url; a.download = decodeURIComponent(fileEnc); document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  } catch (e) { $('logStatus').textContent = 'download failed'; }
}

// ── MCP auth management (on-demand) ──
function scrollToAuth() {
  const el = $('authPanel');
  if (!el) return;
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  el.style.outline = '2px solid var(--accent)';
  el.style.borderRadius = '8px';
  setTimeout(() => { el.style.outline = ''; }, 1500);
}
async function loadAuth() {
  try {
    const d = await fetch('/admin/auth', { headers: HEADERS }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); });
    const s = d.enabled ? ('auth: bearer (' + d.source + ')') : ('auth: disabled (' + d.source + ')');
    const el = $('authStatus');
    el.textContent = s;
    el.style.color = d.enabled ? '' : 'var(--danger)';
    $('authWarnIcon').style.display = d.enabled ? 'none' : '';
  } catch (e) { $('authStatus').textContent = 'status unavailable'; }
}
async function authAction(action, token) {
  try {
    const body = token != null ? { action, token } : { action };
    const d = await fetch('/admin/auth', {
      method: 'POST', headers: { ...HEADERS, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); });
    if (d.token) showToken(d.token);
    else $('authResult').innerHTML = '<div style="color:var(--text-muted);font-size:12.5px;margin:8px 0">Token cleared. Restart the server to apply.</div>';
    loadAuth();
  } catch (e) {
    $('authResult').innerHTML = '<div style="color:var(--danger);font-size:12.5px;margin:8px 0">Action failed (' + (e && e.message) + ').</div>';
  }
}
function authGenerate() { authAction('generate'); }
function authClear() {
  if (confirm('Clear the MCP auth token? /mcp will accept unauthenticated requests after the next restart.')) authAction('clear');
}
function authSetPrompt() {
  $('authResult').innerHTML =
    `<div style="display:flex;gap:8px;margin:8px 0"><input id="authInput" class="mini-select" style="flex:1" placeholder="paste custom token"><button class="srv-btn" onclick="authSet()">Save</button></div>`;
}
function authSet() {
  const t = ($('authInput').value || '').trim();
  if (t) authAction('set', t);
}
function showToken(token) {
  // Keep the raw token in a data attribute so Copy is idempotent (the visible
  // text gets a "✓ copied" suffix, but the clipboard always gets the real token).
  $('authResult').innerHTML =
    `<div class="token-box"><span class="tok" id="tokVal" data-tok="${escHtml(token)}">${escHtml(token)}</span><button class="srv-btn" onclick="copyToken()">Copy</button></div>`
    + `<div style="color:var(--amber);font-size:12px;margin-bottom:6px">Copy this token now — it won't be shown again. Restart the server to apply, then set your client's Authorization header.</div>`;
}
function copyToken() {
  const el = $('tokVal');
  const t = el.getAttribute('data-tok'); // always the original, not the displayed text
  if (navigator.clipboard) navigator.clipboard.writeText(t).then(() => { el.textContent = t + '  ✓ copied'; }, () => {});
}

// ── Init ──
poll();
loadReady(); // sets READ_ONLY, then loads the tool inventory
startEvents();
loadAnalytics(); // on-demand load (refreshed via the button, not the poll timer)
loadLogs();      // on-demand (Refresh button), loaded once at start
loadAuth();      // auth status
setRefreshInterval(POLL_MS); // starts both the poll and tool-inventory timers
