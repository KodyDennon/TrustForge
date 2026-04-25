/**
 * tf-dashboard — viewer + minimal-control HTTP UI for an active tf-daemon.
 *
 * Uses the daemon's `/admin/*` endpoints. As of Phase Q1 the dashboard is
 * mostly read-only but exposes two narrowly-scoped control flows:
 *   1. Live proof-event stream over a browser↔dashboard WebSocket (the
 *      dashboard server polls the daemon and pushes deltas to the
 *      connected browsers).
 *   2. Approval queue UI: list pending approvals, click to approve/deny.
 *      The dashboard proxies the approve/deny POST to the daemon, which
 *      is the source of truth for the audit trail.
 *
 * Everything heavier (revocation, plugin install, contract reload) is
 * still left to the `tf` CLI.
 */

export interface DashboardOptions {
  /** Base URL of the running daemon's admin endpoint, e.g. http://127.0.0.1:8787 */
  daemonUrl: string;
  /** Bearer token. Reads from process.env.TF_ADMIN_TOKEN if omitted. */
  adminToken?: string;
  /** Local port for the dashboard. 0 lets the OS pick. Default 0. */
  port?: number;
  /** Local bind. Default 127.0.0.1. */
  host?: string;
  /** Refresh interval for the in-page poller, in ms. Default 2000. */
  refreshMs?: number;
  /** Server-side polling interval for the live proof stream, in ms.
   *  Default 1000. */
  streamPollMs?: number;
}

export interface DashboardHandle {
  port: number;
  url: string;
  stop: () => void;
}

interface AdminFetchOk<T> {
  ok: true;
  data: T;
}
interface AdminFetchErr {
  ok: false;
  status: number;
  detail: string;
}
type AdminFetchResult<T> = AdminFetchOk<T> | AdminFetchErr;

async function adminFetch<T>(
  opts: DashboardOptions,
  path: string,
  init?: { method?: string; body?: string },
): Promise<AdminFetchResult<T>> {
  const token = opts.adminToken ?? process.env.TF_ADMIN_TOKEN ?? "";
  const headers: Record<string, string> = {};
  if (token) headers["authorization"] = `Bearer ${token}`;
  if (init?.body !== undefined) headers["content-type"] = "application/json";
  try {
    const res = await fetch(`${opts.daemonUrl}${path}`, {
      method: init?.method ?? "GET",
      headers,
      body: init?.body,
    });
    if (!res.ok) {
      return { ok: false, status: res.status, detail: await res.text() };
    }
    return { ok: true, data: (await res.json()) as T };
  } catch (err) {
    return { ok: false, status: 0, detail: (err as Error).message };
  }
}

/** Stable hash for a proof event used to detect "new since last poll".
 *  Defensive: matches the dedup strategy the prom-exporter uses. */
function proofEventKey(ev: unknown): string {
  if (!ev || typeof ev !== "object") return JSON.stringify(ev);
  const e = ev as Record<string, unknown>;
  return [
    String(e.type ?? ""),
    String(e.actor ?? ""),
    String(e.timestamp ?? ""),
    JSON.stringify(e.context ?? {}),
  ].join("|");
}

const HTML_PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>tf-dashboard</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-sans-serif, system-ui, sans-serif; max-width: 1200px; margin: 1.5rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; margin: 0 0 0.5rem; }
  h2 { font-size: 1.05rem; margin: 1.4rem 0 0.4rem; }
  .row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  .panel { border: 1px solid color-mix(in oklab, currentColor 20%, transparent); border-radius: 6px; padding: 0.75rem; background: color-mix(in oklab, Canvas 90%, currentColor 5%); }
  .empty { color: color-mix(in oklab, currentColor 60%, transparent); font-style: italic; }
  .pill { display: inline-block; padding: 0.05rem 0.4rem; border-radius: 999px; font-size: 0.75rem; border: 1px solid color-mix(in oklab, currentColor 30%, transparent); margin-left: 0.4rem; }
  .pill.ok { background: color-mix(in oklab, green 20%, transparent); }
  .pill.warn { background: color-mix(in oklab, orange 20%, transparent); }
  .pill.bad { background: color-mix(in oklab, red 20%, transparent); }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.25rem 0.4rem; border-bottom: 1px solid color-mix(in oklab, currentColor 15%, transparent); }
  pre { font-size: 0.75rem; max-height: 300px; overflow: auto; margin: 0; }
  .mono { font-family: ui-monospace, Menlo, monospace; font-size: 0.8rem; }
  header { display: flex; align-items: baseline; gap: 1rem; flex-wrap: wrap; }
  header small { color: color-mix(in oklab, currentColor 60%, transparent); }
  button { font: inherit; padding: 0.15rem 0.5rem; border-radius: 4px; cursor: pointer; }
  button.approve { background: color-mix(in oklab, green 30%, transparent); border: 1px solid color-mix(in oklab, green 50%, transparent); }
  button.deny { background: color-mix(in oklab, red 30%, transparent); border: 1px solid color-mix(in oklab, red 50%, transparent); }
  .stream-row { font-family: ui-monospace, Menlo, monospace; font-size: 0.75rem; padding: 0.15rem 0; border-bottom: 1px solid color-mix(in oklab, currentColor 10%, transparent); }
  .stream-row.allow { color: color-mix(in oklab, green 80%, currentColor); }
  .stream-row.deny { color: color-mix(in oklab, red 80%, currentColor); }
  .stream-row.escalate { color: color-mix(in oklab, orange 80%, currentColor); }
  #liveStream { max-height: 320px; overflow: auto; }
  canvas { max-width: 100%; }
</style>
</head>
<body>
<header>
  <h1>TrustForge dashboard</h1>
  <small id="lastRefresh">never</small>
  <small id="connState">connecting&hellip;</small>
  <small id="streamState">stream: idle</small>
</header>

<div class="panel" id="profilePanel"><span class="empty">loading profile&hellip;</span></div>

<div class="row">
  <section class="panel">
    <h2>Active sessions</h2>
    <div id="sessions"><span class="empty">loading&hellip;</span></div>
  </section>

  <section class="panel">
    <h2>Pending approvals</h2>
    <div id="approvals"><span class="empty">loading&hellip;</span></div>
  </section>
</div>

<div class="row">
  <section class="panel">
    <h2>Decisions per route</h2>
    <canvas id="chartByRoute" height="180"></canvas>
  </section>

  <section class="panel">
    <h2>Decisions per actor</h2>
    <canvas id="chartByActor" height="180"></canvas>
  </section>
</div>

<div class="row">
  <section class="panel">
    <h2>Loaded plugins</h2>
    <div id="plugins"><span class="empty">loading&hellip;</span></div>
  </section>

  <section class="panel">
    <h2>Live proof events</h2>
    <div id="liveStream"><span class="empty">connecting&hellip;</span></div>
  </section>
</div>

<section class="panel">
  <h2>Recent proof events (snapshot)</h2>
  <div id="proofs"><span class="empty">loading&hellip;</span></div>
</section>

<!-- Chart.js: pinned to the maintained 4.x line. Loaded from a
     deterministic CDN so the dashboard works without a build step. -->
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"
        integrity="sha256-Y4GtIgK5HdFNHWMmJFBiYXovJaq6Whc28GdoMnRBEHE="
        crossorigin="anonymous"></script>

<script>
const REFRESH_MS = window.__TF_DASH__?.refreshMs ?? 2000;
const MAX_STREAM_ROWS = 200;

// In-memory tally of guard.check decisions for the histograms. Keyed by
// {route} → {decision → count} and {actor} → {decision → count}. We
// don't persist; the panel is a "since you opened this tab" view.
const decisionTallyByRoute = new Map();
const decisionTallyByActor = new Map();
let chartByRoute, chartByActor;

function adminGet(path) {
  return fetch('/api' + path).then(async (r) => {
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  });
}

function adminPost(path, body) {
  return fetch('/api' + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  }).then(async (r) => {
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  });
}

function renderSessions(s) {
  if (!s.sessions || s.sessions.length === 0) return '<span class="empty">no sessions</span>';
  let html = '<table><tr><th>id</th><th>actor</th><th>opened</th></tr>';
  for (const row of s.sessions) {
    html += '<tr>'
      + '<td class="mono">' + escapeHtml(row.id) + '</td>'
      + '<td class="mono">' + escapeHtml(row.remote_actor) + '</td>'
      + '<td>' + escapeHtml(row.opened_at) + '</td>'
      + '</tr>';
  }
  return html + '</table>';
}

function renderApprovals(s) {
  if (!s.approvals || s.approvals.length === 0) return '<span class="empty">no pending approvals</span>';
  let html = '<table><tr><th>id</th><th>actor</th><th>action</th><th>danger</th><th>action</th></tr>';
  for (const row of s.approvals) {
    const tags = (row.danger_tags || []).join(', ');
    const id = String(row.id);
    html += '<tr>'
      + '<td class="mono">' + escapeHtml(row.id) + '</td>'
      + '<td class="mono">' + escapeHtml(row.actor) + '</td>'
      + '<td class="mono">' + escapeHtml(row.action) + '</td>'
      + '<td>' + escapeHtml(tags) + '</td>'
      + '<td>'
      +   '<button class="approve" data-id="' + escapeAttr(id) + '" data-decision="approve">approve</button> '
      +   '<button class="deny" data-id="' + escapeAttr(id) + '" data-decision="deny">deny</button>'
      + '</td>'
      + '</tr>';
  }
  return html + '</table>';
}

function renderPlugins(s) {
  if (!s.plugins || s.plugins.length === 0) return '<span class="empty">no plugins loaded</span>';
  let html = '<table><tr><th>plugin_id</th><th>kind</th><th>actor</th><th>capabilities</th></tr>';
  for (const row of s.plugins) {
    html += '<tr>'
      + '<td class="mono">' + escapeHtml(row.plugin_id) + '</td>'
      + '<td>' + escapeHtml(row.kind) + '</td>'
      + '<td class="mono">' + escapeHtml(row.actor_id) + '</td>'
      + '<td class="mono">' + escapeHtml((row.capabilities || []).join(', ')) + '</td>'
      + '</tr>';
  }
  return html + '</table>';
}

function renderProofs(s) {
  if (!s.events || s.events.length === 0) return '<span class="empty">no events</span>';
  return '<pre>' + s.events.slice(-50).reverse().map((e) => escapeHtml(JSON.stringify(e))).join('\\n') + '</pre>';
}

function renderProfile(s) {
  if (!s.profile) {
    return '<span class="empty">no profile claimed by daemon</span>';
  }
  const v = s.profile;
  const cls = v.ok ? 'ok' : 'bad';
  const pill = '<span class="pill ' + cls + '">' + (v.ok ? 'satisfied' : 'failing') + '</span>';
  let html = '<strong>' + escapeHtml(v.profile) + '</strong>' + pill;
  if (v.failures && v.failures.length) {
    html += '<ul>';
    for (const f of v.failures) html += '<li class="mono">' + escapeHtml(f) + '</li>';
    html += '</ul>';
  }
  if (v.warnings && v.warnings.length) {
    html += '<ul>';
    for (const w of v.warnings) html += '<li class="mono">' + escapeHtml(w) + ' <span class="pill warn">SHOULD</span></li>';
    html += '</ul>';
  }
  return html;
}

function escapeHtml(x) {
  return String(x).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function escapeAttr(x) { return escapeHtml(x); }

// ---------------------------------------------------------------------------
// Approve/deny click handler — delegated from the body so we don't have
// to rewire after every refresh.
// ---------------------------------------------------------------------------
document.body.addEventListener('click', async (ev) => {
  const t = ev.target;
  if (!(t instanceof HTMLButtonElement)) return;
  const id = t.dataset.id;
  const decision = t.dataset.decision;
  if (!id || (decision !== 'approve' && decision !== 'deny')) return;
  t.disabled = true;
  try {
    await adminPost('/admin/approvals/' + encodeURIComponent(id) + '/' + decision, {});
    refresh().catch(() => {});
  } catch (err) {
    alert('approval failed: ' + err.message);
    t.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// Live proof-event stream — opens a WebSocket back to the dashboard server.
// ---------------------------------------------------------------------------
function bumpDecisionTally(ev) {
  if (!ev || ev.type !== 'guard.check') return;
  const ctx = ev.context || {};
  const route = ctx.action || 'unknown';
  const actor = ev.actor || 'unknown';
  const decision = ctx.decision || 'unknown';
  function bump(map, key) {
    if (!map.has(key)) map.set(key, {});
    const inner = map.get(key);
    inner[decision] = (inner[decision] || 0) + 1;
  }
  bump(decisionTallyByRoute, route);
  bump(decisionTallyByActor, actor);
}

function ensureCharts() {
  if (chartByRoute || typeof Chart === 'undefined') return;
  const cfg = (label) => ({
    type: 'bar',
    data: { labels: [], datasets: [
      { label: 'allow', data: [], backgroundColor: 'rgba(60,180,75,0.6)' },
      { label: 'deny', data: [], backgroundColor: 'rgba(230,25,75,0.6)' },
      { label: 'escalate', data: [], backgroundColor: 'rgba(255,153,0,0.6)' },
      { label: 'approval-required', data: [], backgroundColor: 'rgba(70,130,200,0.6)' },
      { label: 'log-only', data: [], backgroundColor: 'rgba(180,180,180,0.6)' },
    ]},
    options: {
      responsive: true,
      plugins: { title: { display: true, text: label } },
      scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } },
    },
  });
  chartByRoute = new Chart(document.getElementById('chartByRoute'), cfg('decisions per route'));
  chartByActor = new Chart(document.getElementById('chartByActor'), cfg('decisions per actor'));
}

function refreshCharts() {
  if (!chartByRoute) return;
  function fill(chart, map) {
    const labels = [...map.keys()];
    chart.data.labels = labels;
    const decisions = ['allow','deny','escalate','approval-required','log-only'];
    chart.data.datasets.forEach((ds, i) => {
      ds.data = labels.map((l) => (map.get(l) || {})[decisions[i]] || 0);
    });
    chart.update('none');
  }
  fill(chartByRoute, decisionTallyByRoute);
  fill(chartByActor, decisionTallyByActor);
}

function appendStreamRow(ev) {
  const el = document.getElementById('liveStream');
  if (el.querySelector('.empty')) el.innerHTML = '';
  const div = document.createElement('div');
  let cls = 'stream-row';
  const decision = ev?.context?.decision;
  if (decision === 'allow') cls += ' allow';
  else if (decision === 'deny') cls += ' deny';
  else if (decision === 'escalate' || decision === 'approval-required') cls += ' escalate';
  div.className = cls;
  const summary = (ev?.timestamp || '') + '  ' + (ev?.type || '') + '  ' + (ev?.actor || '');
  div.textContent = summary + '  ' + JSON.stringify(ev?.context ?? {});
  el.prepend(div);
  while (el.childElementCount > MAX_STREAM_ROWS) el.removeChild(el.lastChild);
}

function startStream() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = proto + '//' + location.host + '/ws/proofs';
  let ws;
  try {
    ws = new WebSocket(url);
  } catch (err) {
    document.getElementById('streamState').textContent = 'stream: unavailable (' + err.message + ')';
    return;
  }
  ws.onopen = () => {
    document.getElementById('streamState').innerHTML = 'stream: <span class="pill ok">live</span>';
  };
  ws.onclose = () => {
    document.getElementById('streamState').innerHTML = 'stream: <span class="pill bad">closed</span>';
    setTimeout(startStream, 3000);
  };
  ws.onerror = () => {
    document.getElementById('streamState').innerHTML = 'stream: <span class="pill bad">error</span>';
  };
  ws.onmessage = (msg) => {
    let parsed;
    try { parsed = JSON.parse(msg.data); } catch { return; }
    if (parsed && parsed.type === 'event' && parsed.event) {
      bumpDecisionTally(parsed.event);
      appendStreamRow(parsed.event);
      refreshCharts();
    }
  };
}

async function refresh() {
  ensureCharts();
  try {
    const [sessions, approvals, plugins, proofs, profile] = await Promise.all([
      adminGet('/admin/sessions'),
      adminGet('/admin/approvals'),
      adminGet('/admin/plugins'),
      adminGet('/admin/proofs?n=200'),
      adminGet('/admin/profile'),
    ]);
    document.getElementById('sessions').innerHTML = renderSessions(sessions);
    document.getElementById('approvals').innerHTML = renderApprovals(approvals);
    document.getElementById('plugins').innerHTML = renderPlugins(plugins);
    document.getElementById('proofs').innerHTML = renderProofs(proofs);
    document.getElementById('profilePanel').innerHTML = renderProfile(profile);
    document.getElementById('lastRefresh').textContent = 'refreshed ' + new Date().toLocaleTimeString();
    document.getElementById('connState').innerHTML = '<span class="pill ok">connected</span>';
  } catch (err) {
    document.getElementById('connState').innerHTML = '<span class="pill bad">' + escapeHtml(err.message) + '</span>';
  } finally {
    setTimeout(refresh, REFRESH_MS);
  }
}

refresh();
startStream();
</script>
</body>
</html>
`;

export function startDashboard(opts: DashboardOptions): DashboardHandle {
  const port = opts.port ?? 0;
  const host = opts.host ?? "127.0.0.1";
  const refreshMs = opts.refreshMs ?? 2000;
  const streamPollMs = opts.streamPollMs ?? 1000;

  // ---------------------------------------------------------------------
  // Live proof-event stream state.
  // The dashboard server polls the daemon at `streamPollMs` cadence,
  // diffs against the keys it has already seen, and pushes new events
  // out to every connected browser WebSocket.
  // ---------------------------------------------------------------------
  const seenKeys = new Set<string>();
  const wsClients = new Set<{ send: (msg: string) => void; close: () => void }>();
  let streamTimer: ReturnType<typeof setTimeout> | null = null;
  let stopped = false;

  async function streamTick() {
    if (stopped) return;
    try {
      const r = await adminFetch<{ events: Array<Record<string, unknown>> }>(
        opts,
        "/admin/proofs?n=500",
      );
      if (r.ok && Array.isArray(r.data.events)) {
        for (const ev of r.data.events) {
          const key = proofEventKey(ev);
          if (seenKeys.has(key)) continue;
          seenKeys.add(key);
          // Cap memory: don't let `seenKeys` grow without bound.
          if (seenKeys.size > 5000) {
            const first = seenKeys.values().next().value;
            if (first !== undefined) seenKeys.delete(first);
          }
          const msg = JSON.stringify({ type: "event", event: ev });
          for (const c of wsClients) {
            try {
              c.send(msg);
            } catch {
              /* ignore individual send errors; the close handler will
                 prune the client slot. */
            }
          }
        }
      }
    } catch {
      /* tolerate transient daemon errors */
    } finally {
      if (!stopped) streamTimer = setTimeout(streamTick, streamPollMs);
    }
  }

  // Pre-seed seenKeys so the very first stream connection doesn't get
  // flooded with the entire historical proof log. We treat events that
  // already existed at startup as "seen". Pre-seed is best-effort.
  void (async () => {
    const r = await adminFetch<{ events: Array<Record<string, unknown>> }>(
      opts,
      "/admin/proofs?n=500",
    );
    if (r.ok && Array.isArray(r.data.events)) {
      for (const ev of r.data.events) seenKeys.add(proofEventKey(ev));
    }
    streamTick();
  })();

  const server = Bun.serve({
    port,
    hostname: host,
    async fetch(req, server) {
      const url = new URL(req.url);
      // Browser WebSocket upgrade for the live stream.
      if (url.pathname === "/ws/proofs") {
        if (server.upgrade(req, { data: {} as never })) return undefined;
        return new Response("expected websocket", { status: 400 });
      }
      if (url.pathname === "/" || url.pathname === "/index.html") {
        const page = HTML_PAGE.replace(
          "</head>",
          `<script>window.__TF_DASH__=${JSON.stringify({ refreshMs })}</script></head>`,
        );
        return new Response(page, { headers: { "content-type": "text/html; charset=utf-8" } });
      }
      if (url.pathname.startsWith("/api/admin/")) {
        const adminPath = url.pathname.slice("/api".length) + (url.search ?? "");
        const init =
          req.method === "POST"
            ? { method: "POST", body: await req.text() }
            : undefined;
        const r = await adminFetch<unknown>(opts, adminPath, init);
        if (r.ok) {
          return new Response(JSON.stringify(r.data), {
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(r.detail, { status: r.status || 502 });
      }
      return new Response("not found", { status: 404 });
    },
    websocket: {
      open(ws) {
        const client = {
          send: (msg: string) => ws.send(msg),
          close: () => ws.close(),
        };
        (ws.data as { client?: typeof client }).client = client;
        wsClients.add(client);
        ws.send(JSON.stringify({ type: "hello", refreshMs, streamPollMs }));
      },
      message(_ws, _msg) {
        // The browser never sends to us — ignore.
      },
      close(ws) {
        const c = (ws.data as { client?: { send: (m: string) => void; close: () => void } }).client;
        if (c) wsClients.delete(c);
      },
    },
  });

  const url = `http://${host}:${server.port ?? port}`;
  return {
    port: server.port ?? port,
    url,
    stop: () => {
      stopped = true;
      if (streamTimer) clearTimeout(streamTimer);
      for (const c of wsClients) {
        try {
          c.close();
        } catch {
          /* ignore */
        }
      }
      wsClients.clear();
      server.stop(true);
    },
  };
}
