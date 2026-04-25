/**
 * tf-dashboard — viewer-only HTTP UI for an active tf-daemon.
 *
 * Uses the daemon's `/admin/*` endpoints. The dashboard is read-only:
 * it lists active sessions, pending approvals, recent proof events,
 * loaded plugins, and the daemon's profile verdict. It does NOT mutate
 * daemon state — approvals/denials/revocations all go through the
 * `tf` CLI (or directly to the admin HTTP API) which require their own
 * audit trail.
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

async function adminFetch<T>(opts: DashboardOptions, path: string): Promise<AdminFetchResult<T>> {
  const token = opts.adminToken ?? process.env.TF_ADMIN_TOKEN ?? "";
  try {
    const res = await fetch(`${opts.daemonUrl}${path}`, {
      headers: token ? { authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      return { ok: false, status: res.status, detail: await res.text() };
    }
    return { ok: true, data: (await res.json()) as T };
  } catch (err) {
    return { ok: false, status: 0, detail: (err as Error).message };
  }
}

const HTML_PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>tf-dashboard</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-sans-serif, system-ui, sans-serif; max-width: 1100px; margin: 1.5rem auto; padding: 0 1rem; }
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
  header { display: flex; align-items: baseline; gap: 1rem; }
  header small { color: color-mix(in oklab, currentColor 60%, transparent); }
</style>
</head>
<body>
<header>
  <h1>TrustForge dashboard</h1>
  <small id="lastRefresh">never</small>
  <small id="connState">connecting…</small>
</header>

<div class="panel" id="profilePanel"><span class="empty">loading profile…</span></div>

<div class="row">
  <section class="panel">
    <h2>Active sessions</h2>
    <div id="sessions"><span class="empty">loading…</span></div>
  </section>

  <section class="panel">
    <h2>Pending approvals</h2>
    <div id="approvals"><span class="empty">loading…</span></div>
  </section>
</div>

<div class="row">
  <section class="panel">
    <h2>Loaded plugins</h2>
    <div id="plugins"><span class="empty">loading…</span></div>
  </section>

  <section class="panel">
    <h2>Recent proof events</h2>
    <div id="proofs"><span class="empty">loading…</span></div>
  </section>
</div>

<script>
const REFRESH_MS = window.__TF_DASH__?.refreshMs ?? 2000;

async function adminGet(path) {
  const r = await fetch('/api' + path);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
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
  let html = '<table><tr><th>id</th><th>actor</th><th>action</th><th>danger</th></tr>';
  for (const row of s.approvals) {
    const tags = (row.danger_tags || []).join(', ');
    html += '<tr>'
      + '<td class="mono">' + escapeHtml(row.id) + '</td>'
      + '<td class="mono">' + escapeHtml(row.actor) + '</td>'
      + '<td class="mono">' + escapeHtml(row.action) + '</td>'
      + '<td>' + escapeHtml(tags) + '</td>'
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
  return '<pre>' + s.events.slice(-50).reverse().map(e => escapeHtml(JSON.stringify(e))).join('\\n') + '</pre>';
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

async function refresh() {
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
</script>
</body>
</html>
`;

export function startDashboard(opts: DashboardOptions): DashboardHandle {
  const port = opts.port ?? 0;
  const host = opts.host ?? "127.0.0.1";
  const refreshMs = opts.refreshMs ?? 2000;

  const server = Bun.serve({
    port,
    hostname: host,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/" || url.pathname === "/index.html") {
        const page = HTML_PAGE.replace(
          "</head>",
          `<script>window.__TF_DASH__=${JSON.stringify({ refreshMs })}</script></head>`,
        );
        return new Response(page, { headers: { "content-type": "text/html; charset=utf-8" } });
      }
      if (url.pathname.startsWith("/api/admin/")) {
        const adminPath = url.pathname.slice("/api".length) + (url.search ?? "");
        const r = await adminFetch<unknown>(opts, adminPath);
        if (r.ok) {
          return new Response(JSON.stringify(r.data), { headers: { "content-type": "application/json" } });
        }
        return new Response(r.detail, { status: r.status || 502 });
      }
      return new Response("not found", { status: 404 });
    },
  });

  const url = `http://${host}:${server.port ?? port}`;
  return {
    port: server.port ?? port,
    url,
    stop: () => server.stop(true),
  };
}
