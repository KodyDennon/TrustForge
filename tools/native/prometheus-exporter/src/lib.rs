//! tf-prom-exporter library: polls a tf-daemon admin endpoint and exposes
//! the result as Prometheus metrics.
//!
//! The exporter is intentionally a *passive* observer of the daemon: it
//! scrapes `/admin/sessions`, `/admin/approvals`, `/admin/plugins`, and
//! `/admin/proofs` (read-only endpoints) and translates the responses into
//! Prometheus counters, gauges, and a histogram. It NEVER mutates daemon
//! state.
//!
//! Metrics:
//!
//! - `tf_decisions_total{decision, method, actor}`     counter
//! - `tf_decisions_latency_seconds{method}`            histogram
//! - `tf_approval_queue_depth`                          gauge
//! - `tf_revocations_active`                            gauge
//! - `tf_sessions_open`                                 gauge
//! - `tf_plugins_loaded{kind}`                          gauge
//! - `tf_proof_events_total{type}`                      counter

use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

/// Holds every Prometheus metric the exporter exposes plus the registry
/// they belong to.
pub struct Metrics {
    pub registry: Registry,
    pub decisions_total: IntCounterVec,
    pub decisions_latency: HistogramVec,
    pub approval_queue_depth: IntGauge,
    pub revocations_active: IntGauge,
    pub sessions_open: IntGauge,
    pub plugins_loaded: GaugeVec,
    pub proof_events_total: IntCounterVec,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let decisions_total = IntCounterVec::new(
            Opts::new(
                "tf_decisions_total",
                "Count of guard decisions, partitioned by decision kind, RPC method, and caller actor.",
            ),
            &["decision", "method", "actor"],
        )
        .expect("IntCounterVec::new tf_decisions_total");
        registry
            .register(Box::new(decisions_total.clone()))
            .expect("register tf_decisions_total");

        let decisions_latency = HistogramVec::new(
            HistogramOpts::new(
                "tf_decisions_latency_seconds",
                "Latency of guarded decisions, partitioned by RPC method.",
            )
            .buckets(vec![
                0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ]),
            &["method"],
        )
        .expect("HistogramVec::new tf_decisions_latency_seconds");
        registry
            .register(Box::new(decisions_latency.clone()))
            .expect("register tf_decisions_latency_seconds");

        let approval_queue_depth = IntGauge::with_opts(Opts::new(
            "tf_approval_queue_depth",
            "Number of approvals currently pending in the daemon's approval queue.",
        ))
        .expect("IntGauge tf_approval_queue_depth");
        registry
            .register(Box::new(approval_queue_depth.clone()))
            .expect("register tf_approval_queue_depth");

        let revocations_active = IntGauge::with_opts(Opts::new(
            "tf_revocations_active",
            "Number of revocations the daemon has on file.",
        ))
        .expect("IntGauge tf_revocations_active");
        registry
            .register(Box::new(revocations_active.clone()))
            .expect("register tf_revocations_active");

        let sessions_open = IntGauge::with_opts(Opts::new(
            "tf_sessions_open",
            "Number of currently open daemon sessions.",
        ))
        .expect("IntGauge tf_sessions_open");
        registry
            .register(Box::new(sessions_open.clone()))
            .expect("register tf_sessions_open");

        let plugins_loaded = GaugeVec::new(
            Opts::new(
                "tf_plugins_loaded",
                "Number of plugins currently loaded by the daemon, partitioned by plugin kind.",
            ),
            &["kind"],
        )
        .expect("GaugeVec::new tf_plugins_loaded");
        registry
            .register(Box::new(plugins_loaded.clone()))
            .expect("register tf_plugins_loaded");

        let proof_events_total = IntCounterVec::new(
            Opts::new(
                "tf_proof_events_total",
                "Cumulative count of proof events seen at scrape time, partitioned by type.",
            ),
            &["type"],
        )
        .expect("IntCounterVec::new tf_proof_events_total");
        registry
            .register(Box::new(proof_events_total.clone()))
            .expect("register tf_proof_events_total");

        Self {
            registry,
            decisions_total,
            decisions_latency,
            approval_queue_depth,
            revocations_active,
            sessions_open,
            plugins_loaded,
            proof_events_total,
        }
    }

    /// Encode the registry into a Prometheus text-format payload.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let mf = self.registry.gather();
        let mut buf = Vec::new();
        encoder
            .encode(&mf, &mut buf)
            .expect("prometheus text encoding never fails on owned buffer");
        String::from_utf8(buf).expect("prometheus encoder produces utf-8")
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Session {
    pub id: String,
    pub remote_actor: Option<String>,
    pub opened_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionsBody {
    pub sessions: Vec<Session>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Approval {
    pub id: String,
    pub action: Option<String>,
    pub actor: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalsBody {
    pub approvals: Vec<Approval>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Plugin {
    pub plugin_id: Option<String>,
    pub kind: Option<String>,
    pub actor_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginsBody {
    pub plugins: Vec<Plugin>,
}

/// Proof events have a flexible context shape — we only care about
/// `type`, `actor`, `context.action`, `context.decision`,
/// `context.duration_ms`.
#[derive(Debug, Clone, Deserialize)]
pub struct ProofEvent {
    #[serde(rename = "type")]
    pub kind: String,
    pub actor: Option<String>,
    #[serde(default)]
    pub context: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProofsBody {
    pub events: Vec<ProofEvent>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RevocationsBody {
    #[serde(default)]
    pub revocations: Vec<serde_json::Value>,
}

/// Configuration for one polling client — separated from the metrics so a
/// single registry can be shared across multiple test threads.
#[derive(Debug, Clone)]
pub struct ScrapeConfig {
    pub daemon_url: String,
    pub admin_token: Option<String>,
    pub timeout: Duration,
}

impl ScrapeConfig {
    pub fn new(daemon_url: impl Into<String>) -> Self {
        Self {
            daemon_url: daemon_url.into(),
            admin_token: std::env::var("TF_ADMIN_TOKEN").ok(),
            timeout: Duration::from_secs(5),
        }
    }
}

/// Scrape every admin endpoint once and update the supplied metrics.
///
/// Counters (`tf_decisions_total`, `tf_proof_events_total`) are derived
/// from the proof-event stream — every poll re-reads the last N events.
/// We only *increment* the counter for the delta of events the exporter
/// has not already seen; that bookkeeping is held in
/// [`ScrapeState::seen_proof_offset`] which is intentionally pluggable so
/// tests can drive the exporter through a sequence of synthetic windows.
#[derive(Debug, Default)]
pub struct ScrapeState {
    /// Highest offset (in the daemon's proof log) the exporter has
    /// already counted. The daemon's `/admin/proofs?n=` endpoint returns
    /// the *last* N events; we use a position-independent strategy: hash
    /// the canonicalized event text and skip any we've already seen.
    pub seen_event_keys: std::collections::HashSet<String>,
}

pub async fn scrape_once(
    cfg: &ScrapeConfig,
    metrics: &Metrics,
    state: &mut ScrapeState,
    client: &reqwest::Client,
) -> Result<(), ScrapeError> {
    // Build helper closure that adds the bearer token when set.
    async fn get_json<T: for<'de> Deserialize<'de>>(
        client: &reqwest::Client,
        url: &str,
        token: Option<&str>,
    ) -> Result<T, ScrapeError> {
        let mut req = client.get(url);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(ScrapeError::HttpStatus {
                url: url.to_string(),
                status: status.as_u16(),
            });
        }
        Ok(resp.json::<T>().await?)
    }

    let token = cfg.admin_token.as_deref();

    // Sessions.
    let sessions: SessionsBody =
        get_json(client, &format!("{}/admin/sessions", cfg.daemon_url), token).await?;
    metrics.sessions_open.set(sessions.sessions.len() as i64);

    // Approvals.
    let approvals: ApprovalsBody =
        get_json(client, &format!("{}/admin/approvals", cfg.daemon_url), token).await?;
    metrics
        .approval_queue_depth
        .set(approvals.approvals.len() as i64);

    // Plugins. Reset and re-tally to handle plugin unload.
    let plugins: PluginsBody =
        get_json(client, &format!("{}/admin/plugins", cfg.daemon_url), token).await?;
    metrics.plugins_loaded.reset();
    let mut by_kind: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for p in &plugins.plugins {
        let kind = p.kind.clone().unwrap_or_else(|| "unknown".to_string());
        *by_kind.entry(kind).or_default() += 1;
    }
    for (kind, n) in by_kind {
        metrics
            .plugins_loaded
            .with_label_values(&[&kind])
            .set(n as f64);
    }

    // Proof events. Pull the last 1000; only count what we haven't seen.
    let proofs: ProofsBody = get_json(
        client,
        &format!("{}/admin/proofs?n=1000", cfg.daemon_url),
        token,
    )
    .await?;
    for ev in &proofs.events {
        let key = event_dedup_key(ev);
        if !state.seen_event_keys.insert(key) {
            continue;
        }
        metrics
            .proof_events_total
            .with_label_values(&[&ev.kind])
            .inc();
        // guard.check carries the {decision, action} we want for
        // tf_decisions_total + tf_decisions_latency_seconds.
        if ev.kind == "guard.check" {
            let decision = ev
                .context
                .get("decision")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let action = ev
                .context
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let actor = ev.actor.clone().unwrap_or_else(|| "unknown".to_string());
            metrics
                .decisions_total
                .with_label_values(&[&decision, &action, &actor])
                .inc();
            if let Some(ms) = ev.context.get("duration_ms").and_then(|v| v.as_f64()) {
                metrics
                    .decisions_latency
                    .with_label_values(&[&action])
                    .observe(ms / 1000.0);
            }
        }
    }

    // Revocations: the daemon doesn't currently expose a count endpoint
    // directly — for now, count `admin.revocation` events seen in the
    // proof stream.
    let revs = proofs
        .events
        .iter()
        .filter(|e| e.kind == "admin.revocation")
        .count() as i64;
    metrics.revocations_active.set(revs);

    Ok(())
}

fn event_dedup_key(ev: &ProofEvent) -> String {
    // Use {type, actor, context} canonical-ish JSON for dedup.
    let mut out = String::new();
    out.push_str(&ev.kind);
    out.push('|');
    out.push_str(ev.actor.as_deref().unwrap_or(""));
    out.push('|');
    out.push_str(&ev.context.to_string());
    out
}

#[derive(Debug)]
pub enum ScrapeError {
    Http(reqwest::Error),
    HttpStatus { url: String, status: u16 },
}

impl From<reqwest::Error> for ScrapeError {
    fn from(e: reqwest::Error) -> Self {
        ScrapeError::Http(e)
    }
}

impl std::fmt::Display for ScrapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScrapeError::Http(e) => write!(f, "reqwest error: {}", e),
            ScrapeError::HttpStatus { url, status } => {
                write!(f, "non-success status from {}: {}", url, status)
            }
        }
    }
}
impl std::error::Error for ScrapeError {}

/// Lightweight HTTP server that serves `/metrics` from `metrics.render()`.
/// Used by `tf-prom-exporter` and the integration test.
pub async fn serve_metrics(
    bind: std::net::SocketAddr,
    metrics: Arc<Metrics>,
) -> std::io::Result<ServeHandle> {
    use hyper::body::Bytes;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(bind).await?;
    let local = listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accept = listener.accept() => {
                    let (stream, _peer) = match accept {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let metrics = metrics.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                            let metrics = metrics.clone();
                            async move {
                                let path = req.uri().path();
                                let (status, body) = if path == "/metrics" {
                                    (200u16, metrics.render())
                                } else if path == "/healthz" {
                                    (200u16, "ok\n".to_string())
                                } else {
                                    (404u16, "not found\n".to_string())
                                };
                                let resp = Response::builder()
                                    .status(status)
                                    .header(
                                        "content-type",
                                        "text/plain; version=0.0.4; charset=utf-8",
                                    )
                                    .body(http_body_util::Full::new(Bytes::from(body)))
                                    .expect("response builder never fails on owned bytes");
                                Ok::<_, std::convert::Infallible>(resp)
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, svc)
                            .await;
                    });
                }
            }
        }
    });

    Ok(ServeHandle {
        local,
        shutdown: Some(shutdown_tx),
        task: Some(task),
    })
}

pub struct ServeHandle {
    pub local: std::net::SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl ServeHandle {
    pub async fn stop(mut self) {
        if let Some(s) = self.shutdown.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
    }
}
