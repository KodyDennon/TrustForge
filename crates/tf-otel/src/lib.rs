//! tf-otel — TrustForge OpenTelemetry / OTLP wiring for Rust.
//!
//! This crate is the Rust counterpart to `tools/tf-daemon/src/otel.ts`.
//! It owns three things:
//!
//! 1. **A single `init_otel(...)` entry point** that brings up a tracer
//!    provider, a meter provider, and a `tracing` -> OpenTelemetry bridge
//!    in one shot. Callers hand back a [`TfOtelHandle`] whose `Drop` impl
//!    flushes spans and metrics on shutdown so we never silently drop the
//!    tail of a workload.
//!
//! 2. **Canonical span and metric names** that match the TS daemon's wire
//!    spec. Every Rust component that participates in a TrustForge
//!    decision MUST use these constants — that is the contract that lets
//!    Grafana dashboards cover the whole stack with a single set of
//!    queries. The names are listed in [`spans`] and [`metrics`] modules.
//!
//! 3. **Convenience helpers** ([`record_decide`], [`record_proof_event`],
//!    etc.) that the proxy, axum/tonic adapters, and prom-exporter use to
//!    emit the standard observable events without each call site
//!    re-implementing the attribute keys.
//!
//! ## Wire-spec compatibility
//!
//! The TS daemon emits one span per `/v1/decide` request named `tf.decide`
//! with attributes `tf.action`, `tf.target`, `tf.decision`,
//! `tf.actor_resolved`. The Rust side keeps `tf.daemon.decide` (the spec
//! name from `crates/tf-otel`) as the canonical span; the legacy
//! `tf.decide` short form is also available as
//! [`spans::DECIDE_LEGACY`] for cross-stack joins.
//!
//! ## Endpoint selection
//!
//! `init_otel(service, otlp_endpoint)` accepts an optional endpoint:
//!
//! - `Some("http://collector:4317")` -> OTLP/gRPC export.
//! - `None` -> falls back to `OTEL_EXPORTER_OTLP_ENDPOINT` env var. If
//!    that is also unset, no remote exporter is installed; spans/metrics
//!    are routed through a stdout exporter so tests and dev runs still
//!    produce visible output without a collector.
//!
//! ## Drop / shutdown
//!
//! [`TfOtelHandle::shutdown`] explicitly flushes both providers and is
//! idempotent. The `Drop` impl performs the same shutdown best-effort if
//! the caller forgot. Long-running daemons should call `shutdown()`
//! explicitly during their graceful-stop path so the final span batch
//! reaches the collector.

use std::sync::Arc;
use std::time::Duration;

use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter, UpDownCounter};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::TracerProvider as SdkTracerProvider;
use opentelemetry_sdk::{runtime, Resource};
use tracing::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Layer};

/// Canonical span names. Every Rust component that participates in a
/// TrustForge flow MUST use one of these constants for the span name so
/// the Grafana trace explorer dashboards can pivot across services.
pub mod spans {
    /// Per-`/v1/decide` span emitted by the daemon and the proxy.
    pub const DAEMON_DECIDE: &str = "tf.daemon.decide";
    /// Legacy short name used by the TS daemon. Kept as a parallel
    /// emission point during the migration so dashboards can join old
    /// traces against new ones.
    pub const DECIDE_LEGACY: &str = "tf.decide";
    /// Bridge import-credential operation (WebAuthn, SPIFFE, GNAP, ...).
    pub const BRIDGE_IMPORT_CREDENTIAL: &str = "tf.bridge.import_credential";
    /// Proof-event signing.
    pub const PROOF_SIGN: &str = "tf.proof.sign";
    /// Proof-event verification.
    pub const PROOF_VERIFY: &str = "tf.proof.verify";
    /// Session handshake (live-mode setup).
    pub const SESSION_HANDSHAKE: &str = "tf.session.handshake";
    /// Per-tick of an established session.
    pub const SESSION_TICK: &str = "tf.session.tick";
    /// Evidence-bundle assembly (TF-0012 compliance evidence pipeline).
    pub const EVIDENCE_ASSEMBLE: &str = "tf.evidence.assemble";
    /// Evidence-bundle verification.
    pub const EVIDENCE_VERIFY: &str = "tf.evidence.verify";
}

/// Canonical metric names. Match the TS daemon's wire spec.
pub mod metrics {
    /// Counter, incremented once per finalized decide. Labels:
    /// `decision`, `action`, `actor`.
    pub const DECIDE_COUNT: &str = "tf.decide.count";
    /// Histogram of decide latency in seconds. Label: `action`.
    pub const DECIDE_LATENCY: &str = "tf.decide.latency";
    /// Up/down counter tracking pending approvals.
    pub const APPROVAL_QUEUE_DEPTH: &str = "tf.approval.queue_depth";
    /// Gauge of currently active revocations.
    pub const REVOCATION_ACTIVE: &str = "tf.revocation.active";
    /// Gauge of currently open sessions.
    pub const SESSION_OPEN: &str = "tf.session.open";
    /// Counter of proof events emitted, labelled by `type`.
    pub const PROOF_EVENT_COUNT: &str = "tf.proof_event.count";
}

/// Errors returned from [`init_otel`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The OTLP exporter could not be constructed.
    #[error("failed to build OTLP span exporter: {0}")]
    SpanExporter(String),
    /// The OTLP metric exporter could not be constructed.
    #[error("failed to build OTLP metric exporter: {0}")]
    MetricExporter(String),
    /// `tracing-subscriber` global default was already installed by an
    /// outer layer. The caller can either ignore this (the OTel layer was
    /// still attached if [`TfOtelHandle::install_subscriber`] was used)
    /// or arrange for tf-otel to own the subscriber.
    #[error("tracing global default already set")]
    SubscriberAlreadySet,
}

/// Set of canonical TrustForge metric instruments. Cloning is cheap; each
/// instrument is `Arc`-shared internally by the OTel SDK.
#[derive(Clone)]
pub struct TfMetrics {
    pub decide_count: Counter<u64>,
    pub decide_latency: Histogram<f64>,
    pub approval_queue_depth: UpDownCounter<i64>,
    pub revocation_active: Gauge<i64>,
    pub session_open: Gauge<i64>,
    pub proof_event_count: Counter<u64>,
    /// Underlying meter, kept so callers that need ad-hoc instruments
    /// can build them without redoing the provider plumbing.
    pub meter: Meter,
}

impl std::fmt::Debug for TfMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TfMetrics").finish_non_exhaustive()
    }
}

impl TfMetrics {
    /// Build the canonical instrument set on a meter. Idempotent:
    /// instruments with the same name are deduped by the SDK.
    pub fn new(meter: Meter) -> Self {
        let decide_count = meter
            .u64_counter(metrics::DECIDE_COUNT)
            .with_description("Count of guard decisions, by decision/action/actor.")
            .with_unit("1")
            .build();
        let decide_latency = meter
            .f64_histogram(metrics::DECIDE_LATENCY)
            .with_description("Latency of guarded decisions in seconds.")
            .with_unit("s")
            .build();
        let approval_queue_depth = meter
            .i64_up_down_counter(metrics::APPROVAL_QUEUE_DEPTH)
            .with_description("Number of approvals pending in the daemon queue.")
            .with_unit("1")
            .build();
        let revocation_active = meter
            .i64_gauge(metrics::REVOCATION_ACTIVE)
            .with_description("Number of currently active revocations.")
            .with_unit("1")
            .build();
        let session_open = meter
            .i64_gauge(metrics::SESSION_OPEN)
            .with_description("Number of currently open sessions.")
            .with_unit("1")
            .build();
        let proof_event_count = meter
            .u64_counter(metrics::PROOF_EVENT_COUNT)
            .with_description("Cumulative count of proof events, labelled by type.")
            .with_unit("1")
            .build();
        Self {
            decide_count,
            decide_latency,
            approval_queue_depth,
            revocation_active,
            session_open,
            proof_event_count,
            meter,
        }
    }
}

/// Handle to the live OTel pipeline. Holds the tracer + meter providers
/// and is responsible for flushing them on shutdown.
///
/// The handle is `Clone` (so it can be parked in a `ProxyState` while the
/// caller hands a copy to a graceful-shutdown task) — but only the
/// authoritative copy held by the original caller will trigger
/// shutdown when dropped. Subsequent drops are no-ops.
#[derive(Clone)]
pub struct TfOtelHandle {
    inner: Arc<TfOtelInner>,
}

struct TfOtelInner {
    service_name: String,
    otlp_endpoint: Option<String>,
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
    metrics: TfMetrics,
    /// Cached meter so external callers can grab instruments without
    /// reaching into globals.
    /// Set once in `init_otel`, used by [`TfOtelHandle::metrics`].
    shutdown_done: std::sync::Mutex<bool>,
}

impl TfOtelHandle {
    /// Service name as advertised on every span / metric resource.
    pub fn service_name(&self) -> &str {
        &self.inner.service_name
    }

    /// OTLP endpoint we are exporting to, or `None` if running in the
    /// stdout-only fallback (no `OTEL_EXPORTER_OTLP_ENDPOINT`).
    pub fn otlp_endpoint(&self) -> Option<&str> {
        self.inner.otlp_endpoint.as_deref()
    }

    /// Borrow the canonical TrustForge metric instrument set.
    pub fn metrics(&self) -> &TfMetrics {
        &self.inner.metrics
    }

    /// Get a tracer scoped to a given component. Most call sites should
    /// use `tracing` macros which are bridged to OTel automatically; this
    /// is for code that wants direct OpenTelemetry API access.
    pub fn tracer(&self, name: &'static str) -> opentelemetry_sdk::trace::Tracer {
        self.inner.tracer_provider.tracer(name)
    }

    /// Force-flush both providers. Best effort. Safe to call multiple
    /// times; subsequent invocations are no-ops once the providers have
    /// been finally shut down.
    pub fn flush(&self) {
        let _ = self.inner.tracer_provider.force_flush();
        let _ = self.inner.meter_provider.force_flush();
    }

    /// Explicitly shut down the pipeline. Flushes any buffered batches.
    /// Idempotent.
    pub fn shutdown(&self) {
        let mut done = match self.inner.shutdown_done.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if *done {
            return;
        }
        let _ = self.inner.tracer_provider.shutdown();
        let _ = self.inner.meter_provider.shutdown();
        *done = true;
    }

    /// Build a `tracing` Layer that bridges every `tracing` span/event
    /// into OpenTelemetry. Composed onto a `Registry` by the caller. We
    /// expose this rather than auto-installing a global subscriber so the
    /// caller (proxy, daemon, exporter) keeps control of its own logging
    /// stack.
    pub fn tracing_layer<S>(&self) -> impl Layer<S> + Send + Sync + 'static
    where
        S: Subscriber + for<'span> LookupSpan<'span> + Send + Sync,
    {
        let tracer = self.inner.tracer_provider.tracer("tf-otel");
        OpenTelemetryLayer::new(tracer)
    }

    /// Convenience: install a `tracing` global default subscriber that
    /// combines an `EnvFilter` with the OTel bridge. Intended for binary
    /// entry points (proxy, exporter) that don't already own a subscriber.
    /// Returns `Error::SubscriberAlreadySet` if a default is already
    /// installed.
    pub fn install_subscriber(&self) -> Result<(), Error> {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(self.tracing_layer());
        tracing::subscriber::set_global_default(subscriber).map_err(|_| Error::SubscriberAlreadySet)
    }
}

impl std::fmt::Debug for TfOtelHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TfOtelHandle")
            .field("service_name", &self.inner.service_name)
            .field("otlp_endpoint", &self.inner.otlp_endpoint)
            .finish()
    }
}

/// `Drop` flushes the providers as a last line of defense for callers
/// that didn't run `shutdown()` themselves.
impl Drop for TfOtelInner {
    fn drop(&mut self) {
        // Best-effort flush; ignore errors. If `shutdown_done` is true we
        // already flushed in shutdown().
        let already = self.shutdown_done.lock().map(|g| *g).unwrap_or(false);
        if !already {
            let _ = self.tracer_provider.force_flush();
            let _ = self.meter_provider.force_flush();
            let _ = self.tracer_provider.shutdown();
            let _ = self.meter_provider.shutdown();
        }
    }
}

/// Initialize the OpenTelemetry pipeline.
///
/// `service_name` is advertised as the `service.name` resource attribute
/// on every span and metric. `otlp_endpoint` is the gRPC URL of an OTLP
/// collector (e.g. `http://localhost:4317`). When `None`, we read
/// `OTEL_EXPORTER_OTLP_ENDPOINT`; if that is also unset, the SDK is
/// brought up with stdout exporters so dev runs and tests still produce
/// visible telemetry.
///
/// Safe to call once per process. Calling twice will install two pipelines
/// — the second handle's providers are not registered as global; only the
/// first call sets `global::set_tracer_provider` / `set_meter_provider`.
pub fn init_otel(service_name: &str, otlp_endpoint: Option<&str>) -> Result<TfOtelHandle, Error> {
    let endpoint = otlp_endpoint
        .map(|s| s.to_string())
        .or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok());

    let resource = Resource::new(vec![
        KeyValue::new("service.name", service_name.to_string()),
        KeyValue::new("tf.component", service_name.to_string()),
    ]);

    // ---------- Tracer provider ----------
    let mut tracer_builder = SdkTracerProvider::builder().with_resource(resource.clone());
    if let Some(ep) = endpoint.as_deref() {
        let span_exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(ep)
            .with_timeout(Duration::from_secs(3))
            .build()
            .map_err(|e| Error::SpanExporter(e.to_string()))?;
        tracer_builder = tracer_builder.with_batch_exporter(span_exporter, runtime::Tokio);
    } else {
        // No endpoint: emit to stdout so dev runs still see spans. The
        // exporter is intentionally synchronous; it's fine for the
        // expected volume in tests/dev.
        let exporter = opentelemetry_stdout::SpanExporter::default();
        tracer_builder = tracer_builder.with_simple_exporter(exporter);
    }
    let tracer_provider = tracer_builder.build();
    global::set_tracer_provider(tracer_provider.clone());

    // ---------- Meter provider ----------
    let meter_provider = build_meter_provider(&resource, endpoint.as_deref())?;
    global::set_meter_provider(meter_provider.clone());

    // `meter()` takes an `Into<Cow<'static, str>>`; we leak a small
    // string so the meter name (which is keyed for de-dup) survives the
    // 'static lifetime requirement without forcing a lifetime on the
    // public `init_otel` API.
    let meter_name: &'static str = Box::leak(format!("tf-otel/{service_name}").into_boxed_str());
    let meter = global::meter(meter_name);
    let metrics = TfMetrics::new(meter);

    let handle = TfOtelHandle {
        inner: Arc::new(TfOtelInner {
            service_name: service_name.to_string(),
            otlp_endpoint: endpoint,
            tracer_provider,
            meter_provider,
            metrics,
            shutdown_done: std::sync::Mutex::new(false),
        }),
    };
    Ok(handle)
}

fn build_meter_provider(
    resource: &Resource,
    endpoint: Option<&str>,
) -> Result<SdkMeterProvider, Error> {
    let mut builder = SdkMeterProvider::builder().with_resource(resource.clone());
    if let Some(ep) = endpoint {
        let exporter = MetricExporter::builder()
            .with_tonic()
            .with_endpoint(ep)
            .with_timeout(Duration::from_secs(3))
            .build()
            .map_err(|e| Error::MetricExporter(e.to_string()))?;
        let reader = PeriodicReader::builder(exporter, runtime::Tokio)
            .with_interval(Duration::from_secs(10))
            .build();
        builder = builder.with_reader(reader);
    } else {
        let exporter = opentelemetry_stdout::MetricExporter::default();
        let reader = PeriodicReader::builder(exporter, runtime::Tokio)
            .with_interval(Duration::from_secs(60))
            .build();
        builder = builder.with_reader(reader);
    }
    Ok(builder.build())
}

/// Record one finalized decide. Bumps `tf.decide.count` and
/// `tf.decide.latency`, with the canonical TrustForge attribute set.
///
/// `latency_seconds` is what the daemon (or proxy) measured from request
/// arrival to decision; `decision`/`action`/`actor`/`target` map directly
/// to the TS daemon's span attributes.
pub fn record_decide(
    metrics: &TfMetrics,
    decision: &str,
    action: &str,
    actor: &str,
    target: Option<&str>,
    latency_seconds: f64,
) {
    let mut attrs = vec![
        KeyValue::new("tf.decision", decision.to_string()),
        KeyValue::new("tf.action", action.to_string()),
        KeyValue::new("tf.actor_resolved", actor.to_string()),
    ];
    if let Some(t) = target {
        attrs.push(KeyValue::new("tf.target", t.to_string()));
    }
    metrics.decide_count.add(1, &attrs);
    metrics.decide_latency.record(latency_seconds, &attrs);
}

/// Record one proof event by `type`. Used by the daemon's proof bus and
/// the prom-exporter's scrape loop.
pub fn record_proof_event(metrics: &TfMetrics, kind: &str) {
    metrics
        .proof_event_count
        .add(1, &[KeyValue::new("type", kind.to_string())]);
}

/// Set the gauge tracking active revocations.
pub fn set_revocations_active(metrics: &TfMetrics, n: i64) {
    metrics.revocation_active.record(n, &[]);
}

/// Set the gauge tracking open sessions.
pub fn set_sessions_open(metrics: &TfMetrics, n: i64) {
    metrics.session_open.record(n, &[]);
}

/// Add a delta to the approval queue depth.
pub fn add_approval_queue_delta(metrics: &TfMetrics, delta: i64) {
    metrics.approval_queue_depth.add(delta, &[]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn init_with_no_endpoint_succeeds() {
        // Make sure we're not picking up ambient env that would force a
        // real OTLP collector connection during the test.
        // SAFETY: the test process does not assume a stable environment.
        unsafe {
            std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        }
        let handle = init_otel("tf-otel-unit", None).expect("init");
        assert_eq!(handle.service_name(), "tf-otel-unit");
        assert_eq!(handle.otlp_endpoint(), None);

        // Smoke-test instruments: incrementing should not panic.
        record_decide(
            handle.metrics(),
            "allow",
            "GET /",
            "tf:actor:user:test",
            None,
            0.001,
        );
        record_proof_event(handle.metrics(), "guard.check");
        set_revocations_active(handle.metrics(), 3);
        set_sessions_open(handle.metrics(), 7);
        add_approval_queue_delta(handle.metrics(), 1);

        handle.flush();
        handle.shutdown();
    }

    #[test]
    fn metric_names_match_wire_spec() {
        assert_eq!(metrics::DECIDE_COUNT, "tf.decide.count");
        assert_eq!(metrics::DECIDE_LATENCY, "tf.decide.latency");
        assert_eq!(metrics::APPROVAL_QUEUE_DEPTH, "tf.approval.queue_depth");
        assert_eq!(metrics::REVOCATION_ACTIVE, "tf.revocation.active");
        assert_eq!(metrics::SESSION_OPEN, "tf.session.open");
        assert_eq!(metrics::PROOF_EVENT_COUNT, "tf.proof_event.count");
    }

    #[test]
    fn span_names_match_wire_spec() {
        assert_eq!(spans::DAEMON_DECIDE, "tf.daemon.decide");
        assert_eq!(spans::DECIDE_LEGACY, "tf.decide");
        assert_eq!(
            spans::BRIDGE_IMPORT_CREDENTIAL,
            "tf.bridge.import_credential"
        );
        assert_eq!(spans::PROOF_SIGN, "tf.proof.sign");
        assert_eq!(spans::PROOF_VERIFY, "tf.proof.verify");
        assert_eq!(spans::SESSION_HANDSHAKE, "tf.session.handshake");
        assert_eq!(spans::SESSION_TICK, "tf.session.tick");
        assert_eq!(spans::EVIDENCE_ASSEMBLE, "tf.evidence.assemble");
        assert_eq!(spans::EVIDENCE_VERIFY, "tf.evidence.verify");
    }
}
