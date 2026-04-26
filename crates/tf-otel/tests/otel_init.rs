//! Integration tests for `tf-otel`.
//!
//! These tests exercise the full init -> emit -> shutdown loop using the
//! stdout exporter (no live OTLP collector required). The goal is to
//! catch:
//!
//! 1. Initialization with `None` endpoint never panics and never picks up
//!    ambient env vars in a flaky way.
//! 2. Spans emitted via `tracing` flow through the OTel layer when the
//!    handle's subscriber is installed.
//! 3. `shutdown()` is idempotent and safely flushes the providers.

use std::sync::Arc;
use std::time::Duration;

use tf_otel::{
    add_approval_queue_delta, init_otel, record_decide, record_proof_event, set_revocations_active,
    set_sessions_open, spans, TfOtelHandle,
};
use tracing::{info_span, Instrument};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Registry};

fn clear_endpoint_env() {
    // The test must not pick up the user's local collector. SAFETY: we
    // only mutate the test process environment.
    unsafe {
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn init_emit_shutdown_flush() {
    clear_endpoint_env();
    let handle = init_otel("tf-otel-it", None).expect("init_otel succeeded");
    assert_eq!(handle.service_name(), "tf-otel-it");
    assert!(handle.otlp_endpoint().is_none());

    // Direct OTel API: emit a decide span via the canonical name.
    use opentelemetry::trace::{Span, Tracer};
    let tracer = handle.tracer("tf-otel-it");
    let mut span = tracer.start(spans::DAEMON_DECIDE);
    span.set_attribute(opentelemetry::KeyValue::new("tf.action", "GET /test"));
    span.set_attribute(opentelemetry::KeyValue::new("tf.decision", "allow"));
    span.end();

    // Metrics: hit every instrument at least once.
    record_decide(
        handle.metrics(),
        "allow",
        "GET /v1/decide",
        "tf:actor:user:integration",
        Some("https://example.com/path"),
        0.0042,
    );
    record_decide(
        handle.metrics(),
        "deny",
        "POST /v1/decide",
        "tf:actor:agent:bad",
        None,
        0.0007,
    );
    record_proof_event(handle.metrics(), "guard.check");
    record_proof_event(handle.metrics(), "guard.check");
    record_proof_event(handle.metrics(), "admin.revocation");
    set_revocations_active(handle.metrics(), 5);
    set_sessions_open(handle.metrics(), 12);
    add_approval_queue_delta(handle.metrics(), 3);
    add_approval_queue_delta(handle.metrics(), -1);

    handle.flush();

    // Shutdown is idempotent.
    handle.shutdown();
    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tracing_bridge_emits_via_otel_layer() {
    clear_endpoint_env();
    let handle = init_otel("tf-otel-bridge", None).expect("init_otel succeeded");

    // Build a Registry-based subscriber with the OTel layer attached so
    // any `tracing::span!()` in scope flows into the tracer provider.
    let filter = EnvFilter::new("trace");
    let subscriber = Registry::default()
        .with(filter)
        .with(handle.tracing_layer());

    // `set_default` is per-thread so our test stays isolated; that's
    // sufficient because we only emit from this very task.
    let _guard = tracing::subscriber::set_default(subscriber);

    let parent = info_span!(
        "tf.daemon.decide",
        tf.action = "GET /",
        tf.decision = "allow"
    );
    async {
        // Child span exercising spans::PROOF_SIGN.
        let child = info_span!("tf.proof.sign", tf.actor_resolved = "tf:actor:user:t");
        async { tracing::info!("signing proof") }
            .instrument(child)
            .await;
    }
    .instrument(parent)
    .await;

    handle.flush();
    handle.shutdown();
}

/// `Drop` impl on the inner `Arc` should flush + shutdown without
/// panicking even when the user never called `shutdown()` explicitly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_path_flushes_silently() {
    clear_endpoint_env();
    {
        let handle: TfOtelHandle = init_otel("tf-otel-drop", None).expect("init_otel succeeded");
        record_proof_event(handle.metrics(), "guard.check");
        // No explicit shutdown. Letting `handle` drop here triggers the
        // Inner::drop best-effort flush.
    }
    // Give async exporters a moment to land output. Stdout is sync so
    // this is mostly belt-and-suspenders.
    tokio::time::sleep(Duration::from_millis(20)).await;
}

/// The handle is `Clone` and cheap; multiple clones can be parked in
/// long-lived state and `Arc`-shared without leaking exporters.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handle_clone_does_not_double_shutdown() {
    clear_endpoint_env();
    let handle = init_otel("tf-otel-clone", None).expect("init_otel succeeded");
    let h2 = handle.clone();
    let h3 = Arc::new(handle.clone());

    record_proof_event(handle.metrics(), "guard.check");
    record_proof_event(h2.metrics(), "guard.check");
    record_proof_event(h3.metrics(), "guard.check");

    // First shutdown is real.
    handle.shutdown();
    // Second shutdown via the clone is a no-op (exercise the
    // shutdown_done guard).
    h2.shutdown();
    drop(h3);
    drop(h2);
    drop(handle);
}
