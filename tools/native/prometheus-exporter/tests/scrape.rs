//! Integration test: spin up a mock tf-daemon admin endpoint, drive
//! scrape_once + the /metrics renderer, and assert the right metric
//! names + labels appear.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tf_prom_exporter::{scrape_once, serve_metrics, Metrics, ScrapeConfig, ScrapeState};
use tokio::net::TcpListener;

async fn mock_daemon() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = listener.local_addr().unwrap();
    let (shutdown, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accept = listener.accept() => {
                    let (stream, _peer) = match accept {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(|req: Request<hyper::body::Incoming>| async move {
                            let path = req.uri().path();
                            let body = match path {
                                "/admin/sessions" => {
                                    r#"{"sessions":[{"id":"s1","remote_actor":"tf:actor:agent:example.com/a","opened_at":"2026-04-25T00:00:00Z"},{"id":"s2","remote_actor":"tf:actor:agent:example.com/b","opened_at":"2026-04-25T00:00:01Z"}]}"#
                                }
                                "/admin/approvals" => {
                                    r#"{"approvals":[{"id":"r1","actor":"tf:actor:agent:example.com/a","action":"fs.write"}]}"#
                                }
                                "/admin/plugins" => {
                                    r#"{"plugins":[{"plugin_id":"p1","actor_id":"a","kind":"bridge.webauthn"},{"plugin_id":"p2","actor_id":"b","kind":"bridge.webauthn"},{"plugin_id":"p3","actor_id":"c","kind":"bridge.spiffe"}]}"#
                                }
                                p if p.starts_with("/admin/proofs") => {
                                    r#"{"events":[
                                        {"type":"guard.check","actor":"tf:actor:agent:example.com/a","context":{"action":"fs.write","decision":"allow","duration_ms":12.5}},
                                        {"type":"guard.check","actor":"tf:actor:agent:example.com/b","context":{"action":"net.fetch","decision":"deny","duration_ms":2.1}},
                                        {"type":"guard.check","actor":"tf:actor:agent:example.com/a","context":{"action":"fs.write","decision":"allow","duration_ms":15.0}},
                                        {"type":"approval.request","actor":"tf:actor:agent:example.com/a","context":{"action":"fs.write","request_id":"r1"}},
                                        {"type":"admin.revocation","actor":"tf:actor:service:example.com/tf-daemon","context":{"target_id":"x"}}
                                    ]}"#
                                }
                                _ => return Ok::<_, Infallible>(
                                    Response::builder().status(404).body(Full::new(Bytes::from("not found"))).unwrap(),
                                ),
                            };
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
                            )
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, svc)
                            .await;
                    });
                }
            }
        }
    });

    (addr, shutdown)
}

#[tokio::test]
async fn scrape_populates_expected_metrics() {
    let (addr, shutdown) = mock_daemon().await;
    let cfg = ScrapeConfig::new(format!("http://{}", addr));
    let metrics = Metrics::new();
    let mut state = ScrapeState::default();
    let client = reqwest::Client::builder().build().unwrap();

    scrape_once(&cfg, &metrics, &mut state, &client)
        .await
        .expect("scrape ok");

    let text = metrics.render();

    // Names exposed.
    assert!(text.contains("tf_decisions_total"), "missing tf_decisions_total in:\n{text}");
    assert!(text.contains("tf_decisions_latency_seconds"), "missing tf_decisions_latency_seconds");
    assert!(text.contains("tf_approval_queue_depth"), "missing tf_approval_queue_depth");
    assert!(text.contains("tf_revocations_active"), "missing tf_revocations_active");
    assert!(text.contains("tf_sessions_open"), "missing tf_sessions_open");
    assert!(text.contains("tf_plugins_loaded"), "missing tf_plugins_loaded");
    assert!(text.contains("tf_proof_events_total"), "missing tf_proof_events_total");

    // Gauge values.
    assert!(text.contains("tf_sessions_open 2"), "expected sessions_open 2 in:\n{text}");
    assert!(text.contains("tf_approval_queue_depth 1"), "expected approval depth 1");
    assert!(text.contains("tf_revocations_active 1"), "expected revocations 1");

    // Label appearance.
    assert!(text.contains("decision=\"allow\""), "missing decision=allow label");
    assert!(text.contains("decision=\"deny\""), "missing decision=deny label");
    assert!(text.contains("method=\"fs.write\"") || text.contains("action=\"fs.write\""), "missing method label for fs.write");
    assert!(text.contains("kind=\"bridge.webauthn\""), "missing plugin kind label");
    assert!(text.contains("kind=\"bridge.spiffe\""), "missing spiffe plugin kind label");
    assert!(text.contains("type=\"guard.check\""), "missing proof event type label");

    let _ = shutdown.send(());
}

#[tokio::test]
async fn metrics_endpoint_serves_text_format() {
    let metrics = Arc::new(Metrics::new());
    metrics
        .decisions_total
        .with_label_values(&["allow", "tf.ping", "tf:actor:agent:example.com/x"])
        .inc();
    metrics.sessions_open.set(7);
    let serve = serve_metrics("127.0.0.1:0".parse().unwrap(), metrics.clone())
        .await
        .expect("bind");

    let url = format!("http://{}/metrics", serve.local);
    let body = reqwest::get(&url).await.unwrap().text().await.unwrap();
    assert!(body.contains("tf_sessions_open 7"));
    assert!(body.contains("tf_decisions_total"));

    serve.stop().await;
}

#[tokio::test]
async fn scrape_dedupes_proof_events_across_polls() {
    let (addr, shutdown) = mock_daemon().await;
    let cfg = ScrapeConfig::new(format!("http://{}", addr));
    let metrics = Metrics::new();
    let mut state = ScrapeState::default();
    let client = reqwest::Client::builder().build().unwrap();

    scrape_once(&cfg, &metrics, &mut state, &client).await.unwrap();
    let count_after_first = count_metric_lines(&metrics.render(), "tf_proof_events_total{");
    scrape_once(&cfg, &metrics, &mut state, &client).await.unwrap();
    let count_after_second = count_metric_lines(&metrics.render(), "tf_proof_events_total{");
    assert_eq!(
        count_after_first, count_after_second,
        "second scrape should not double-count identical events"
    );

    let _ = shutdown.send(());
}

fn count_metric_lines(text: &str, prefix: &str) -> Vec<(String, u64)> {
    text.lines()
        .filter(|l| l.starts_with(prefix))
        .map(|l| {
            let parts: Vec<&str> = l.rsplitn(2, ' ').collect();
            let value = parts[0].parse::<u64>().unwrap_or(0);
            let name = parts.get(1).copied().unwrap_or("").to_string();
            (name, value)
        })
        .collect()
}
