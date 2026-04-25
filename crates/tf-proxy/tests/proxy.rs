//! Integration tests for tf-proxy.
//!
//! These tests spin up:
//!   * a mock tf-daemon that returns a configurable decision on `/v1/decide`
//!   * a mock upstream that records every request and replies 200
//!   * the tf-proxy itself, bound to an ephemeral port
//!
//! and then drive a `reqwest::Client` against the proxy.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use tf_proxy::{Mode, ProxyConfig, ProxyState, run};

// ---------- Mock daemon ----------

#[derive(Clone)]
struct DaemonHandle {
    addr: SocketAddr,
    state: Arc<DaemonState>,
}

struct DaemonState {
    body: Mutex<String>,
    status: Mutex<u16>,
    hits: AtomicUsize,
    last_request: Mutex<Option<serde_json::Value>>,
}

async fn start_mock_daemon(initial_body: &str) -> DaemonHandle {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(DaemonState {
        body: Mutex::new(initial_body.to_string()),
        status: Mutex::new(200),
        hits: AtomicUsize::new(0),
        last_request: Mutex::new(None),
    });
    let s = state.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let s = s.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let s = s.clone();
                    async move { handle_daemon(s, req).await }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    DaemonHandle { addr, state }
}

async fn handle_daemon(
    s: Arc<DaemonState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    s.hits.fetch_add(1, Ordering::Relaxed);
    let (parts, body) = req.into_parts();
    let bytes = body.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        *s.last_request.lock().await = Some(v);
    }
    if parts.uri.path() != "/v1/decide" {
        return Ok(Response::builder()
            .status(404)
            .body(Full::new(Bytes::from_static(b"not found")))
            .unwrap());
    }
    let body = s.body.lock().await.clone();
    let status = *s.status.lock().await;
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

// ---------- Mock upstream ----------

#[derive(Clone)]
struct UpstreamHandle {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

async fn start_mock_upstream() -> UpstreamHandle {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let h = h.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let h = h.clone();
                    async move {
                        h.fetch_add(1, Ordering::Relaxed);
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(200)
                                .header("x-upstream", "yes")
                                .body(Full::new(Bytes::from_static(b"hello from upstream")))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    UpstreamHandle { addr, hits }
}

// ---------- Proxy harness ----------

struct ProxyHarness {
    addr: SocketAddr,
    upstream: UpstreamHandle,
    daemon: DaemonHandle,
}

async fn start_proxy(daemon_body: &str, mode: Mode) -> ProxyHarness {
    let daemon = start_mock_daemon(daemon_body).await;
    let upstream = start_mock_upstream().await;

    // Bind to an ephemeral port first so we can hand the SocketAddr back.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let cfg = ProxyConfig {
        listen: addr,
        upstream: format!("http://{}", upstream.addr),
        daemon: format!("http://{}", daemon.addr),
        admin_token: None,
        profile: "tf-home-compatible".to_string(),
        mode,
        tls_cert: None,
        tls_key: None,
    };
    let state = ProxyState::new(cfg);
    tokio::spawn(async move {
        let _ = run(state).await;
    });

    // Wait for the proxy to bind. Try a quick TCP connect with a few retries.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    ProxyHarness {
        addr,
        upstream,
        daemon,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

// ---------- Tests ----------

#[tokio::test]
async fn allow_forwards_to_upstream() {
    let h = start_proxy(
        r#"{"decision":"allow","reason":"ok"}"#,
        Mode::Enforce,
    )
    .await;
    let url = format!("http://{}/api/users", h.addr);
    let resp = client().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("x-upstream").unwrap(), "yes");
    let body = resp.text().await.unwrap();
    assert_eq!(body, "hello from upstream");
    assert_eq!(h.upstream.hits.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn deny_in_enforce_returns_403() {
    let h = start_proxy(
        r#"{"decision":"deny","reason":"no-cap","proof_id":"proof-123"}"#,
        Mode::Enforce,
    )
    .await;
    let url = format!("http://{}/admin/delete", h.addr);
    let resp = client().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let www = resp
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(www.contains("TrustForge"), "header was: {www}");
    assert!(www.contains("no-cap"), "header was: {www}");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "deny");
    assert_eq!(body["reason"], "no-cap");
    assert_eq!(body["proof_id"], "proof-123");
    assert_eq!(h.upstream.hits.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn deny_in_observe_only_still_forwards() {
    // Capture log lines and assert that a proof-event style log was emitted.
    use std::sync::Mutex as SyncMutex;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct Buf(Arc<SyncMutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let buf = Buf::default();
    let _g = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_env_filter("warn,tf_proxy=warn")
            .finish(),
    );

    let h = start_proxy(
        r#"{"decision":"deny","reason":"no-cap","proof_id":"proof-obs"}"#,
        Mode::ObserveOnly,
    )
    .await;
    let url = format!("http://{}/api/widgets", h.addr);
    let resp = client().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(h.upstream.hits.load(Ordering::Relaxed), 1);

    // Allow log lines to flush.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let captured = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        captured.contains("observe-only"),
        "expected observe-only proof-event log, got: {captured}"
    );
    assert!(
        captured.contains("proof-obs") || captured.contains("no-cap"),
        "expected proof_id or reason in log, got: {captured}"
    );
}

#[tokio::test]
async fn approval_required_returns_202() {
    let h = start_proxy(
        r#"{"decision":"approval-required","approval_id":"appr-42"}"#,
        Mode::Enforce,
    )
    .await;
    let url = format!("http://{}/api/sensitive", h.addr);
    let resp = client().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 202);
    let location = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        location.ends_with("/v1/approval/appr-42"),
        "location was: {location}"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "pending");
    assert_eq!(body["approval_id"], "appr-42");
    assert_eq!(h.upstream.hits.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn websocket_upgrade_allow_pipes_bytes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Set up a real upstream that speaks the websocket handshake and echoes
    // a single payload. We can't reuse the mock_upstream HTTP-only server
    // because it doesn't switch protocols, so spin up a dedicated raw
    // listener on a fresh port.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = upstream_listener.accept().await {
            // Read until end of headers.
            let mut buf = [0u8; 4096];
            let mut total = Vec::new();
            loop {
                let n = match s.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                total.extend_from_slice(&buf[..n]);
                if total.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // Send a 101 upgrade response.
            let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n";
            let _ = s.write_all(resp).await;
            // Now echo whatever the client sends.
            loop {
                let n = match s.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                if s.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        }
    });

    let daemon = start_mock_daemon(r#"{"decision":"allow"}"#).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);
    let cfg = ProxyConfig {
        listen: proxy_addr,
        upstream: format!("http://{upstream_addr}"),
        daemon: format!("http://{}", daemon.addr),
        admin_token: None,
        profile: "test".to_string(),
        mode: Mode::Enforce,
        tls_cert: None,
        tls_key: None,
    };
    let state = ProxyState::new(cfg);
    tokio::spawn(async move {
        let _ = run(state).await;
    });
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(proxy_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Pretend to be a websocket client: send a GET with Upgrade: websocket.
    let mut s = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let req = b"GET /chat HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    s.write_all(req).await.unwrap();

    // Read 101 from upstream (proxied).
    let mut buf = [0u8; 1024];
    let n = s.read(&mut buf).await.unwrap();
    let head = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected 101 Switching Protocols, got: {head}"
    );

    // Now send a payload and expect it echoed.
    s.write_all(b"PING").await.unwrap();
    let mut acc = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let mut tmp = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(200), s.read(&mut tmp)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                acc.extend_from_slice(&tmp[..n]);
                if acc.windows(4).any(|w| w == b"PING") {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }
    let s = String::from_utf8_lossy(&acc).to_string();
    assert!(s.contains("PING"), "expected echoed PING in: {s:?}");
}

#[tokio::test]
async fn malformed_daemon_response_returns_502() {
    let h = start_proxy("not-json-at-all", Mode::Enforce).await;
    let url = format!("http://{}/whatever", h.addr);
    let resp = client().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 502);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "daemon-error");
    assert_eq!(h.upstream.hits.load(Ordering::Relaxed), 0);
    // Daemon was contacted at least once.
    assert!(h.daemon.state.hits.load(Ordering::Relaxed) >= 1);
}
