//! Smoke tests for `tf-decide-client` against an in-process mock daemon.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use tf_decide_client::{DecideRequest, TfDecideClient, is_allow, is_deny};

struct DaemonState {
    body: Mutex<String>,
    status: Mutex<u16>,
    hits: AtomicUsize,
    last: Mutex<Option<serde_json::Value>>,
    last_auth: Mutex<Option<String>>,
}

async fn start_mock_daemon(initial_body: &str) -> (SocketAddr, Arc<DaemonState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(DaemonState {
        body: Mutex::new(initial_body.to_string()),
        status: Mutex::new(200),
        hits: AtomicUsize::new(0),
        last: Mutex::new(None),
        last_auth: Mutex::new(None),
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
                    async move {
                        s.hits.fetch_add(1, Ordering::Relaxed);
                        let auth = req
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(|x| x.to_string());
                        *s.last_auth.lock().await = auth;
                        let (_p, body) = req.into_parts();
                        let bytes = body.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                            *s.last.lock().await = Some(v);
                        }
                        let body = s.body.lock().await.clone();
                        let status = *s.status.lock().await;
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    (addr, state)
}

fn allow_body() -> &'static str {
    r#"{"decision":"allow","reason":"ok","proof_id":"p1","danger_tags":[]}"#
}

fn deny_body() -> &'static str {
    r#"{"decision":"deny","reason":"nope","proof_id":"p2","danger_tags":["dangerous"]}"#
}

#[tokio::test]
async fn allows_request_and_sends_bearer() {
    let (addr, state) = start_mock_daemon(allow_body()).await;
    let client = TfDecideClient::new(format!("http://{addr}"), "secret-token");
    let resp = client
        .decide(&DecideRequest {
            action: "GET /x".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(is_allow(&resp));
    assert_eq!(state.hits.load(Ordering::Relaxed), 1);
    let auth = state.last_auth.lock().await.clone().unwrap();
    assert_eq!(auth, "Bearer secret-token");
}

#[tokio::test]
async fn deny_decoded_with_danger_tags() {
    let (addr, _state) = start_mock_daemon(deny_body()).await;
    let client = TfDecideClient::new(format!("http://{addr}"), "tok");
    let resp = client
        .decide(&DecideRequest {
            action: "DELETE /x".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(is_deny(&resp));
    assert_eq!(resp.danger_tags, vec!["dangerous".to_string()]);
}

#[tokio::test]
async fn http_500_surfaces_status_error() {
    let (addr, state) = start_mock_daemon(allow_body()).await;
    *state.status.lock().await = 500;
    *state.body.lock().await = "boom".into();
    let client = TfDecideClient::new(format!("http://{addr}"), "tok");
    let err = client
        .decide(&DecideRequest {
            action: "X".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("500"), "{msg}");
}

#[tokio::test]
async fn request_body_round_trips_fields() {
    let (addr, state) = start_mock_daemon(allow_body()).await;
    let client = TfDecideClient::new(format!("http://{addr}"), "tok");
    let _ = client
        .decide(&DecideRequest {
            action: "POST /a".into(),
            actor: Some("tf:actor:agent:test".into()),
            host_token: Some("ht".into()),
            host_token_kind: Some("oauth".into()),
            target: Some("res://foo".into()),
            context: serde_json::json!({"k":"v"}),
            trace_id: Some("trace-1".into()),
        })
        .await
        .unwrap();
    let last = state.last.lock().await.clone().unwrap();
    assert_eq!(last["action"], "POST /a");
    assert_eq!(last["actor"], "tf:actor:agent:test");
    assert_eq!(last["host_token"], "ht");
    assert_eq!(last["host_token_kind"], "oauth");
    assert_eq!(last["target"], "res://foo");
    assert_eq!(last["trace_id"], "trace-1");
    assert_eq!(last["context"]["k"], "v");
}
