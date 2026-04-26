//! Rust ProofRPC runtime tests (in-memory transport).

use std::sync::{Arc, Mutex};

use serde_json::json;
use tokio::sync::mpsc::UnboundedSender;

use tf_types::rpc::{
    AllowAllEnforcer, DenyAllEnforcer, RpcClient, RpcContext, RpcError, RpcErrorCode, RpcServer,
    RpcTransport,
};
use tf_types::session::SessionFrame;

type Listener = Arc<dyn Fn(SessionFrame) + Send + Sync>;

struct InMemoryTransport {
    peer_listeners: Arc<Mutex<Vec<Listener>>>,
    our_listeners: Arc<Mutex<Vec<Listener>>>,
}

impl RpcTransport for InMemoryTransport {
    fn send(&self, frame: SessionFrame) {
        let listeners: Vec<Listener> = self.peer_listeners.lock().unwrap().clone();
        for l in listeners {
            l(frame.clone());
        }
    }
    fn on_frame(&self, listener: Arc<dyn Fn(SessionFrame) + Send + Sync>) {
        self.our_listeners.lock().unwrap().push(listener);
    }
}

fn wire_pair() -> (Arc<InMemoryTransport>, Arc<InMemoryTransport>) {
    let a_ours: Arc<Mutex<Vec<Listener>>> = Arc::new(Mutex::new(Vec::new()));
    let b_ours: Arc<Mutex<Vec<Listener>>> = Arc::new(Mutex::new(Vec::new()));
    let a = Arc::new(InMemoryTransport {
        peer_listeners: Arc::new(Mutex::new(Vec::new())),
        our_listeners: a_ours.clone(),
    });
    let b = Arc::new(InMemoryTransport {
        peer_listeners: Arc::new(Mutex::new(Vec::new())),
        our_listeners: b_ours.clone(),
    });

    // When a.send(...) fires, dispatch to everything b has registered.
    {
        let b_ours = b_ours.clone();
        a.peer_listeners.lock().unwrap().push(Arc::new(move |f| {
            let ls: Vec<Listener> = b_ours.lock().unwrap().clone();
            for l in ls {
                l(f.clone());
            }
        }));
    }
    {
        let a_ours = a_ours.clone();
        b.peer_listeners.lock().unwrap().push(Arc::new(move |f| {
            let ls: Vec<Listener> = a_ours.lock().unwrap().clone();
            for l in ls {
                l(f.clone());
            }
        }));
    }
    (a, b)
}

#[tokio::test]
async fn unary_round_trip() {
    let (client_t, server_t) = wire_pair();
    let server = RpcServer::new(
        server_t.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    let call_count = Arc::new(Mutex::new(0u32));
    let counter = call_count.clone();
    server.register_unary(
        "fetchFile",
        "file.read",
        Arc::new(move |req, ctx: RpcContext| {
            let counter = counter.clone();
            Box::pin(async move {
                *counter.lock().unwrap() += 1;
                let path = req
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let _ = ctx;
                Ok(json!({ "path": path, "contents": "hello", "size": 5 }))
            })
        }),
    );
    let client = RpcClient::new(client_t.clone(), "tf:actor:human:example.com/user");
    let resp = client
        .call_raw("fetchFile", json!({ "path": "README.md" }))
        .await
        .unwrap();
    assert_eq!(
        resp,
        json!({ "path": "README.md", "contents": "hello", "size": 5 })
    );
    assert_eq!(*call_count.lock().unwrap(), 1);
}

#[tokio::test]
async fn unknown_method_returns_not_found() {
    let (client_t, server_t) = wire_pair();
    let _server = RpcServer::new(
        server_t,
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    let client = RpcClient::new(client_t, "tf:actor:human:example.com/user");
    let err = client.call_raw("bogus", json!({})).await.unwrap_err();
    assert_eq!(err.code, RpcErrorCode::NotFound);
}

#[tokio::test]
async fn deny_all_rejects_with_permission_denied() {
    let (client_t, server_t) = wire_pair();
    let server = RpcServer::new(
        server_t,
        "tf:actor:agent:example.com/srv",
        Arc::new(DenyAllEnforcer),
    );
    server.register_unary(
        "fetchFile",
        "file.read",
        Arc::new(|_, _| Box::pin(async { Ok(json!({})) })),
    );
    let client = RpcClient::new(client_t, "tf:actor:human:example.com/user");
    let err = client
        .call_raw("fetchFile", json!({ "path": "x" }))
        .await
        .unwrap_err();
    assert_eq!(err.code, RpcErrorCode::PermissionDenied);
}

#[tokio::test]
async fn handler_error_returns_internal() {
    let (client_t, server_t) = wire_pair();
    let server = RpcServer::new(
        server_t,
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    server.register_unary(
        "boom",
        "file.read",
        Arc::new(|_, _| {
            Box::pin(async {
                Err(RpcError {
                    code: RpcErrorCode::Internal,
                    message: "oh no".into(),
                })
            })
        }),
    );
    let client = RpcClient::new(client_t, "tf:actor:human:example.com/user");
    let err = client.call_raw("boom", json!({})).await.unwrap_err();
    assert_eq!(err.code, RpcErrorCode::Internal);
}

#[tokio::test]
async fn server_stream_delivers_values_and_terminates() {
    let (client_t, server_t) = wire_pair();
    let server = RpcServer::new(
        server_t,
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    server.register_stream(
        "count",
        "file.read",
        Arc::new(|req, _ctx, tx: UnboundedSender<Result<_, _>>| {
            Box::pin(async move {
                let n = req.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                for i in 0..n {
                    let _ = tx.send(Ok(json!({ "n": i })));
                }
                // drop tx to terminate
                drop(tx);
            })
        }),
    );
    let client = RpcClient::new(client_t, "tf:actor:human:example.com/user");
    let mut rx = client.server_stream_raw("count", json!({ "count": 3 }));
    let mut collected = Vec::new();
    while let Some(item) = rx.recv().await {
        collected.push(item.expect("item ok"));
    }
    assert_eq!(
        collected,
        vec![json!({"n": 0}), json!({"n": 1}), json!({"n": 2})]
    );
}
