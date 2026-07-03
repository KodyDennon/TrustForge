//! Per-kind ProofRPC tests — exercises the 10 RpcMethodKind dispatchers
//! end-to-end over an in-memory transport. Each test asserts both the
//! handler-observed state and the wire-level invariants (ack frames,
//! credit grants, hash echoes, stream-tag pass-through, chain echoes).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tf_types::encoding::STANDARD as B64;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::time::timeout;

use tf_types::rpc::{
    AgentSessionFrame, AllowAllEnforcer, RemoteShellOut, RemoteShellStream, RpcClient, RpcContext,
    RpcError, RpcFrame, RpcFrameExt, RpcMethodKind, RpcServer, RpcTransport, StreamingPriority,
};
use tf_types::session::SessionFrame;

type Listener = Arc<dyn Fn(SessionFrame) + Send + Sync>;

/// Bidirectional in-memory transport pair. Each side records every
/// outgoing SessionFrame in `sent_log` and forwards it to the other
/// side's listeners.
struct MemPipeTransport {
    peer_listeners: Arc<Mutex<Vec<Listener>>>,
    our_listeners: Arc<Mutex<Vec<Listener>>>,
    sent_log: Arc<Mutex<Vec<SessionFrame>>>,
}

impl RpcTransport for MemPipeTransport {
    fn send(&self, frame: SessionFrame) {
        self.sent_log.lock().unwrap().push(frame.clone());
        let listeners: Vec<Listener> = self.peer_listeners.lock().unwrap().clone();
        for l in listeners {
            l(frame.clone());
        }
    }
    fn on_frame(&self, listener: Arc<dyn Fn(SessionFrame) + Send + Sync>) {
        self.our_listeners.lock().unwrap().push(listener);
    }
}

struct PipePair {
    client: Arc<MemPipeTransport>,
    server: Arc<MemPipeTransport>,
    /// Frames the *server* side sent (i.e. what the client should observe).
    server_sent: Arc<Mutex<Vec<SessionFrame>>>,
    /// Frames the *client* side sent (i.e. what the server received). Held
    /// here for symmetry; individual tests that don't introspect this can
    /// ignore it.
    #[allow(dead_code)]
    client_sent: Arc<Mutex<Vec<SessionFrame>>>,
}

fn pipe_pair() -> PipePair {
    let a_ours: Arc<Mutex<Vec<Listener>>> = Arc::new(Mutex::new(Vec::new()));
    let b_ours: Arc<Mutex<Vec<Listener>>> = Arc::new(Mutex::new(Vec::new()));
    let a_log: Arc<Mutex<Vec<SessionFrame>>> = Arc::new(Mutex::new(Vec::new()));
    let b_log: Arc<Mutex<Vec<SessionFrame>>> = Arc::new(Mutex::new(Vec::new()));
    let a = Arc::new(MemPipeTransport {
        peer_listeners: Arc::new(Mutex::new(Vec::new())),
        our_listeners: a_ours.clone(),
        sent_log: a_log.clone(),
    });
    let b = Arc::new(MemPipeTransport {
        peer_listeners: Arc::new(Mutex::new(Vec::new())),
        our_listeners: b_ours.clone(),
        sent_log: b_log.clone(),
    });
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
    PipePair {
        client: a,
        server: b,
        client_sent: a_log,
        server_sent: b_log,
    }
}

fn rpc_frames(log: &Arc<Mutex<Vec<SessionFrame>>>) -> Vec<RpcFrame> {
    log.lock()
        .unwrap()
        .iter()
        .filter_map(|f| match f {
            SessionFrame::Data { payload } => serde_json::from_value(payload.clone()).ok(),
            _ => None,
        })
        .collect()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    let mut s = String::from("sha256:");
    for b in d.iter() {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[tokio::test]
async fn unary_round_trip() {
    let pair = pipe_pair();
    let server = RpcServer::new(
        pair.server.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    server.register_unary(
        "echo",
        "echo",
        Arc::new(|req, _ctx: RpcContext| Box::pin(async move { Ok(req) })),
    );
    let client = RpcClient::new(pair.client.clone(), "tf:actor:human:example.com/u");
    let resp = client.call_raw("echo", json!({"x": 1})).await.unwrap();
    assert_eq!(resp, json!({"x": 1}));
}

#[tokio::test]
async fn server_stream_emits_method_kind() {
    let pair = pipe_pair();
    let server = RpcServer::new(
        pair.server.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    server.register_stream(
        "tick",
        "tick",
        Arc::new(|_req, _ctx, tx| {
            Box::pin(async move {
                for i in 0..3 {
                    let _ = tx.send(Ok(json!({ "i": i })));
                }
            })
        }),
    );
    let client = RpcClient::new(pair.client.clone(), "tf:actor:human:example.com/u");
    let mut rx = client.server_stream_raw("tick", json!({}));
    let mut got = Vec::new();
    while let Some(item) = rx.recv().await {
        got.push(item.unwrap());
    }
    assert_eq!(got, vec![json!({"i":0}), json!({"i":1}), json!({"i":2})]);
    let frames = rpc_frames(&pair.server_sent);
    let stream_frames: Vec<_> = frames
        .iter()
        .filter(|f| matches!(f, RpcFrame::RpcStream { .. }))
        .collect();
    // every server stream frame should carry method_kind = server-streaming
    for f in &stream_frames {
        if let RpcFrame::RpcStream { ext, .. } = f {
            let ext = ext.as_ref().expect("ext present");
            assert_eq!(ext.method_kind, Some(RpcMethodKind::ServerStreaming));
        }
    }
    assert!(stream_frames.len() >= 4, "3 data + 1 trailer expected");
}

#[tokio::test]
async fn client_stream_aggregates() {
    let pair = pipe_pair();
    let server = RpcServer::new(
        pair.server.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    server.register_client_stream(
        "sum",
        "sum",
        Arc::new(|initial: Value, _ctx, mut rx| {
            Box::pin(async move {
                let mut total = initial.get("seed").and_then(|v| v.as_i64()).unwrap_or(0);
                while let Some(item) = rx.recv().await {
                    let v = item.expect("ok");
                    total += v.as_i64().unwrap_or(0);
                }
                Ok(json!({ "total": total }))
            })
        }),
    );
    let client = RpcClient::new(pair.client.clone(), "tf:actor:human:example.com/u");
    let (tx, rx) = mpsc::unbounded_channel::<Result<Value, RpcError>>();
    let fut = client.client_stream_raw("sum", json!({"seed": 100}), rx);
    tx.send(Ok(json!(1))).unwrap();
    tx.send(Ok(json!(2))).unwrap();
    tx.send(Ok(json!(3))).unwrap();
    drop(tx);
    let resp = fut.await.unwrap();
    assert_eq!(resp, json!({"total": 106}));
}

#[tokio::test]
async fn bidi_streaming_two_way() {
    let pair = pipe_pair();
    let server = RpcServer::new(
        pair.server.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    server.register_bidi(
        "double",
        "double",
        Arc::new(|_initial: Value, _ctx, mut rx, tx| {
            Box::pin(async move {
                while let Some(item) = rx.recv().await {
                    let v = item.expect("ok");
                    let n = v.as_i64().unwrap_or(0);
                    if tx.send(Ok(json!(n * 2))).is_err() {
                        return;
                    }
                }
            })
        }),
    );
    let client = RpcClient::new(pair.client.clone(), "tf:actor:human:example.com/u");
    let (client_tx, mut server_rx) = client.bidi_raw("double", json!({}));
    client_tx.send(Ok(json!(2))).unwrap();
    client_tx.send(Ok(json!(5))).unwrap();
    drop(client_tx);
    let mut got = Vec::new();
    while let Some(item) = server_rx.recv().await {
        got.push(item.unwrap());
    }
    assert_eq!(got, vec![json!(4), json!(10)]);
    // every server stream frame should carry method_kind = bidi-streaming
    let frames = rpc_frames(&pair.server_sent);
    for f in &frames {
        if let RpcFrame::RpcStream { ext, .. } = f {
            assert_eq!(
                ext.as_ref().and_then(|e| e.method_kind.clone()),
                Some(RpcMethodKind::BidiStreaming)
            );
        }
    }
}

#[tokio::test]
async fn subscribe_emits_subscribed_and_unsubscribed_ack() {
    let pair = pipe_pair();
    let server = RpcServer::new(
        pair.server.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    let observed_topic: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let topic_for_handler = observed_topic.clone();
    server.register_subscribe(
        "sub",
        "sub",
        Arc::new(move |_req, ctx, tx| {
            let topic_for_handler = topic_for_handler.clone();
            Box::pin(async move {
                *topic_for_handler.lock().unwrap() = ctx.subscribe_topic.clone();
                let _ = tx.send(Ok(json!({"event": "a"})));
                let _ = tx.send(Ok(json!({"event": "b"})));
            })
        }),
    );
    let client = RpcClient::new(pair.client.clone(), "tf:actor:human:example.com/u");
    let mut rx = client.subscribe_raw("sub", json!({}), Some("topic-x".into()));
    let mut events = Vec::new();
    while let Some(item) = rx.recv().await {
        events.push(item.unwrap());
    }
    assert_eq!(events, vec![json!({"event":"a"}), json!({"event":"b"})]);
    assert_eq!(
        observed_topic.lock().unwrap().clone(),
        Some("topic-x".into())
    );
    let frames = rpc_frames(&pair.server_sent);
    // Find subscribed ack and unsubscribed trailer.
    let mut saw_subscribed = false;
    let mut saw_unsubscribed = false;
    for f in frames.iter() {
        if let RpcFrame::RpcStream { seq, more, ext, .. } = f {
            if *seq == -1 {
                if let Some(ext) = ext {
                    match ext.ack.as_deref() {
                        Some("subscribed") if *more => {
                            saw_subscribed = true;
                            assert_eq!(ext.subscribe_topic.as_deref(), Some("topic-x"));
                        }
                        Some("unsubscribed") if !*more => saw_unsubscribed = true,
                        _ => {}
                    }
                }
            }
        }
    }
    assert!(saw_subscribed, "subscribed ack frame not seen");
    assert!(saw_unsubscribed, "unsubscribed trailer not seen");
}

#[tokio::test]
async fn command_channel_emits_initial_credit_grant() {
    let pair = pipe_pair();
    let server = RpcServer::new(
        pair.server.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    server.register_command_channel(
        "cmd",
        "cmd",
        Arc::new(|_initial, _ctx, mut rx, tx| {
            Box::pin(async move {
                while let Some(item) = rx.recv().await {
                    let v = item.expect("ok");
                    if tx.send(Ok(json!({"echo": v}))).is_err() {
                        return;
                    }
                }
            })
        }),
        7, // initial_credit
    );
    let client = RpcClient::new(pair.client.clone(), "tf:actor:human:example.com/u");
    let (client_tx, mut server_rx) = client.command_channel_raw("cmd", json!({}));
    client_tx.send(Ok(json!("hi"))).unwrap();
    drop(client_tx);
    let mut got = Vec::new();
    while let Some(item) = server_rx.recv().await {
        got.push(item.unwrap());
    }
    assert_eq!(got, vec![json!({"echo": "hi"})]);
    // The first server stream frame should be the seq=-1 credit grant.
    let frames = rpc_frames(&pair.server_sent);
    let mut saw_credit_grant = false;
    let mut data_frames_kind = Vec::new();
    for f in frames.iter() {
        if let RpcFrame::RpcStream {
            seq,
            more,
            ext,
            value,
            ..
        } = f
        {
            if *seq == -1 && *more {
                if let Some(ext) = ext {
                    if ext.method_kind == Some(RpcMethodKind::CommandChannel)
                        && ext.credit == Some(7)
                    {
                        saw_credit_grant = true;
                    }
                }
            } else if value.is_some() {
                data_frames_kind.push(ext.as_ref().and_then(|e| e.method_kind.clone()));
            }
        }
    }
    assert!(saw_credit_grant, "did not see initial credit grant");
    for k in data_frames_kind {
        assert_eq!(k, Some(RpcMethodKind::CommandChannel));
    }
}

#[tokio::test]
async fn bulk_transfer_verifies_hash() {
    let pair = pipe_pair();
    let server = RpcServer::new(
        pair.server.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    let bytes_received: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let bytes_for_handler = bytes_received.clone();
    server.register_bulk_transfer(
        "upload",
        "upload",
        Arc::new(move |_initial, _ctx, mut rx| {
            let bytes_for_handler = bytes_for_handler.clone();
            Box::pin(async move {
                while let Some(chunk) = rx.recv().await {
                    bytes_for_handler.lock().unwrap().extend_from_slice(&chunk);
                }
                Ok(json!({"received": bytes_for_handler.lock().unwrap().len()}))
            })
        }),
    );
    let client = RpcClient::new(pair.client.clone(), "tf:actor:human:example.com/u");
    let chunks: Vec<Vec<u8>> = vec![b"hello".to_vec(), b" ".to_vec(), b"world".to_vec()];
    let combined: Vec<u8> = chunks.iter().flatten().copied().collect();
    let expected_hash = sha256_hex(&combined);
    let resp = client
        .bulk_transfer_raw("upload", json!({}), &chunks)
        .await
        .unwrap();
    assert_eq!(resp, json!({"received": combined.len()}));
    assert_eq!(*bytes_received.lock().unwrap(), combined);
    // The success rpc-response should echo the hash in ext.bulk.expected_hash.
    let frames = rpc_frames(&pair.server_sent);
    let response_frame = frames
        .iter()
        .find_map(|f| match f {
            RpcFrame::RpcResponse { ext, .. } => ext.clone(),
            _ => None,
        })
        .expect("response frame");
    assert_eq!(
        response_frame.method_kind,
        Some(RpcMethodKind::BulkTransfer)
    );
    assert_eq!(
        response_frame.bulk.and_then(|b| b.expected_hash).as_deref(),
        Some(expected_hash.as_str())
    );
}

#[tokio::test]
async fn bulk_transfer_rejects_hash_mismatch() {
    let pair = pipe_pair();
    let server = RpcServer::new(
        pair.server.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    server.register_bulk_transfer(
        "upload",
        "upload",
        Arc::new(|_initial, _ctx, mut rx| {
            Box::pin(async move {
                while rx.recv().await.is_some() {}
                Ok(json!({"ok": true}))
            })
        }),
    );
    // Send a hand-crafted RpcCall with a deliberately wrong expected_hash,
    // followed by chunks. We bypass `bulk_transfer_raw` to lie about the hash.
    let client = pair.client.clone();
    let server_sent = pair.server_sent.clone();
    // Subscribe to incoming server frames so we can capture the rejection
    // synchronously.
    let response_seen: Arc<Mutex<Option<RpcFrame>>> = Arc::new(Mutex::new(None));
    let response_seen_listener = response_seen.clone();
    client.on_frame(Arc::new(move |frame| {
        if let SessionFrame::Data { payload } = frame {
            if let Ok(rpc) = serde_json::from_value::<RpcFrame>(payload) {
                if let RpcFrame::RpcResponse { .. } = &rpc {
                    *response_seen_listener.lock().unwrap() = Some(rpc);
                }
            }
        }
    }));
    let call_id = "test-bulk-mismatch".to_string();
    let bogus_hash = "sha256:deadbeef".to_string();
    let call = RpcFrame::RpcCall {
        call_id: call_id.clone(),
        method: "upload".into(),
        request: json!({}),
        ext: Some(RpcFrameExt {
            method_kind: Some(RpcMethodKind::BulkTransfer),
            bulk: Some(tf_types::rpc::RpcBulkExt {
                expected_hash: Some(bogus_hash.clone()),
                ..Default::default()
            }),
            ..Default::default()
        }),
    };
    client.send(SessionFrame::Data {
        payload: serde_json::to_value(&call).unwrap(),
    });
    // Yield so the server registers the inflight call.
    tokio::time::sleep(Duration::from_millis(10)).await;
    // Send one chunk.
    let chunk = b"garbage".to_vec();
    let actual_hash = sha256_hex(&chunk);
    let frame = RpcFrame::RpcClientStream {
        call_id: call_id.clone(),
        seq: 0,
        more: true,
        value: Some(Value::String(B64.encode(&chunk))),
        error: None,
        ext: Some(RpcFrameExt {
            method_kind: Some(RpcMethodKind::BulkTransfer),
            ..Default::default()
        }),
    };
    client.send(SessionFrame::Data {
        payload: serde_json::to_value(&frame).unwrap(),
    });
    let trailer = RpcFrame::RpcClientStream {
        call_id: call_id.clone(),
        seq: 1,
        more: false,
        value: None,
        error: None,
        ext: None,
    };
    client.send(SessionFrame::Data {
        payload: serde_json::to_value(&trailer).unwrap(),
    });
    // Wait for the server to reject.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while response_seen.lock().unwrap().is_none() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let response = response_seen
        .lock()
        .unwrap()
        .clone()
        .expect("server response not received");
    let RpcFrame::RpcResponse {
        status, error, ext, ..
    } = response
    else {
        panic!("expected rpc-response");
    };
    assert!(matches!(status, tf_types::rpc::ResponseStatus::Error));
    let err = error.expect("error body");
    assert_eq!(err.code, tf_types::rpc::RpcErrorCode::InvalidArgument);
    // ext.bulk.expected_hash should echo the *actual* hash so the client
    // can debug the mismatch.
    let ext = ext.expect("ext");
    let actual_echoed = ext
        .bulk
        .and_then(|b| b.expected_hash)
        .expect("actual hash echoed");
    assert_eq!(actual_echoed, actual_hash);
    let _ = server_sent; // silence unused
}

#[tokio::test]
async fn telemetry_round_trip_with_priority() {
    let pair = pipe_pair();
    let server = RpcServer::new(
        pair.server.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    let received: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let received_for_handler = received.clone();
    let priority_seen: Arc<Mutex<Option<StreamingPriority>>> = Arc::new(Mutex::new(None));
    let priority_for_handler = priority_seen.clone();
    server.register_telemetry(
        "metrics",
        "metrics",
        Arc::new(move |_initial, _ctx, prio, mut rx| {
            let received = received_for_handler.clone();
            let prio_seen = priority_for_handler.clone();
            Box::pin(async move {
                *prio_seen.lock().unwrap() = Some(prio);
                while let Some(item) = rx.recv().await {
                    let v = item.expect("ok");
                    received.lock().unwrap().push(v);
                }
                Ok(())
            })
        }),
        StreamingPriority::P2,
    );
    let client = RpcClient::new(pair.client.clone(), "tf:actor:human:example.com/u");
    let (tx, rx) = mpsc::unbounded_channel::<Result<Value, RpcError>>();
    let fut = client.telemetry_raw("metrics", json!({}), rx, StreamingPriority::P2);
    tx.send(Ok(json!({"cpu": 0.5}))).unwrap();
    tx.send(Ok(json!({"cpu": 0.7}))).unwrap();
    drop(tx);
    fut.await.unwrap();
    assert_eq!(
        *received.lock().unwrap(),
        vec![json!({"cpu":0.5}), json!({"cpu":0.7})]
    );
    assert_eq!(*priority_seen.lock().unwrap(), Some(StreamingPriority::P2));
    // Closing rpc-response should carry method_kind=telemetry +
    // streaming_priority=P2.
    let frames = rpc_frames(&pair.server_sent);
    let resp_ext = frames
        .iter()
        .find_map(|f| match f {
            RpcFrame::RpcResponse { ext, .. } => ext.clone(),
            _ => None,
        })
        .expect("response ext");
    assert_eq!(resp_ext.method_kind, Some(RpcMethodKind::Telemetry));
    assert_eq!(resp_ext.streaming_priority, Some(StreamingPriority::P2));
}

#[tokio::test]
async fn remote_shell_tags_stdout_stderr() {
    let pair = pipe_pair();
    let server = RpcServer::new(
        pair.server.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    server.register_remote_shell(
        "shell",
        "shell",
        Arc::new(|_initial, _ctx, mut stdin_rx, out_tx| {
            Box::pin(async move {
                // Drain stdin (we only care that the pipe works).
                let mut got_stdin = Vec::new();
                while let Some(chunk) = stdin_rx.recv().await {
                    got_stdin.push(chunk);
                }
                let _ = got_stdin;
                let _ = out_tx.send(RemoteShellOut {
                    stream: RemoteShellStream::Stdout,
                    data: b"out-1\n".to_vec(),
                });
                let _ = out_tx.send(RemoteShellOut {
                    stream: RemoteShellStream::Stderr,
                    data: b"err-1\n".to_vec(),
                });
            })
        }),
    );
    let client = RpcClient::new(pair.client.clone(), "tf:actor:human:example.com/u");
    let (stdin_tx, stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    stdin_tx.send(b"echo hi\n".to_vec()).unwrap();
    drop(stdin_tx);
    let mut out_rx = client.remote_shell_raw("shell", json!({}), stdin_rx);
    let mut got = Vec::new();
    let result = timeout(Duration::from_secs(2), async {
        while let Some(item) = out_rx.recv().await {
            got.push(item.unwrap());
        }
    })
    .await;
    assert!(result.is_ok(), "remote-shell timed out");
    assert_eq!(got.len(), 2);
    assert!(matches!(got[0].stream, RemoteShellStream::Stdout));
    assert_eq!(got[0].data, b"out-1\n");
    assert!(matches!(got[1].stream, RemoteShellStream::Stderr));
    assert_eq!(got[1].data, b"err-1\n");
}

#[tokio::test]
async fn agent_session_preserves_chain() {
    let pair = pipe_pair();
    let server = RpcServer::new(
        pair.server.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    let observed_initial: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_for_handler = observed_initial.clone();
    server.register_agent_session(
        "session",
        "session",
        Arc::new(move |_initial, ctx, mut rx, tx| {
            let observed = observed_for_handler.clone();
            Box::pin(async move {
                *observed.lock().unwrap() = ctx.initial_chain.clone();
                while let Some(frame) = rx.recv().await {
                    // Server appends an extra delegation hop and echoes back.
                    let mut new_chain = frame.responsibility_chain.clone();
                    new_chain.push("tf:actor:agent:example.com/srv".into());
                    if tx
                        .send(AgentSessionFrame {
                            value: frame.value,
                            responsibility_chain: new_chain,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
            })
        }),
    );
    let client = RpcClient::new(pair.client.clone(), "tf:actor:human:example.com/u");
    let (frames_tx, frames_rx) = mpsc::unbounded_channel::<AgentSessionFrame>();
    let initial_chain = vec!["tf:actor:human:example.com/alice".to_string()];
    frames_tx
        .send(AgentSessionFrame {
            value: json!({"task": "t1"}),
            responsibility_chain: vec![
                "tf:actor:human:example.com/alice".into(),
                "tf:actor:agent:example.com/coder".into(),
            ],
        })
        .unwrap();
    drop(frames_tx);
    let mut rx = client.agent_session_raw("session", json!({}), initial_chain.clone(), frames_rx);
    let mut got = Vec::new();
    let result = timeout(Duration::from_secs(2), async {
        while let Some(item) = rx.recv().await {
            got.push(item.unwrap());
        }
    })
    .await;
    assert!(result.is_ok(), "agent-session timed out");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].value, json!({"task": "t1"}));
    assert_eq!(
        got[0].responsibility_chain,
        vec![
            "tf:actor:human:example.com/alice".to_string(),
            "tf:actor:agent:example.com/coder".to_string(),
            "tf:actor:agent:example.com/srv".to_string(),
        ]
    );
    // ctx.initial_chain should reflect the rpc-call ext.
    assert_eq!(*observed_initial.lock().unwrap(), initial_chain);
    // Every server-side stream frame should carry the chain in ext.
    let frames = rpc_frames(&pair.server_sent);
    let mut saw_chained_stream = false;
    for f in &frames {
        if let RpcFrame::RpcStream {
            ext, more, value, ..
        } = f
        {
            if *more && value.is_some() {
                if let Some(ext) = ext {
                    assert_eq!(ext.method_kind, Some(RpcMethodKind::AgentSession));
                    assert!(ext.responsibility_chain.is_some());
                    saw_chained_stream = true;
                }
            }
        }
    }
    assert!(saw_chained_stream, "no chained stream frame seen");
}
