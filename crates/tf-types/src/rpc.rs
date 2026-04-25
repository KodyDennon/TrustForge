//! ProofRPC runtime — mirrors `tools/tf-types-ts/src/core/rpc.ts`.
//!
//! Sits on top of a transport that carries `SessionFrame` values
//! (typically `tf_types::session::SessionState` wrapped by some adapter).
//! Emits typed Rust structs; capability enforcement is pluggable.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use crate::session::SessionFrame;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RpcErrorCode {
    InvalidArgument,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Internal,
}

impl RpcErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RpcErrorCode::InvalidArgument => "invalid_argument",
            RpcErrorCode::Unauthenticated => "unauthenticated",
            RpcErrorCode::PermissionDenied => "permission_denied",
            RpcErrorCode::NotFound => "not_found",
            RpcErrorCode::Internal => "internal",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcError {
    pub code: RpcErrorCode,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct RpcCallError {
    pub code: RpcErrorCode,
    pub message: String,
}

impl From<RpcError> for RpcCallError {
    fn from(e: RpcError) -> Self {
        RpcCallError {
            code: e.code,
            message: e.message,
        }
    }
}

/// ProofRPC method kind. Mirror of TS `RpcMethodKind`. The proofrpc
/// schema enumerates all 10 distinct flows; the runtime applies
/// per-kind invariants (subscribe ack, command-channel credits,
/// bulk-transfer hash verification, telemetry priority, remote-shell
/// stream tagging, agent-session delegation chain).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum RpcMethodKind {
    Unary,
    ServerStreaming,
    ClientStreaming,
    BidiStreaming,
    Subscribe,
    CommandChannel,
    BulkTransfer,
    Telemetry,
    RemoteShell,
    AgentSession,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum RemoteShellStream {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum StreamingPriority {
    P0,
    P1,
    P2,
    P3,
    P4,
    P5,
}

/// Per-frame metadata carried alongside the rpc envelope. Optional;
/// older counterparts that don't understand a field skip it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcFrameExt {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub method_kind: Option<RpcMethodKind>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub streaming_priority: Option<StreamingPriority>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subscribe_topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub credit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bulk: Option<RpcBulkExt>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub shell_stream: Option<RemoteShellStream>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub responsibility_chain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ack: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcBulkExt {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chunk_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub total_chunks: Option<u32>,
    /// `sha256:<hex>` digest of the concatenated chunks; the receiving
    /// side recomputes and compares before accepting the receipt.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expected_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RpcFrame {
    RpcCall {
        call_id: String,
        method: String,
        request: Value,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        ext: Option<RpcFrameExt>,
    },
    RpcResponse {
        call_id: String,
        status: ResponseStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        response: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<RpcError>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        ext: Option<RpcFrameExt>,
    },
    RpcStream {
        call_id: String,
        seq: i64,
        more: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<RpcError>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        ext: Option<RpcFrameExt>,
    },
    /// Client → server stream message used by client-streaming, bidi,
    /// command-channel, bulk-transfer, telemetry, remote-shell and
    /// agent-session method kinds. Mirror of the TS variant added in
    /// B13.
    RpcClientStream {
        call_id: String,
        seq: u64,
        more: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<RpcError>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        ext: Option<RpcFrameExt>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Ok,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcProofEventStub {
    #[serde(rename = "type")]
    pub kind: String,
    pub method: String,
    pub call_id: String,
    pub caller: String,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Method kind from the descriptor; lets the daemon apply per-kind
    /// policy and surfaces the distinction in proof events.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub method_kind: Option<RpcMethodKind>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub streaming_priority: Option<StreamingPriority>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bulk_hash_verified: Option<bool>,
}

pub trait CapabilityEnforcer: Send + Sync {
    fn check(&self, caller: &str, method: &str, capability: &str) -> CapabilityDecision;
}

pub enum CapabilityDecision {
    Allow,
    Deny(String),
}

pub struct AllowAllEnforcer;

impl CapabilityEnforcer for AllowAllEnforcer {
    fn check(&self, _: &str, _: &str, _: &str) -> CapabilityDecision {
        CapabilityDecision::Allow
    }
}

pub struct DenyAllEnforcer;

impl CapabilityEnforcer for DenyAllEnforcer {
    fn check(&self, _: &str, _: &str, _: &str) -> CapabilityDecision {
        CapabilityDecision::Deny("capability enforcement denied all".into())
    }
}

/// Wire-level transport. The tf-session crate will provide an adapter that
/// implements this on top of SessionState; for tests we use an in-memory
/// pair.
pub trait RpcTransport: Send + Sync {
    fn send(&self, frame: SessionFrame);
    /// Register a listener; returns a key that can be used to unregister
    /// (unused here because we just store the Arc).
    fn on_frame(&self, listener: Arc<dyn Fn(SessionFrame) + Send + Sync>);
}

pub fn new_call_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    B64.encode(bytes)
}

fn encode_rpc(frame: RpcFrame) -> SessionFrame {
    let payload = serde_json::to_value(frame).expect("serialize rpc frame");
    SessionFrame::Data { payload }
}

fn decode_rpc(frame: SessionFrame) -> Option<RpcFrame> {
    match frame {
        SessionFrame::Data { payload } => serde_json::from_value(payload).ok(),
        _ => None,
    }
}

// ---------- Client ----------

type UnaryResp = oneshot::Sender<Result<Value, RpcError>>;

enum Pending {
    Unary(UnaryResp),
    Stream {
        tx: mpsc::UnboundedSender<Result<Value, RpcError>>,
        next_seq: u64,
    },
}

pub struct RpcClient<T: RpcTransport + 'static> {
    transport: Arc<T>,
    pending: Arc<Mutex<HashMap<String, Pending>>>,
    caller_actor: String,
}

impl<T: RpcTransport + 'static> RpcClient<T> {
    pub fn new(transport: Arc<T>, caller_actor: impl Into<String>) -> Self {
        let pending: Arc<Mutex<HashMap<String, Pending>>> = Arc::new(Mutex::new(HashMap::new()));
        let pending_for_listener = pending.clone();
        transport.on_frame(Arc::new(move |frame| {
            let rpc = match decode_rpc(frame) {
                Some(r) => r,
                None => return,
            };
            match rpc {
                RpcFrame::RpcResponse {
                    call_id,
                    status,
                    response,
                    error,
                    ext: _,
                } => {
                    let mut map = pending_for_listener.lock().unwrap();
                    if let Some(Pending::Unary(tx)) = map.remove(&call_id) {
                        match status {
                            ResponseStatus::Ok => {
                                let _ = tx.send(Ok(response.unwrap_or(Value::Null)));
                            }
                            ResponseStatus::Error => {
                                let _ = tx.send(Err(error.unwrap_or(RpcError {
                                    code: RpcErrorCode::Internal,
                                    message: "(no error body)".into(),
                                })));
                            }
                        }
                    }
                }
                RpcFrame::RpcStream {
                    call_id,
                    seq,
                    more,
                    value,
                    error,
                    ext: _,
                } => {
                    let mut map = pending_for_listener.lock().unwrap();
                    if let Some(entry) = map.get_mut(&call_id) {
                        match entry {
                            Pending::Stream { tx, next_seq } => {
                                // Synthetic ack frames (subscribe / command-channel)
                                // ride on seq = -1 and don't advance the client's
                                // sequence counter. Drop them silently here.
                                if seq < 0 {
                                    if !more {
                                        // Closing ack (e.g. unsubscribed) ends the stream.
                                        map.remove(&call_id);
                                    }
                                    return;
                                }
                                let seq_u = seq as u64;
                                if seq_u != *next_seq {
                                    let _ = tx.send(Err(RpcError {
                                        code: RpcErrorCode::Internal,
                                        message: format!(
                                            "stream seq mismatch: expected {}, got {}",
                                            next_seq, seq_u
                                        ),
                                    }));
                                    map.remove(&call_id);
                                    return;
                                }
                                *next_seq += 1;
                                if more {
                                    if let Some(v) = value {
                                        let _ = tx.send(Ok(v));
                                    }
                                } else if let Some(err) = error {
                                    let _ = tx.send(Err(err));
                                    map.remove(&call_id);
                                } else {
                                    map.remove(&call_id);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                RpcFrame::RpcCall { .. } | RpcFrame::RpcClientStream { .. } => {
                    // client side ignores inbound rpc-call / rpc-client-stream frames
                }
            }
        }));
        RpcClient {
            transport,
            pending,
            caller_actor: caller_actor.into(),
        }
    }

    pub fn caller_actor(&self) -> &str {
        &self.caller_actor
    }

    pub async fn call_raw(&self, method: &str, request: Value) -> Result<Value, RpcCallError> {
        let call_id = new_call_id();
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap()
            .insert(call_id.clone(), Pending::Unary(tx));
        self.transport.send(encode_rpc(RpcFrame::RpcCall {
            call_id: call_id.clone(),
            method: method.to_owned(),
            request,
            ext: None,
        }));
        match rx.await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(err)) => Err(err.into()),
            Err(_) => Err(RpcCallError {
                code: RpcErrorCode::Internal,
                message: "transport dropped the pending call".into(),
            }),
        }
    }

    pub fn server_stream_raw(
        &self,
        method: &str,
        request: Value,
    ) -> mpsc::UnboundedReceiver<Result<Value, RpcError>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let call_id = new_call_id();
        self.pending.lock().unwrap().insert(
            call_id.clone(),
            Pending::Stream { tx, next_seq: 0 },
        );
        self.transport.send(encode_rpc(RpcFrame::RpcCall {
            call_id,
            method: method.to_owned(),
            request,
            ext: None,
        }));
        rx
    }
}

// ---------- Server ----------

pub struct RpcContext {
    pub caller_actor: String,
    pub method: String,
    pub call_id: String,
}

pub type UnaryHandler = Arc<
    dyn Fn(Value, RpcContext) -> Pin<Box<dyn Future<Output = Result<Value, RpcError>> + Send>>
        + Send
        + Sync,
>;

pub type StreamHandler = Arc<
    dyn Fn(Value, RpcContext, mpsc::UnboundedSender<Result<Value, RpcError>>) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

enum Handler {
    Unary {
        capability: String,
        handler: UnaryHandler,
    },
    Stream {
        capability: String,
        handler: StreamHandler,
    },
}

pub struct RpcServer<T: RpcTransport + 'static> {
    transport: Arc<T>,
    handlers: Arc<Mutex<HashMap<String, Handler>>>,
    caller_actor: String,
    enforcer: Arc<dyn CapabilityEnforcer>,
}

impl<T: RpcTransport + 'static> RpcServer<T> {
    pub fn new(
        transport: Arc<T>,
        caller_actor: impl Into<String>,
        enforcer: Arc<dyn CapabilityEnforcer>,
    ) -> Self {
        let handlers: Arc<Mutex<HashMap<String, Handler>>> = Arc::new(Mutex::new(HashMap::new()));
        let caller_actor: String = caller_actor.into();
        let caller_for_listener = caller_actor.clone();
        let handlers_for_listener = handlers.clone();
        let enforcer_for_listener = enforcer.clone();
        let transport_for_listener = transport.clone();
        transport.on_frame(Arc::new(move |frame| {
            let rpc = match decode_rpc(frame) {
                Some(r) => r,
                None => return,
            };
            let RpcFrame::RpcCall {
                call_id,
                method,
                request,
                ext: _,
            } = rpc
            else {
                return;
            };

            let ctx = RpcContext {
                caller_actor: caller_for_listener.clone(),
                method: method.clone(),
                call_id: call_id.clone(),
            };

            let entry = {
                let map = handlers_for_listener.lock().unwrap();
                map.get(&method).map(|h| match h {
                    Handler::Unary { capability, handler } => {
                        ("unary", capability.clone(), Some(handler.clone()), None)
                    }
                    Handler::Stream { capability, handler } => (
                        "stream",
                        capability.clone(),
                        None,
                        Some(handler.clone()),
                    ),
                })
            };

            let Some((kind, capability, unary_handler, stream_handler)) = entry else {
                transport_for_listener.send(encode_rpc(RpcFrame::RpcResponse {
                    call_id: call_id.clone(),
                    status: ResponseStatus::Error,
                    response: None,
                    error: Some(RpcError {
                        code: RpcErrorCode::NotFound,
                        message: format!("unknown method: {}", method),
                    }),
                    ext: None,
                }));
                return;
            };

            match enforcer_for_listener.check(&caller_for_listener, &method, &capability) {
                CapabilityDecision::Allow => {}
                CapabilityDecision::Deny(reason) => {
                    if kind == "stream" {
                        transport_for_listener.send(encode_rpc(RpcFrame::RpcStream {
                            call_id,
                            seq: 0,
                            more: false,
                            value: None,
                            error: Some(RpcError {
                                code: RpcErrorCode::PermissionDenied,
                                message: reason,
                            }),
                            ext: None,
                        }));
                    } else {
                        transport_for_listener.send(encode_rpc(RpcFrame::RpcResponse {
                            call_id,
                            status: ResponseStatus::Error,
                            response: None,
                            error: Some(RpcError {
                                code: RpcErrorCode::PermissionDenied,
                                message: reason,
                            }),
                            ext: None,
                        }));
                    }
                    return;
                }
            }

            let transport_in_task = transport_for_listener.clone();
            if kind == "unary" {
                let handler = unary_handler.unwrap();
                tokio::spawn(async move {
                    let fut = handler(request, ctx);
                    match fut.await {
                        Ok(v) => transport_in_task.send(encode_rpc(RpcFrame::RpcResponse {
                            call_id,
                            status: ResponseStatus::Ok,
                            response: Some(v),
                            error: None,
                            ext: None,
                        })),
                        Err(err) => transport_in_task.send(encode_rpc(RpcFrame::RpcResponse {
                            call_id,
                            status: ResponseStatus::Error,
                            response: None,
                            error: Some(err),
                            ext: None,
                        })),
                    }
                });
            } else {
                let handler = stream_handler.unwrap();
                tokio::spawn(async move {
                    let (tx, mut rx) = mpsc::unbounded_channel::<Result<Value, RpcError>>();
                    let fut = handler(request, ctx, tx);
                    tokio::spawn(fut);
                    let mut seq: i64 = 0;
                    while let Some(item) = rx.recv().await {
                        match item {
                            Ok(v) => {
                                transport_in_task.send(encode_rpc(RpcFrame::RpcStream {
                                    call_id: call_id.clone(),
                                    seq,
                                    more: true,
                                    value: Some(v),
                                    error: None,
                                    ext: None,
                                }));
                                seq += 1;
                            }
                            Err(err) => {
                                transport_in_task.send(encode_rpc(RpcFrame::RpcStream {
                                    call_id: call_id.clone(),
                                    seq,
                                    more: false,
                                    value: None,
                                    error: Some(err),
                                    ext: None,
                                }));
                                return;
                            }
                        }
                    }
                    transport_in_task.send(encode_rpc(RpcFrame::RpcStream {
                        call_id,
                        seq,
                        more: false,
                        value: None,
                        error: None,
                        ext: None,
                    }));
                });
            }
        }));
        RpcServer {
            transport,
            handlers,
            caller_actor,
            enforcer,
        }
    }

    pub fn register_unary(&self, method: impl Into<String>, capability: impl Into<String>, handler: UnaryHandler) {
        self.handlers.lock().unwrap().insert(
            method.into(),
            Handler::Unary {
                capability: capability.into(),
                handler,
            },
        );
    }

    pub fn register_stream(&self, method: impl Into<String>, capability: impl Into<String>, handler: StreamHandler) {
        self.handlers.lock().unwrap().insert(
            method.into(),
            Handler::Stream {
                capability: capability.into(),
                handler,
            },
        );
    }

    pub fn caller_actor(&self) -> &str {
        &self.caller_actor
    }

    pub fn transport(&self) -> &Arc<T> {
        &self.transport
    }

    pub fn enforcer(&self) -> &Arc<dyn CapabilityEnforcer> {
        &self.enforcer
    }
}

impl<T: RpcTransport + 'static> RpcServer<T> {
    /// Run the CapabilityEnforcer against a synthetic call without going
    /// through the transport — useful for CLI tooling and tests that want to
    /// confirm what the server would decide for a given (caller, method,
    /// capability) triple.
    pub fn check_authorization(
        &self,
        caller: &str,
        method: &str,
        capability: &str,
    ) -> CapabilityDecision {
        self.enforcer.check(caller, method, capability)
    }
}

#[cfg(test)]
mod method_kind_tests {
    use super::*;

    #[test]
    fn rpc_method_kind_serde_kebab_case() {
        let kinds = [
            RpcMethodKind::Unary,
            RpcMethodKind::ServerStreaming,
            RpcMethodKind::ClientStreaming,
            RpcMethodKind::BidiStreaming,
            RpcMethodKind::Subscribe,
            RpcMethodKind::CommandChannel,
            RpcMethodKind::BulkTransfer,
            RpcMethodKind::Telemetry,
            RpcMethodKind::RemoteShell,
            RpcMethodKind::AgentSession,
        ];
        let json = serde_json::to_string(&kinds).unwrap();
        assert!(json.contains("unary"));
        assert!(json.contains("server-streaming"));
        assert!(json.contains("client-streaming"));
        assert!(json.contains("bidi-streaming"));
        assert!(json.contains("subscribe"));
        assert!(json.contains("command-channel"));
        assert!(json.contains("bulk-transfer"));
        assert!(json.contains("telemetry"));
        assert!(json.contains("remote-shell"));
        assert!(json.contains("agent-session"));
        let parsed: Vec<RpcMethodKind> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, kinds);
    }

    #[test]
    fn rpc_frame_ext_round_trip() {
        let ext = RpcFrameExt {
            method_kind: Some(RpcMethodKind::BulkTransfer),
            streaming_priority: Some(StreamingPriority::P1),
            subscribe_topic: None,
            credit: Some(8),
            bulk: Some(RpcBulkExt {
                chunk_index: Some(3),
                total_chunks: Some(4),
                expected_hash: Some("sha256:abcd".into()),
            }),
            shell_stream: Some(RemoteShellStream::Stderr),
            responsibility_chain: Some(vec!["tf:actor:human:example.com/alice".into()]),
            ack: Some("subscribed".into()),
        };
        let json = serde_json::to_string(&ext).unwrap();
        let parsed: RpcFrameExt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ext);
    }

    #[test]
    fn rpc_client_stream_frame_serializes_with_kebab_kind() {
        let frame = RpcFrame::RpcClientStream {
            call_id: "c1".into(),
            seq: 0,
            more: true,
            value: Some(serde_json::json!("payload")),
            error: None,
            ext: Some(RpcFrameExt {
                method_kind: Some(RpcMethodKind::Telemetry),
                streaming_priority: Some(StreamingPriority::P3),
                ..Default::default()
            }),
        };
        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["kind"], "rpc-client-stream");
        assert_eq!(json["ext"]["method_kind"], "telemetry");
        assert_eq!(json["ext"]["streaming_priority"], "P3");
    }

    #[test]
    fn proof_event_carries_method_kind_when_set() {
        let ev = RpcProofEventStub {
            kind: "rpc.call".into(),
            method: "blob.upload".into(),
            call_id: "c1".into(),
            caller: "tf:actor:agent:example.com/x".into(),
            result: "ok".into(),
            error_code: None,
            method_kind: Some(RpcMethodKind::BulkTransfer),
            streaming_priority: None,
            bulk_hash_verified: Some(true),
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["method_kind"], "bulk-transfer");
        assert_eq!(json["bulk_hash_verified"], true);
    }
}
