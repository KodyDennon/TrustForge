#![allow(clippy::type_complexity)]
//! ProofRPC runtime — mirrors `tools/tf-types-ts/src/core/rpc.ts`.
//!
//! Sits on top of a transport that carries `SessionFrame` values
//! (typically `tf_types::session::SessionState` wrapped by some adapter).
//! Emits typed Rust structs; capability enforcement is pluggable.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use crate::encoding::STANDARD as B64;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
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
    HttpBridge,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum HttpFrame {
    RequestHeaders {
        method: String,
        path: String,
        headers: HashMap<String, String>,
    },
    ResponseHeaders {
        status: u16,
        headers: HashMap<String, String>,
    },
    BodyChunk {
        data: String, // base64
    },
    Trailers {
        headers: HashMap<String, String>,
    },
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

/// Compute `sha256:<hex>` over the concatenation of `chunks`. Used by
/// bulk-transfer client + server to verify chunk integrity.
fn sha256_of_chunks(chunks: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    for c in chunks {
        hasher.update(c);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(7 + digest.len() * 2);
    hex.push_str("sha256:");
    for b in digest.iter() {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

/// Decode a `Value` that is expected to be a base64-encoded byte chunk.
/// Accepts either a `Value::String` (preferred wire form) or a
/// `Value::Array` of integer bytes (best-effort fallback).
fn decode_bulk_chunk(v: &Value) -> Vec<u8> {
    match v {
        Value::String(s) => B64.decode(s.as_bytes()).unwrap_or_default(),
        Value::Array(arr) => arr
            .iter()
            .filter_map(|n| n.as_u64().map(|x| x as u8))
            .collect(),
        _ => Vec::new(),
    }
}

// ---------- Client ----------

type UnaryResp = oneshot::Sender<Result<Value, RpcError>>;

enum Pending {
    Unary(UnaryResp),
    Stream {
        tx: mpsc::UnboundedSender<Result<Value, RpcError>>,
        next_seq: u64,
        last_shell_stream: Option<RemoteShellStream>,
        last_chain: Option<Vec<String>>,
    },
    /// Like `Stream`, but the server emits `RemoteShellOut { stream, data }`
    /// records reconstructed from per-frame `ext.shell_stream` tags.
    RemoteShellStream {
        tx: mpsc::UnboundedSender<Result<RemoteShellOut, RpcError>>,
        next_seq: u64,
        last_stream: RemoteShellStream,
    },
    /// Like `Stream`, but the server emits `AgentSessionFrame { value, chain }`
    /// records reconstructed from per-frame `ext.responsibility_chain`.
    AgentSessionStream {
        tx: mpsc::UnboundedSender<Result<AgentSessionFrame, RpcError>>,
        next_seq: u64,
        last_chain: Vec<String>,
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
                    ext,
                } => {
                    let mut map = pending_for_listener.lock().unwrap();
                    let Some(entry) = map.get_mut(&call_id) else {
                        return;
                    };
                    match entry {
                        Pending::Stream {
                            tx,
                            next_seq,
                            last_shell_stream,
                            last_chain,
                        } => {
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
                            // Stash per-frame ext so the helpers can recover it.
                            if let Some(e) = &ext {
                                if let Some(s) = &e.shell_stream {
                                    *last_shell_stream = Some(s.clone());
                                }
                                if let Some(c) = &e.responsibility_chain {
                                    *last_chain = Some(c.clone());
                                }
                            }
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
                        Pending::RemoteShellStream {
                            tx,
                            next_seq,
                            last_stream,
                        } => {
                            if seq < 0 {
                                if !more {
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
                            let stream_tag = ext
                                .as_ref()
                                .and_then(|e| e.shell_stream.clone())
                                .unwrap_or_else(|| last_stream.clone());
                            *last_stream = stream_tag.clone();
                            if more {
                                if let Some(v) = value {
                                    let bytes = decode_bulk_chunk(&v);
                                    let _ = tx.send(Ok(RemoteShellOut {
                                        stream: stream_tag,
                                        data: bytes,
                                    }));
                                }
                            } else if let Some(err) = error {
                                let _ = tx.send(Err(err));
                                map.remove(&call_id);
                            } else {
                                map.remove(&call_id);
                            }
                        }
                        Pending::AgentSessionStream {
                            tx,
                            next_seq,
                            last_chain,
                        } => {
                            if seq < 0 {
                                if !more {
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
                            let chain = ext
                                .as_ref()
                                .and_then(|e| e.responsibility_chain.clone())
                                .unwrap_or_else(|| last_chain.clone());
                            *last_chain = chain.clone();
                            if more {
                                if let Some(v) = value {
                                    let _ = tx.send(Ok(AgentSessionFrame {
                                        value: v,
                                        responsibility_chain: chain,
                                    }));
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
            Pending::Stream {
                tx,
                next_seq: 0,
                last_shell_stream: None,
                last_chain: None,
            },
        );
        self.transport.send(encode_rpc(RpcFrame::RpcCall {
            call_id,
            method: method.to_owned(),
            request,
            ext: None,
        }));
        rx
    }

    /// Subscribe — server-streaming variant. The server emits a `seq=-1`
    /// `subscribed` ack frame at the start and a `seq=-1, more=false`
    /// `unsubscribed` trailer at the end. The returned receiver only
    /// yields the real event payloads in between.
    pub fn subscribe_raw(
        &self,
        method: &str,
        request: Value,
        topic: Option<String>,
    ) -> mpsc::UnboundedReceiver<Result<Value, RpcError>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let call_id = new_call_id();
        self.pending.lock().unwrap().insert(
            call_id.clone(),
            Pending::Stream {
                tx,
                next_seq: 0,
                last_shell_stream: None,
                last_chain: None,
            },
        );
        let ext = RpcFrameExt {
            method_kind: Some(RpcMethodKind::Subscribe),
            subscribe_topic: topic,
            ..Default::default()
        };
        self.transport.send(encode_rpc(RpcFrame::RpcCall {
            call_id,
            method: method.to_owned(),
            request,
            ext: Some(ext),
        }));
        rx
    }

    /// Client-streaming. The handler receives the initial `request` plus
    /// every value the caller pushes through `requests_rx`; it returns
    /// the single aggregated response.
    pub fn client_stream_raw(
        &self,
        method: &str,
        request: Value,
        mut requests_rx: mpsc::UnboundedReceiver<Result<Value, RpcError>>,
    ) -> Pin<Box<dyn Future<Output = Result<Value, RpcCallError>> + Send>> {
        let call_id = new_call_id();
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap()
            .insert(call_id.clone(), Pending::Unary(tx));
        let transport = self.transport.clone();
        transport.send(encode_rpc(RpcFrame::RpcCall {
            call_id: call_id.clone(),
            method: method.to_owned(),
            request,
            ext: Some(RpcFrameExt {
                method_kind: Some(RpcMethodKind::ClientStreaming),
                ..Default::default()
            }),
        }));
        let pump_transport = transport.clone();
        let pump_call_id = call_id.clone();
        tokio::spawn(async move {
            let mut seq: u64 = 0;
            while let Some(item) = requests_rx.recv().await {
                match item {
                    Ok(v) => {
                        pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                            call_id: pump_call_id.clone(),
                            seq,
                            more: true,
                            value: Some(v),
                            error: None,
                            ext: None,
                        }));
                        seq += 1;
                    }
                    Err(err) => {
                        pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                            call_id: pump_call_id.clone(),
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
            pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                call_id: pump_call_id,
                seq,
                more: false,
                value: None,
                error: None,
                ext: None,
            }));
        });
        Box::pin(async move {
            match rx.await {
                Ok(Ok(v)) => Ok(v),
                Ok(Err(err)) => Err(err.into()),
                Err(_) => Err(RpcCallError {
                    code: RpcErrorCode::Internal,
                    message: "transport dropped the pending call".into(),
                }),
            }
        })
    }

    /// Bidi-streaming. Returns `(tx, rx)`: caller sends client values into
    /// `tx`, receives server values from `rx`. Closing `tx` ends the
    /// client side; the server's stream end terminates `rx`.
    pub fn bidi_raw(
        &self,
        method: &str,
        request: Value,
    ) -> (
        mpsc::UnboundedSender<Result<Value, RpcError>>,
        mpsc::UnboundedReceiver<Result<Value, RpcError>>,
    ) {
        self.bidi_with_kind(method, request, RpcMethodKind::BidiStreaming, None)
    }

    /// Command-channel — bidi with credit-based backpressure. Server
    /// emits an initial credit grant frame on accept; we surface that as
    /// part of the transport flow but the receiver just sees the data
    /// frames (the credit grant rides on `seq=-1` and is filtered out).
    pub fn command_channel_raw(
        &self,
        method: &str,
        request: Value,
    ) -> (
        mpsc::UnboundedSender<Result<Value, RpcError>>,
        mpsc::UnboundedReceiver<Result<Value, RpcError>>,
    ) {
        self.bidi_with_kind(method, request, RpcMethodKind::CommandChannel, None)
    }

    fn bidi_with_kind(
        &self,
        method: &str,
        request: Value,
        kind: RpcMethodKind,
        topic: Option<String>,
    ) -> (
        mpsc::UnboundedSender<Result<Value, RpcError>>,
        mpsc::UnboundedReceiver<Result<Value, RpcError>>,
    ) {
        let call_id = new_call_id();
        let (server_tx, server_rx) = mpsc::unbounded_channel();
        self.pending.lock().unwrap().insert(
            call_id.clone(),
            Pending::Stream {
                tx: server_tx,
                next_seq: 0,
                last_shell_stream: None,
                last_chain: None,
            },
        );
        let ext = RpcFrameExt {
            method_kind: Some(kind.clone()),
            subscribe_topic: topic,
            ..Default::default()
        };
        self.transport.send(encode_rpc(RpcFrame::RpcCall {
            call_id: call_id.clone(),
            method: method.to_owned(),
            request,
            ext: Some(ext.clone()),
        }));
        let (client_tx, mut client_rx) = mpsc::unbounded_channel::<Result<Value, RpcError>>();
        let pump_transport = self.transport.clone();
        let pump_call_id = call_id.clone();
        tokio::spawn(async move {
            let mut seq: u64 = 0;
            while let Some(item) = client_rx.recv().await {
                match item {
                    Ok(v) => {
                        pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                            call_id: pump_call_id.clone(),
                            seq,
                            more: true,
                            value: Some(v),
                            error: None,
                            ext: Some(ext.clone()),
                        }));
                        seq += 1;
                    }
                    Err(err) => {
                        pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                            call_id: pump_call_id.clone(),
                            seq,
                            more: false,
                            value: None,
                            error: Some(err),
                            ext: Some(ext.clone()),
                        }));
                        return;
                    }
                }
            }
            pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                call_id: pump_call_id,
                seq,
                more: false,
                value: None,
                error: None,
                ext: Some(ext),
            }));
        });
        (client_tx, server_rx)
    }

    /// Bulk-transfer — client-streamed byte chunks with a final SHA-256
    /// hash assertion. The client computes the hash up-front and ships it
    /// in `ext.bulk.expected_hash`; the server recomputes and compares.
    pub fn bulk_transfer_raw(
        &self,
        method: &str,
        request: Value,
        chunks: &[Vec<u8>],
    ) -> Pin<Box<dyn Future<Output = Result<Value, RpcCallError>> + Send>> {
        let expected_hash = sha256_of_chunks(chunks);
        let call_id = new_call_id();
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap()
            .insert(call_id.clone(), Pending::Unary(tx));
        let transport = self.transport.clone();
        let total_chunks = chunks.len() as u32;
        transport.send(encode_rpc(RpcFrame::RpcCall {
            call_id: call_id.clone(),
            method: method.to_owned(),
            request,
            ext: Some(RpcFrameExt {
                method_kind: Some(RpcMethodKind::BulkTransfer),
                bulk: Some(RpcBulkExt {
                    chunk_index: None,
                    total_chunks: Some(total_chunks),
                    expected_hash: Some(expected_hash),
                }),
                ..Default::default()
            }),
        }));
        let owned_chunks: Vec<Vec<u8>> = chunks.to_vec();
        let pump_transport = transport.clone();
        let pump_call_id = call_id.clone();
        tokio::spawn(async move {
            // Yield once so the server has time to register the inflight
            // call before chunks start arriving.
            tokio::task::yield_now().await;
            let mut seq: u64 = 0;
            for chunk in owned_chunks.iter() {
                let encoded = B64.encode(chunk);
                pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                    call_id: pump_call_id.clone(),
                    seq,
                    more: true,
                    value: Some(Value::String(encoded)),
                    error: None,
                    ext: Some(RpcFrameExt {
                        method_kind: Some(RpcMethodKind::BulkTransfer),
                        bulk: Some(RpcBulkExt {
                            chunk_index: Some(seq as u32),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                }));
                seq += 1;
            }
            pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                call_id: pump_call_id,
                seq,
                more: false,
                value: None,
                error: None,
                ext: Some(RpcFrameExt {
                    method_kind: Some(RpcMethodKind::BulkTransfer),
                    ..Default::default()
                }),
            }));
        });
        Box::pin(async move {
            match rx.await {
                Ok(Ok(v)) => Ok(v),
                Ok(Err(err)) => Err(err.into()),
                Err(_) => Err(RpcCallError {
                    code: RpcErrorCode::Internal,
                    message: "transport dropped the pending call".into(),
                }),
            }
        })
    }

    /// Telemetry — push-only client-streaming with no aggregated response.
    /// The runtime emits a closing `rpc-response status=ok` with
    /// `ext.streaming_priority` set so the future resolves cleanly.
    pub fn telemetry_raw(
        &self,
        method: &str,
        request: Value,
        mut frames_rx: mpsc::UnboundedReceiver<Result<Value, RpcError>>,
        priority: StreamingPriority,
    ) -> Pin<Box<dyn Future<Output = Result<(), RpcCallError>> + Send>> {
        let call_id = new_call_id();
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap()
            .insert(call_id.clone(), Pending::Unary(tx));
        let transport = self.transport.clone();
        let call_ext = RpcFrameExt {
            method_kind: Some(RpcMethodKind::Telemetry),
            streaming_priority: Some(priority.clone()),
            ..Default::default()
        };
        transport.send(encode_rpc(RpcFrame::RpcCall {
            call_id: call_id.clone(),
            method: method.to_owned(),
            request,
            ext: Some(call_ext),
        }));
        let pump_transport = transport.clone();
        let pump_call_id = call_id.clone();
        let pump_priority = priority;
        tokio::spawn(async move {
            let mut seq: u64 = 0;
            while let Some(item) = frames_rx.recv().await {
                match item {
                    Ok(v) => {
                        pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                            call_id: pump_call_id.clone(),
                            seq,
                            more: true,
                            value: Some(v),
                            error: None,
                            ext: Some(RpcFrameExt {
                                method_kind: Some(RpcMethodKind::Telemetry),
                                streaming_priority: Some(pump_priority.clone()),
                                ..Default::default()
                            }),
                        }));
                        seq += 1;
                    }
                    Err(err) => {
                        pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                            call_id: pump_call_id.clone(),
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
            pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                call_id: pump_call_id,
                seq,
                more: false,
                value: None,
                error: None,
                ext: Some(RpcFrameExt {
                    method_kind: Some(RpcMethodKind::Telemetry),
                    ..Default::default()
                }),
            }));
        });
        Box::pin(async move {
            match rx.await {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(err)) => Err(err.into()),
                Err(_) => Err(RpcCallError {
                    code: RpcErrorCode::Internal,
                    message: "transport dropped the pending call".into(),
                }),
            }
        })
    }

    /// Remote-shell — client emits stdin chunks, server emits
    /// `(stream, data)` records tagged stdin/stdout/stderr.
    pub fn remote_shell_raw(
        &self,
        method: &str,
        request: Value,
        mut stdin_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> mpsc::UnboundedReceiver<Result<RemoteShellOut, RpcError>> {
        let call_id = new_call_id();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        self.pending.lock().unwrap().insert(
            call_id.clone(),
            Pending::RemoteShellStream {
                tx: out_tx,
                next_seq: 0,
                last_stream: RemoteShellStream::Stdout,
            },
        );
        let transport = self.transport.clone();
        transport.send(encode_rpc(RpcFrame::RpcCall {
            call_id: call_id.clone(),
            method: method.to_owned(),
            request,
            ext: Some(RpcFrameExt {
                method_kind: Some(RpcMethodKind::RemoteShell),
                ..Default::default()
            }),
        }));
        let pump_transport = transport.clone();
        let pump_call_id = call_id.clone();
        tokio::spawn(async move {
            let mut seq: u64 = 0;
            while let Some(chunk) = stdin_rx.recv().await {
                pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                    call_id: pump_call_id.clone(),
                    seq,
                    more: true,
                    value: Some(Value::String(B64.encode(&chunk))),
                    error: None,
                    ext: Some(RpcFrameExt {
                        method_kind: Some(RpcMethodKind::RemoteShell),
                        shell_stream: Some(RemoteShellStream::Stdin),
                        ..Default::default()
                    }),
                }));
                seq += 1;
            }
            pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                call_id: pump_call_id,
                seq,
                more: false,
                value: None,
                error: None,
                ext: Some(RpcFrameExt {
                    method_kind: Some(RpcMethodKind::RemoteShell),
                    ..Default::default()
                }),
            }));
        });
        out_rx
    }

    /// Agent-session — bidi that propagates a delegation chain on every
    /// frame. The handler receives `{value, responsibility_chain}` records
    /// and emits the same shape; the chain is copied into
    /// `ext.responsibility_chain` on each wire frame.
    pub fn agent_session_raw(
        &self,
        method: &str,
        request: Value,
        initial_chain: Vec<String>,
        mut frames_rx: mpsc::UnboundedReceiver<AgentSessionFrame>,
    ) -> mpsc::UnboundedReceiver<Result<AgentSessionFrame, RpcError>> {
        let call_id = new_call_id();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        self.pending.lock().unwrap().insert(
            call_id.clone(),
            Pending::AgentSessionStream {
                tx: out_tx,
                next_seq: 0,
                last_chain: initial_chain.clone(),
            },
        );
        let transport = self.transport.clone();
        transport.send(encode_rpc(RpcFrame::RpcCall {
            call_id: call_id.clone(),
            method: method.to_owned(),
            request,
            ext: Some(RpcFrameExt {
                method_kind: Some(RpcMethodKind::AgentSession),
                responsibility_chain: Some(initial_chain),
                ..Default::default()
            }),
        }));
        let pump_transport = transport.clone();
        let pump_call_id = call_id.clone();
        tokio::spawn(async move {
            let mut seq: u64 = 0;
            while let Some(frame) = frames_rx.recv().await {
                pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                    call_id: pump_call_id.clone(),
                    seq,
                    more: true,
                    value: Some(frame.value),
                    error: None,
                    ext: Some(RpcFrameExt {
                        method_kind: Some(RpcMethodKind::AgentSession),
                        responsibility_chain: Some(frame.responsibility_chain),
                        ..Default::default()
                    }),
                }));
                seq += 1;
            }
            pump_transport.send(encode_rpc(RpcFrame::RpcClientStream {
                call_id: pump_call_id,
                seq,
                more: false,
                value: None,
                error: None,
                ext: Some(RpcFrameExt {
                    method_kind: Some(RpcMethodKind::AgentSession),
                    ..Default::default()
                }),
            }));
        });
        out_rx
    }
}

// ---------- Server ----------

pub struct RpcContext {
    pub caller_actor: String,
    pub method: String,
    pub call_id: String,
    /// Initial responsibility chain from `rpc-call.ext.responsibility_chain`,
    /// captured for agent-session calls. Empty for other kinds.
    pub initial_chain: Vec<String>,
    /// Subscription topic from `rpc-call.ext.subscribe_topic`, captured
    /// for subscribe calls. None for other kinds.
    pub subscribe_topic: Option<String>,
}

pub type UnaryHandler = Arc<
    dyn Fn(Value, RpcContext) -> Pin<Box<dyn Future<Output = Result<Value, RpcError>> + Send>>
        + Send
        + Sync,
>;

pub type StreamHandler = Arc<
    dyn Fn(
            Value,
            RpcContext,
            mpsc::UnboundedSender<Result<Value, RpcError>>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Subscribe handler — same shape as a server-streaming handler. The
/// runtime brackets the stream with `subscribed`/`unsubscribed` ack
/// frames automatically.
pub type SubscribeHandler = StreamHandler;

/// Client-streaming handler. Receives the initial request plus an
/// `UnboundedReceiver` of streamed client values, returns a single
/// aggregated response.
pub type ClientStreamHandler = Arc<
    dyn Fn(
            Value,
            RpcContext,
            mpsc::UnboundedReceiver<Result<Value, RpcError>>,
        ) -> Pin<Box<dyn Future<Output = Result<Value, RpcError>> + Send>>
        + Send
        + Sync,
>;

/// Bidi-streaming handler. Receives an inbound receiver and an outbound
/// sender; drives both independently. Returns when the handler is done
/// emitting (the runtime wires the sender to RpcStream frames).
pub type BidiHandler = Arc<
    dyn Fn(
            Value,
            RpcContext,
            mpsc::UnboundedReceiver<Result<Value, RpcError>>,
            mpsc::UnboundedSender<Result<Value, RpcError>>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Command-channel handler — same shape as `BidiHandler`. The runtime
/// emits an initial credit grant on accept and tags every server frame
/// with `ext.method_kind = command-channel`.
pub type CommandChannelHandler = BidiHandler;

/// Bulk-transfer handler. Receives an inbound receiver of byte chunks
/// (decoded from base64 wire frames) and returns a single receipt. The
/// runtime SHA-256s the concatenation and verifies against the
/// caller-asserted `expected_hash` before emitting the receipt.
pub type BulkTransferHandler = Arc<
    dyn Fn(
            Value,
            RpcContext,
            mpsc::UnboundedReceiver<Vec<u8>>,
        ) -> Pin<Box<dyn Future<Output = Result<Value, RpcError>> + Send>>
        + Send
        + Sync,
>;

/// Telemetry handler — push-only client-streaming with the declared
/// streaming priority surfaced in `ctx`. Returns `Ok(())` to commit a
/// success closing frame, `Err` to fail the call.
pub type TelemetryHandler = Arc<
    dyn Fn(
            Value,
            RpcContext,
            StreamingPriority,
            mpsc::UnboundedReceiver<Result<Value, RpcError>>,
        ) -> Pin<Box<dyn Future<Output = Result<(), RpcError>> + Send>>
        + Send
        + Sync,
>;

/// Remote-shell handler. Receives an inbound receiver of stdin byte
/// chunks and an outbound sender for `RemoteShellOut { stream, data }`
/// records; the runtime preserves the stream tag end-to-end.
pub type RemoteShellHandler = Arc<
    dyn Fn(
            Value,
            RpcContext,
            mpsc::UnboundedReceiver<Vec<u8>>,
            mpsc::UnboundedSender<RemoteShellOut>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Agent-session handler. Both directions carry
/// `AgentSessionFrame { value, responsibility_chain }` records. The
/// initial chain from the rpc-call's ext is surfaced in
/// `ctx.initial_chain`; per-frame chains override it.
pub type AgentSessionHandler = Arc<
    dyn Fn(
            Value,
            RpcContext,
            mpsc::UnboundedReceiver<AgentSessionFrame>,
            mpsc::UnboundedSender<AgentSessionFrame>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Http-bridge handler. Both directions carry `HttpFrame` enums
/// (headers, chunks, trailers).
pub type HttpBridgeHandler = Arc<
    dyn Fn(
            Value,
            RpcContext,
            mpsc::UnboundedReceiver<HttpFrame>,
            mpsc::UnboundedSender<HttpFrame>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone, Debug)]
pub struct RemoteShellOut {
    pub stream: RemoteShellStream,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct AgentSessionFrame {
    pub value: Value,
    pub responsibility_chain: Vec<String>,
}

enum Handler {
    Unary {
        capability: String,
        handler: UnaryHandler,
    },
    Stream {
        capability: String,
        handler: StreamHandler,
    },
    Subscribe {
        capability: String,
        handler: SubscribeHandler,
    },
    ClientStream {
        capability: String,
        handler: ClientStreamHandler,
    },
    Bidi {
        capability: String,
        handler: BidiHandler,
    },
    CommandChannel {
        capability: String,
        handler: CommandChannelHandler,
        initial_credit: u32,
    },
    BulkTransfer {
        capability: String,
        handler: BulkTransferHandler,
    },
    Telemetry {
        capability: String,
        handler: TelemetryHandler,
        priority: StreamingPriority,
    },
    RemoteShell {
        capability: String,
        handler: RemoteShellHandler,
    },
    AgentSession {
        capability: String,
        handler: AgentSessionHandler,
    },
    HttpBridge {
        capability: String,
        handler: HttpBridgeHandler,
    },
}

impl Handler {
    fn capability(&self) -> &str {
        match self {
            Handler::Unary { capability, .. }
            | Handler::Stream { capability, .. }
            | Handler::Subscribe { capability, .. }
            | Handler::ClientStream { capability, .. }
            | Handler::Bidi { capability, .. }
            | Handler::CommandChannel { capability, .. }
            | Handler::BulkTransfer { capability, .. }
            | Handler::Telemetry { capability, .. }
            | Handler::RemoteShell { capability, .. }
            | Handler::AgentSession { capability, .. }
            | Handler::HttpBridge { capability, .. } => capability,
        }
    }

    /// Whether a permission-denied for this kind should be reported via
    /// rpc-stream (true) or rpc-response (false).
    fn is_streaming(&self) -> bool {
        matches!(
            self,
            Handler::Stream { .. }
                | Handler::Subscribe { .. }
                | Handler::Bidi { .. }
                | Handler::CommandChannel { .. }
                | Handler::RemoteShell { .. }
                | Handler::AgentSession { .. }
                | Handler::HttpBridge { .. }
        )
    }
}

/// Inflight call state. Used to route `rpc-client-stream` frames to the
/// correct per-call queue on the server side.
struct InflightCall {
    push: Arc<dyn Fn(InflightMsg) + Send + Sync>,
}

#[derive(Clone)]
enum InflightMsg {
    Value(Value, Option<RpcFrameExt>),
    Done,
    Error(RpcError),
}

pub struct RpcServer<T: RpcTransport + 'static> {
    transport: Arc<T>,
    handlers: Arc<Mutex<HashMap<String, Arc<Handler>>>>,
    /// Per-call client-stream sinks, keyed by call_id. The on-frame
    /// listener clones this `Arc` to look up + push inbound
    /// rpc-client-stream messages; the dispatchers insert and remove.
    /// Held on the server struct to keep the table alive for the
    /// listener's lifetime.
    #[allow(dead_code)]
    inflight: Arc<Mutex<HashMap<String, InflightCall>>>,
    caller_actor: String,
    enforcer: Arc<dyn CapabilityEnforcer>,
}

impl<T: RpcTransport + 'static> RpcServer<T> {
    pub fn new(
        transport: Arc<T>,
        caller_actor: impl Into<String>,
        enforcer: Arc<dyn CapabilityEnforcer>,
    ) -> Self {
        let handlers: Arc<Mutex<HashMap<String, Arc<Handler>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let inflight: Arc<Mutex<HashMap<String, InflightCall>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let caller_actor: String = caller_actor.into();
        let caller_for_listener = caller_actor.clone();
        let handlers_for_listener = handlers.clone();
        let inflight_for_listener = inflight.clone();
        let enforcer_for_listener = enforcer.clone();
        let transport_for_listener = transport.clone();
        transport.on_frame(Arc::new(move |frame| {
            let rpc = match decode_rpc(frame) {
                Some(r) => r,
                None => return,
            };

            // Route inbound client-stream frames to the matching call.
            if let RpcFrame::RpcClientStream {
                call_id,
                seq: _,
                more,
                value,
                error,
                ext,
            } = &rpc
            {
                let push = {
                    let map = inflight_for_listener.lock().unwrap();
                    map.get(call_id).map(|c| c.push.clone())
                };
                let Some(push) = push else { return };
                if let Some(err) = error.clone() {
                    push(InflightMsg::Error(err));
                } else if *more {
                    if let Some(v) = value.clone() {
                        push(InflightMsg::Value(v, ext.clone()));
                    }
                } else {
                    push(InflightMsg::Done);
                }
                return;
            }

            let RpcFrame::RpcCall {
                call_id,
                method,
                request,
                ext: call_ext,
            } = rpc
            else {
                return;
            };

            let initial_chain = call_ext
                .as_ref()
                .and_then(|e| e.responsibility_chain.clone())
                .unwrap_or_default();
            let subscribe_topic = call_ext.as_ref().and_then(|e| e.subscribe_topic.clone());

            let handler = {
                let map = handlers_for_listener.lock().unwrap();
                map.get(&method).cloned()
            };

            let Some(handler) = handler else {
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

            let capability = handler.capability().to_owned();
            let is_streaming = handler.is_streaming();
            match enforcer_for_listener.check(&caller_for_listener, &method, &capability) {
                CapabilityDecision::Allow => {}
                CapabilityDecision::Deny(reason) => {
                    if is_streaming {
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

            let ctx = RpcContext {
                caller_actor: caller_for_listener.clone(),
                method: method.clone(),
                call_id: call_id.clone(),
                initial_chain,
                subscribe_topic,
            };
            let transport = transport_for_listener.clone();
            let inflight = inflight_for_listener.clone();
            match &*handler {
                Handler::Unary { handler, .. } => {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        dispatch_unary(transport, ctx, request, handler).await;
                    });
                }
                Handler::Stream { handler, .. } => {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        dispatch_server_stream(transport, ctx, request, handler).await;
                    });
                }
                Handler::Subscribe { handler, .. } => {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        dispatch_subscribe(transport, ctx, request, handler).await;
                    });
                }
                Handler::ClientStream { handler, .. } => {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        dispatch_client_stream(transport, inflight, ctx, request, handler).await;
                    });
                }
                Handler::Bidi { handler, .. } => {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        dispatch_bidi(transport, inflight, ctx, request, handler).await;
                    });
                }
                Handler::CommandChannel {
                    handler,
                    initial_credit,
                    ..
                } => {
                    let handler = handler.clone();
                    let credit = *initial_credit;
                    tokio::spawn(async move {
                        dispatch_command_channel(
                            transport, inflight, ctx, request, handler, credit,
                        )
                        .await;
                    });
                }
                Handler::BulkTransfer { handler, .. } => {
                    let handler = handler.clone();
                    let expected_hash = call_ext
                        .as_ref()
                        .and_then(|e| e.bulk.as_ref())
                        .and_then(|b| b.expected_hash.clone());
                    tokio::spawn(async move {
                        dispatch_bulk_transfer(
                            transport,
                            inflight,
                            ctx,
                            request,
                            handler,
                            expected_hash,
                        )
                        .await;
                    });
                }
                Handler::Telemetry {
                    handler, priority, ..
                } => {
                    let handler = handler.clone();
                    let priority = priority.clone();
                    tokio::spawn(async move {
                        dispatch_telemetry(transport, inflight, ctx, request, handler, priority)
                            .await;
                    });
                }
                Handler::RemoteShell { handler, .. } => {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        dispatch_remote_shell(transport, inflight, ctx, request, handler).await;
                    });
                }
                Handler::AgentSession { handler, .. } => {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        dispatch_agent_session(transport, inflight, ctx, request, handler).await;
                    });
                }
                Handler::HttpBridge { handler, .. } => {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        dispatch_http_bridge(transport, inflight, ctx, request, handler).await;
                    });
                }
            }
        }));
        RpcServer {
            transport,
            handlers,
            inflight,
            caller_actor,
            enforcer,
        }
    }

    pub fn register_unary(
        &self,
        method: impl Into<String>,
        capability: impl Into<String>,
        handler: UnaryHandler,
    ) {
        self.handlers.lock().unwrap().insert(
            method.into(),
            Arc::new(Handler::Unary {
                capability: capability.into(),
                handler,
            }),
        );
    }

    pub fn register_stream(
        &self,
        method: impl Into<String>,
        capability: impl Into<String>,
        handler: StreamHandler,
    ) {
        self.handlers.lock().unwrap().insert(
            method.into(),
            Arc::new(Handler::Stream {
                capability: capability.into(),
                handler,
            }),
        );
    }

    pub fn register_subscribe(
        &self,
        method: impl Into<String>,
        capability: impl Into<String>,
        handler: SubscribeHandler,
    ) {
        self.handlers.lock().unwrap().insert(
            method.into(),
            Arc::new(Handler::Subscribe {
                capability: capability.into(),
                handler,
            }),
        );
    }

    pub fn register_client_stream(
        &self,
        method: impl Into<String>,
        capability: impl Into<String>,
        handler: ClientStreamHandler,
    ) {
        self.handlers.lock().unwrap().insert(
            method.into(),
            Arc::new(Handler::ClientStream {
                capability: capability.into(),
                handler,
            }),
        );
    }

    pub fn register_bidi(
        &self,
        method: impl Into<String>,
        capability: impl Into<String>,
        handler: BidiHandler,
    ) {
        self.handlers.lock().unwrap().insert(
            method.into(),
            Arc::new(Handler::Bidi {
                capability: capability.into(),
                handler,
            }),
        );
    }

    pub fn register_command_channel(
        &self,
        method: impl Into<String>,
        capability: impl Into<String>,
        handler: CommandChannelHandler,
        initial_credit: u32,
    ) {
        self.handlers.lock().unwrap().insert(
            method.into(),
            Arc::new(Handler::CommandChannel {
                capability: capability.into(),
                handler,
                initial_credit,
            }),
        );
    }

    pub fn register_bulk_transfer(
        &self,
        method: impl Into<String>,
        capability: impl Into<String>,
        handler: BulkTransferHandler,
    ) {
        self.handlers.lock().unwrap().insert(
            method.into(),
            Arc::new(Handler::BulkTransfer {
                capability: capability.into(),
                handler,
            }),
        );
    }

    pub fn register_telemetry(
        &self,
        method: impl Into<String>,
        capability: impl Into<String>,
        handler: TelemetryHandler,
        priority: StreamingPriority,
    ) {
        self.handlers.lock().unwrap().insert(
            method.into(),
            Arc::new(Handler::Telemetry {
                capability: capability.into(),
                handler,
                priority,
            }),
        );
    }

    pub fn register_remote_shell(
        &self,
        method: impl Into<String>,
        capability: impl Into<String>,
        handler: RemoteShellHandler,
    ) {
        self.handlers.lock().unwrap().insert(
            method.into(),
            Arc::new(Handler::RemoteShell {
                capability: capability.into(),
                handler,
            }),
        );
    }

    pub fn register_agent_session(
        &self,
        method: impl Into<String>,
        capability: impl Into<String>,
        handler: AgentSessionHandler,
    ) {
        self.handlers.lock().unwrap().insert(
            method.into(),
            Arc::new(Handler::AgentSession {
                capability: capability.into(),
                handler,
            }),
        );
    }

    pub fn register_http_bridge(
        &self,
        method: impl Into<String>,
        capability: impl Into<String>,
        handler: HttpBridgeHandler,
    ) {
        self.handlers.lock().unwrap().insert(
            method.into(),
            Arc::new(Handler::HttpBridge {
                capability: capability.into(),
                handler,
            }),
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

// ---------- Per-kind dispatchers ----------

async fn dispatch_unary<T: RpcTransport + 'static>(
    transport: Arc<T>,
    ctx: RpcContext,
    request: Value,
    handler: UnaryHandler,
) {
    let call_id = ctx.call_id.clone();
    match handler(request, ctx).await {
        Ok(v) => {
            transport.send(encode_rpc(RpcFrame::RpcResponse {
                call_id,
                status: ResponseStatus::Ok,
                response: Some(v),
                error: None,
                ext: None,
            }));
        }
        Err(err) => {
            transport.send(encode_rpc(RpcFrame::RpcResponse {
                call_id,
                status: ResponseStatus::Error,
                response: None,
                error: Some(err),
                ext: None,
            }));
        }
    }
}

async fn run_server_stream_loop<T: RpcTransport + 'static>(
    transport: &Arc<T>,
    call_id: &str,
    method_kind: Option<RpcMethodKind>,
    mut rx: mpsc::UnboundedReceiver<Result<Value, RpcError>>,
) {
    let ext = method_kind.clone().map(|k| RpcFrameExt {
        method_kind: Some(k),
        ..Default::default()
    });
    let mut seq: i64 = 0;
    while let Some(item) = rx.recv().await {
        match item {
            Ok(v) => {
                transport.send(encode_rpc(RpcFrame::RpcStream {
                    call_id: call_id.to_owned(),
                    seq,
                    more: true,
                    value: Some(v),
                    error: None,
                    ext: ext.clone(),
                }));
                seq += 1;
            }
            Err(err) => {
                transport.send(encode_rpc(RpcFrame::RpcStream {
                    call_id: call_id.to_owned(),
                    seq,
                    more: false,
                    value: None,
                    error: Some(err),
                    ext: ext.clone(),
                }));
                return;
            }
        }
    }
    transport.send(encode_rpc(RpcFrame::RpcStream {
        call_id: call_id.to_owned(),
        seq,
        more: false,
        value: None,
        error: None,
        ext: ext.clone(),
    }));
}

async fn dispatch_server_stream<T: RpcTransport + 'static>(
    transport: Arc<T>,
    ctx: RpcContext,
    request: Value,
    handler: StreamHandler,
) {
    let call_id = ctx.call_id.clone();
    let (tx, rx) = mpsc::unbounded_channel::<Result<Value, RpcError>>();
    let fut = handler(request, ctx, tx);
    tokio::spawn(fut);
    run_server_stream_loop(
        &transport,
        &call_id,
        Some(RpcMethodKind::ServerStreaming),
        rx,
    )
    .await;
}

async fn dispatch_subscribe<T: RpcTransport + 'static>(
    transport: Arc<T>,
    ctx: RpcContext,
    request: Value,
    handler: SubscribeHandler,
) {
    let call_id = ctx.call_id.clone();
    let topic = ctx.subscribe_topic.clone();
    // Emit explicit `subscribed` ack so the client can confirm the
    // subscription was accepted before any events arrive.
    transport.send(encode_rpc(RpcFrame::RpcStream {
        call_id: call_id.clone(),
        seq: -1,
        more: true,
        value: None,
        error: None,
        ext: Some(RpcFrameExt {
            method_kind: Some(RpcMethodKind::Subscribe),
            ack: Some("subscribed".into()),
            subscribe_topic: topic,
            ..Default::default()
        }),
    }));
    let (tx, rx) = mpsc::unbounded_channel::<Result<Value, RpcError>>();
    let fut = handler(request, ctx, tx);
    tokio::spawn(fut);
    run_server_stream_loop(&transport, &call_id, Some(RpcMethodKind::Subscribe), rx).await;
    transport.send(encode_rpc(RpcFrame::RpcStream {
        call_id,
        seq: -1,
        more: false,
        value: None,
        error: None,
        ext: Some(RpcFrameExt {
            method_kind: Some(RpcMethodKind::Subscribe),
            ack: Some("unsubscribed".into()),
            ..Default::default()
        }),
    }));
}

/// Install a client-stream pipe in the inflight map, returning a receiver
/// that yields `(value, ext)` pairs in order plus a guard that removes
/// the entry on drop.
fn install_client_pipe(
    inflight: &Arc<Mutex<HashMap<String, InflightCall>>>,
    call_id: &str,
) -> mpsc::UnboundedReceiver<InflightMsg> {
    let (tx, rx) = mpsc::unbounded_channel::<InflightMsg>();
    let push = Arc::new(move |msg: InflightMsg| {
        let _ = tx.send(msg);
    });
    inflight
        .lock()
        .unwrap()
        .insert(call_id.to_owned(), InflightCall { push });
    rx
}

fn remove_inflight(inflight: &Arc<Mutex<HashMap<String, InflightCall>>>, call_id: &str) {
    inflight.lock().unwrap().remove(call_id);
}

/// Adapt an `UnboundedReceiver<InflightMsg>` into an
/// `UnboundedReceiver<Result<Value, RpcError>>` that strips the ext.
fn pipe_to_value_rx(
    mut raw_rx: mpsc::UnboundedReceiver<InflightMsg>,
) -> mpsc::UnboundedReceiver<Result<Value, RpcError>> {
    let (tx, rx) = mpsc::unbounded_channel::<Result<Value, RpcError>>();
    tokio::spawn(async move {
        while let Some(msg) = raw_rx.recv().await {
            match msg {
                InflightMsg::Value(v, _) => {
                    if tx.send(Ok(v)).is_err() {
                        return;
                    }
                }
                InflightMsg::Done => return,
                InflightMsg::Error(err) => {
                    let _ = tx.send(Err(err));
                    return;
                }
            }
        }
    });
    rx
}

async fn dispatch_client_stream<T: RpcTransport + 'static>(
    transport: Arc<T>,
    inflight: Arc<Mutex<HashMap<String, InflightCall>>>,
    ctx: RpcContext,
    request: Value,
    handler: ClientStreamHandler,
) {
    let call_id = ctx.call_id.clone();
    let raw_rx = install_client_pipe(&inflight, &call_id);
    let value_rx = pipe_to_value_rx(raw_rx);
    let result = handler(request, ctx, value_rx).await;
    remove_inflight(&inflight, &call_id);
    match result {
        Ok(v) => transport.send(encode_rpc(RpcFrame::RpcResponse {
            call_id,
            status: ResponseStatus::Ok,
            response: Some(v),
            error: None,
            ext: None,
        })),
        Err(err) => transport.send(encode_rpc(RpcFrame::RpcResponse {
            call_id,
            status: ResponseStatus::Error,
            response: None,
            error: Some(err),
            ext: None,
        })),
    }
}

async fn dispatch_bidi<T: RpcTransport + 'static>(
    transport: Arc<T>,
    inflight: Arc<Mutex<HashMap<String, InflightCall>>>,
    ctx: RpcContext,
    request: Value,
    handler: BidiHandler,
) {
    let call_id = ctx.call_id.clone();
    let raw_rx = install_client_pipe(&inflight, &call_id);
    let value_rx = pipe_to_value_rx(raw_rx);
    let (server_tx, server_rx) = mpsc::unbounded_channel::<Result<Value, RpcError>>();
    let fut = handler(request, ctx, value_rx, server_tx);
    tokio::spawn(fut);
    run_server_stream_loop(
        &transport,
        &call_id,
        Some(RpcMethodKind::BidiStreaming),
        server_rx,
    )
    .await;
    remove_inflight(&inflight, &call_id);
}

async fn dispatch_command_channel<T: RpcTransport + 'static>(
    transport: Arc<T>,
    inflight: Arc<Mutex<HashMap<String, InflightCall>>>,
    ctx: RpcContext,
    request: Value,
    handler: CommandChannelHandler,
    initial_credit: u32,
) {
    let call_id = ctx.call_id.clone();
    let raw_rx = install_client_pipe(&inflight, &call_id);
    let value_rx = pipe_to_value_rx(raw_rx);
    // Initial credit grant rides on seq=-1, more=true (synthetic ack).
    transport.send(encode_rpc(RpcFrame::RpcStream {
        call_id: call_id.clone(),
        seq: -1,
        more: true,
        value: None,
        error: None,
        ext: Some(RpcFrameExt {
            method_kind: Some(RpcMethodKind::CommandChannel),
            credit: Some(initial_credit),
            ..Default::default()
        }),
    }));
    let (server_tx, mut server_rx) = mpsc::unbounded_channel::<Result<Value, RpcError>>();
    let fut = handler(request, ctx, value_rx, server_tx);
    tokio::spawn(fut);
    let ext = Some(RpcFrameExt {
        method_kind: Some(RpcMethodKind::CommandChannel),
        ..Default::default()
    });
    let mut seq: i64 = 0;
    while let Some(item) = server_rx.recv().await {
        match item {
            Ok(v) => {
                transport.send(encode_rpc(RpcFrame::RpcStream {
                    call_id: call_id.clone(),
                    seq,
                    more: true,
                    value: Some(v),
                    error: None,
                    ext: ext.clone(),
                }));
                seq += 1;
            }
            Err(err) => {
                transport.send(encode_rpc(RpcFrame::RpcStream {
                    call_id: call_id.clone(),
                    seq,
                    more: false,
                    value: None,
                    error: Some(err),
                    ext: ext.clone(),
                }));
                remove_inflight(&inflight, &call_id);
                return;
            }
        }
    }
    transport.send(encode_rpc(RpcFrame::RpcStream {
        call_id: call_id.clone(),
        seq,
        more: false,
        value: None,
        error: None,
        ext,
    }));
    remove_inflight(&inflight, &call_id);
}

async fn dispatch_bulk_transfer<T: RpcTransport + 'static>(
    transport: Arc<T>,
    inflight: Arc<Mutex<HashMap<String, InflightCall>>>,
    ctx: RpcContext,
    request: Value,
    handler: BulkTransferHandler,
    expected_hash: Option<String>,
) {
    let call_id = ctx.call_id.clone();
    let Some(expected_hash) = expected_hash else {
        transport.send(encode_rpc(RpcFrame::RpcResponse {
            call_id,
            status: ResponseStatus::Error,
            response: None,
            error: Some(RpcError {
                code: RpcErrorCode::InvalidArgument,
                message: "bulk-transfer requires ext.bulk.expected_hash".into(),
            }),
            ext: None,
        }));
        return;
    };
    let raw_rx = install_client_pipe(&inflight, &call_id);
    // Tee inbound chunks: hand decoded bytes to the handler, also
    // accumulate them locally to verify the SHA-256 once the client
    // signals end-of-stream.
    let collected: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let collected_for_pump = collected.clone();
    let (handler_tx, handler_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut raw_rx = raw_rx;
    tokio::spawn(async move {
        while let Some(msg) = raw_rx.recv().await {
            match msg {
                InflightMsg::Value(v, _) => {
                    let bytes = decode_bulk_chunk(&v);
                    collected_for_pump.lock().unwrap().push(bytes.clone());
                    if handler_tx.send(bytes).is_err() {
                        return;
                    }
                }
                InflightMsg::Done => return,
                InflightMsg::Error(_) => return,
            }
        }
    });
    let result = handler(request, ctx, handler_rx).await;
    remove_inflight(&inflight, &call_id);
    let actual_hash = {
        let chunks = collected.lock().unwrap();
        sha256_of_chunks(&chunks)
    };
    match result {
        Ok(v) => {
            if actual_hash != expected_hash {
                transport.send(encode_rpc(RpcFrame::RpcResponse {
                    call_id,
                    status: ResponseStatus::Error,
                    response: None,
                    error: Some(RpcError {
                        code: RpcErrorCode::InvalidArgument,
                        message: format!(
                            "bulk-transfer hash mismatch: got {}, expected {}",
                            actual_hash, expected_hash
                        ),
                    }),
                    ext: Some(RpcFrameExt {
                        method_kind: Some(RpcMethodKind::BulkTransfer),
                        bulk: Some(RpcBulkExt {
                            expected_hash: Some(actual_hash),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                }));
                return;
            }
            transport.send(encode_rpc(RpcFrame::RpcResponse {
                call_id,
                status: ResponseStatus::Ok,
                response: Some(v),
                error: None,
                ext: Some(RpcFrameExt {
                    method_kind: Some(RpcMethodKind::BulkTransfer),
                    bulk: Some(RpcBulkExt {
                        expected_hash: Some(actual_hash),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            }));
        }
        Err(err) => {
            transport.send(encode_rpc(RpcFrame::RpcResponse {
                call_id,
                status: ResponseStatus::Error,
                response: None,
                error: Some(err),
                ext: None,
            }));
        }
    }
}

async fn dispatch_telemetry<T: RpcTransport + 'static>(
    transport: Arc<T>,
    inflight: Arc<Mutex<HashMap<String, InflightCall>>>,
    ctx: RpcContext,
    request: Value,
    handler: TelemetryHandler,
    priority: StreamingPriority,
) {
    let call_id = ctx.call_id.clone();
    let raw_rx = install_client_pipe(&inflight, &call_id);
    let value_rx = pipe_to_value_rx(raw_rx);
    let result = handler(request, ctx, priority.clone(), value_rx).await;
    remove_inflight(&inflight, &call_id);
    let ext = Some(RpcFrameExt {
        method_kind: Some(RpcMethodKind::Telemetry),
        streaming_priority: Some(priority),
        ..Default::default()
    });
    match result {
        Ok(()) => transport.send(encode_rpc(RpcFrame::RpcResponse {
            call_id,
            status: ResponseStatus::Ok,
            response: Some(Value::Null),
            error: None,
            ext,
        })),
        Err(err) => transport.send(encode_rpc(RpcFrame::RpcResponse {
            call_id,
            status: ResponseStatus::Error,
            response: None,
            error: Some(err),
            ext,
        })),
    }
}

async fn dispatch_remote_shell<T: RpcTransport + 'static>(
    transport: Arc<T>,
    inflight: Arc<Mutex<HashMap<String, InflightCall>>>,
    ctx: RpcContext,
    request: Value,
    handler: RemoteShellHandler,
) {
    let call_id = ctx.call_id.clone();
    let raw_rx = install_client_pipe(&inflight, &call_id);
    // Stdin pipe — only accept frames whose ext.shell_stream == Stdin (or
    // missing for compat). Decode base64 → bytes.
    let (stdin_tx, stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut raw_rx = raw_rx;
    tokio::spawn(async move {
        while let Some(msg) = raw_rx.recv().await {
            match msg {
                InflightMsg::Value(v, ext) => {
                    let tag = ext
                        .as_ref()
                        .and_then(|e| e.shell_stream.clone())
                        .unwrap_or(RemoteShellStream::Stdin);
                    if !matches!(tag, RemoteShellStream::Stdin) {
                        // Reject non-stdin tags silently for now (the client
                        // helper only ever emits stdin).
                        continue;
                    }
                    let bytes = decode_bulk_chunk(&v);
                    if stdin_tx.send(bytes).is_err() {
                        return;
                    }
                }
                InflightMsg::Done | InflightMsg::Error(_) => return,
            }
        }
    });
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<RemoteShellOut>();
    let fut = handler(request, ctx, stdin_rx, out_tx);
    tokio::spawn(fut);
    let mut seq: i64 = 0;
    while let Some(frame) = out_rx.recv().await {
        let encoded = B64.encode(&frame.data);
        transport.send(encode_rpc(RpcFrame::RpcStream {
            call_id: call_id.clone(),
            seq,
            more: true,
            value: Some(Value::String(encoded)),
            error: None,
            ext: Some(RpcFrameExt {
                method_kind: Some(RpcMethodKind::RemoteShell),
                shell_stream: Some(frame.stream),
                ..Default::default()
            }),
        }));
        seq += 1;
    }
    transport.send(encode_rpc(RpcFrame::RpcStream {
        call_id: call_id.clone(),
        seq,
        more: false,
        value: None,
        error: None,
        ext: Some(RpcFrameExt {
            method_kind: Some(RpcMethodKind::RemoteShell),
            ..Default::default()
        }),
    }));
    remove_inflight(&inflight, &call_id);
}

async fn dispatch_agent_session<T: RpcTransport + 'static>(
    transport: Arc<T>,
    inflight: Arc<Mutex<HashMap<String, InflightCall>>>,
    ctx: RpcContext,
    request: Value,
    handler: AgentSessionHandler,
) {
    let call_id = ctx.call_id.clone();
    let initial_chain = ctx.initial_chain.clone();
    let raw_rx = install_client_pipe(&inflight, &call_id);
    let (frames_tx, frames_rx) = mpsc::unbounded_channel::<AgentSessionFrame>();
    let initial_for_pump = initial_chain.clone();
    let mut raw_rx = raw_rx;
    tokio::spawn(async move {
        while let Some(msg) = raw_rx.recv().await {
            match msg {
                InflightMsg::Value(v, ext) => {
                    let chain = ext
                        .as_ref()
                        .and_then(|e| e.responsibility_chain.clone())
                        .unwrap_or_else(|| initial_for_pump.clone());
                    if frames_tx
                        .send(AgentSessionFrame {
                            value: v,
                            responsibility_chain: chain,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                InflightMsg::Done | InflightMsg::Error(_) => return,
            }
        }
    });
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<AgentSessionFrame>();
    let fut = handler(request, ctx, frames_rx, out_tx);
    tokio::spawn(fut);
    let mut seq: i64 = 0;
    while let Some(frame) = out_rx.recv().await {
        transport.send(encode_rpc(RpcFrame::RpcStream {
            call_id: call_id.clone(),
            seq,
            more: true,
            value: Some(frame.value),
            error: None,
            ext: Some(RpcFrameExt {
                method_kind: Some(RpcMethodKind::AgentSession),
                responsibility_chain: Some(frame.responsibility_chain),
                ..Default::default()
            }),
        }));
        seq += 1;
    }
    transport.send(encode_rpc(RpcFrame::RpcStream {
        call_id: call_id.clone(),
        seq,
        more: false,
        value: None,
        error: None,
        ext: Some(RpcFrameExt {
            method_kind: Some(RpcMethodKind::AgentSession),
            ..Default::default()
        }),
    }));
    remove_inflight(&inflight, &call_id);
}

async fn dispatch_http_bridge<T: RpcTransport>(
    transport: Arc<T>,
    inflight: Arc<Mutex<HashMap<String, InflightCall>>>,
    ctx: RpcContext,
    request: Value,
    handler: HttpBridgeHandler,
) {
    let call_id = ctx.call_id.clone();
    let mut rx = install_client_pipe(&inflight, &call_id);

    let (frames_tx, frames_rx) = mpsc::unbounded_channel::<HttpFrame>();
    let inflight_inner = inflight.clone();
    let call_id_inner = call_id.clone();

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                InflightMsg::Value(v, _) => {
                    if let Ok(frame) = serde_json::from_value::<HttpFrame>(v) {
                        let _ = frames_tx.send(frame);
                    }
                }
                InflightMsg::Done | InflightMsg::Error(_) => {
                    remove_inflight(&inflight_inner, &call_id_inner);
                    return;
                }
            }
        }
    });

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<HttpFrame>();
    let fut = handler(request, ctx, frames_rx, out_tx);
    tokio::spawn(fut);

    let mut seq: i64 = 0;
    while let Some(frame) = out_rx.recv().await {
        transport.send(encode_rpc(RpcFrame::RpcStream {
            call_id: call_id.clone(),
            seq,
            more: true,
            value: Some(serde_json::to_value(frame).unwrap_or_default()),
            error: None,
            ext: Some(RpcFrameExt {
                method_kind: Some(RpcMethodKind::HttpBridge),
                ..Default::default()
            }),
        }));
        seq += 1;
    }
    transport.send(encode_rpc(RpcFrame::RpcStream {
        call_id: call_id.clone(),
        seq,
        more: false,
        value: None,
        error: None,
        ext: Some(RpcFrameExt {
            method_kind: Some(RpcMethodKind::HttpBridge),
            ..Default::default()
        }),
    }));
    remove_inflight(&inflight, &call_id);
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
            RpcMethodKind::HttpBridge,
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
        assert!(json.contains("http-bridge"));
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
