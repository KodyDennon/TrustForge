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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RpcFrame {
    RpcCall {
        call_id: String,
        method: String,
        request: Value,
    },
    RpcResponse {
        call_id: String,
        status: ResponseStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        response: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<RpcError>,
    },
    RpcStream {
        call_id: String,
        seq: u64,
        more: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<RpcError>,
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
                } => {
                    let mut map = pending_for_listener.lock().unwrap();
                    if let Some(entry) = map.get_mut(&call_id) {
                        match entry {
                            Pending::Stream { tx, next_seq } => {
                                if seq != *next_seq {
                                    let _ = tx.send(Err(RpcError {
                                        code: RpcErrorCode::Internal,
                                        message: format!(
                                            "stream seq mismatch: expected {}, got {}",
                                            next_seq, seq
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
                RpcFrame::RpcCall { .. } => {
                    // client side ignores inbound rpc-call frames
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
                        })),
                        Err(err) => transport_in_task.send(encode_rpc(RpcFrame::RpcResponse {
                            call_id,
                            status: ResponseStatus::Error,
                            response: None,
                            error: Some(err),
                        })),
                    }
                });
            } else {
                let handler = stream_handler.unwrap();
                tokio::spawn(async move {
                    let (tx, mut rx) = mpsc::unbounded_channel::<Result<Value, RpcError>>();
                    let fut = handler(request, ctx, tx);
                    tokio::spawn(fut);
                    let mut seq: u64 = 0;
                    while let Some(item) = rx.recv().await {
                        match item {
                            Ok(v) => {
                                transport_in_task.send(encode_rpc(RpcFrame::RpcStream {
                                    call_id: call_id.clone(),
                                    seq,
                                    more: true,
                                    value: Some(v),
                                    error: None,
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
}
