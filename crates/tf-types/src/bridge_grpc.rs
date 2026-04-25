//! gRPC bridge — mirror of TS `bridge-grpc.ts`.
//!
//! Wraps a caller-supplied gRPC channel adapter and exposes it as a
//! ProofRPC `RpcTransport`. Frames are serialised as canonical JSON
//! inside the gRPC binary payload; TrustForge metadata (caller actor,
//! capability) rides as gRPC headers.
//!
//! Implementations of `GrpcChannel` adapt to whichever gRPC stack the
//! consumer pulls in (`tonic`, `grpcio`, etc.). The bridge itself is
//! transport-agnostic.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::bridges::{Bridge, BridgeError, BridgeKind};
use crate::canonicalize;

#[derive(Clone, Debug)]
pub struct GrpcCallContext {
    pub method: String,
    pub metadata: HashMap<String, String>,
    /// Optional gRPC `:authority` pseudo-header.
    pub authority: Option<String>,
}

#[derive(Clone, Debug)]
pub struct GrpcReply {
    pub body: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

/// Caller-supplied gRPC channel adapter. The bridge issues unary or
/// server-streaming calls through this trait and is otherwise unaware
/// of the concrete gRPC stack.
pub trait GrpcChannel: Send + Sync {
    fn unary(&self, call: &GrpcCallContext, body: &[u8]) -> Result<GrpcReply, BridgeError>;
    fn close(&self) -> Result<(), BridgeError>;
}

#[derive(Clone, Debug)]
pub struct GrpcBridgeConfig {
    pub bridge_id: String,
    pub trust_domain: String,
    /// Default service method, e.g. `trustforge.ProofRpc/Unary`.
    pub service_method: String,
    /// Default `:authority`.
    pub authority: Option<String>,
    /// Static metadata added to every call (tracing, etc.).
    pub metadata: HashMap<String, String>,
}

pub struct GrpcBridge {
    cfg: GrpcBridgeConfig,
    channel: Arc<dyn GrpcChannel>,
    listeners: Mutex<Vec<Arc<dyn Fn(&[u8]) + Send + Sync>>>,
}

impl GrpcBridge {
    pub fn new(channel: Arc<dyn GrpcChannel>, cfg: GrpcBridgeConfig) -> Self {
        Self {
            cfg,
            channel,
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Send a single frame over the underlying gRPC channel. Returns
    /// the unary reply body so callers can route it through their own
    /// frame-handling path; also fans the body out to listeners
    /// registered via `on_frame`.
    pub fn send_frame(&self, frame_canonical_json: &[u8]) -> Result<Vec<u8>, BridgeError> {
        let ctx = GrpcCallContext {
            method: self.cfg.service_method.clone(),
            metadata: self.cfg.metadata.clone(),
            authority: self.cfg.authority.clone(),
        };
        let reply = self.channel.unary(&ctx, frame_canonical_json)?;
        if let Ok(listeners) = self.listeners.lock() {
            for l in listeners.iter() {
                l(&reply.body);
            }
        }
        Ok(reply.body)
    }

    /// Convenience: canonicalise a serde_json::Value frame, send, and
    /// return the response body.
    pub fn send_value(&self, frame: &serde_json::Value) -> Result<Vec<u8>, BridgeError> {
        let bytes = canonicalize(frame).map_err(|e| BridgeError::InvalidInput(e.to_string()))?;
        self.send_frame(bytes.as_bytes())
    }

    pub fn on_frame<F>(&self, f: F)
    where
        F: Fn(&[u8]) + Send + Sync + 'static,
    {
        if let Ok(mut listeners) = self.listeners.lock() {
            listeners.push(Arc::new(f));
        }
    }

    pub fn close(&self) -> Result<(), BridgeError> {
        self.channel.close()
    }
}

impl Bridge for GrpcBridge {
    fn bridge_id(&self) -> &str {
        &self.cfg.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::Grpc
    }
    fn trust_domain(&self) -> &str {
        &self.cfg.trust_domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeChannel {
        last_body: Mutex<Vec<u8>>,
        echo: Mutex<Vec<u8>>,
        close_calls: AtomicUsize,
    }

    impl FakeChannel {
        fn new(echo: Vec<u8>) -> Self {
            Self {
                last_body: Mutex::new(Vec::new()),
                echo: Mutex::new(echo),
                close_calls: AtomicUsize::new(0),
            }
        }
    }

    impl GrpcChannel for FakeChannel {
        fn unary(&self, _call: &GrpcCallContext, body: &[u8]) -> Result<GrpcReply, BridgeError> {
            *self.last_body.lock().unwrap() = body.to_vec();
            Ok(GrpcReply {
                body: self.echo.lock().unwrap().clone(),
                metadata: HashMap::new(),
            })
        }
        fn close(&self) -> Result<(), BridgeError> {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn send_and_receive_round_trip() {
        let chan = Arc::new(FakeChannel::new(b"reply-bytes".to_vec()));
        let bridge = GrpcBridge::new(
            chan.clone(),
            GrpcBridgeConfig {
                bridge_id: "tf-grpc".into(),
                trust_domain: "example.com".into(),
                service_method: "trustforge.ProofRpc/Unary".into(),
                authority: Some("rpc.example.com".into()),
                metadata: HashMap::new(),
            },
        );
        let counter = Arc::new(AtomicUsize::new(0));
        {
            let counter = counter.clone();
            bridge.on_frame(move |b| {
                assert_eq!(b, b"reply-bytes");
                counter.fetch_add(1, Ordering::SeqCst);
            });
        }
        let reply = bridge.send_frame(b"hello-world").expect("send");
        assert_eq!(reply, b"reply-bytes");
        assert_eq!(*chan.last_body.lock().unwrap(), b"hello-world");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        bridge.close().expect("close");
        assert_eq!(chan.close_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn bridge_metadata_round_trip() {
        let chan = Arc::new(FakeChannel::new(Vec::new()));
        let bridge = GrpcBridge::new(
            chan,
            GrpcBridgeConfig {
                bridge_id: "tf-grpc".into(),
                trust_domain: "example.com".into(),
                service_method: "trustforge.ProofRpc/Unary".into(),
                authority: None,
                metadata: HashMap::new(),
            },
        );
        assert_eq!(bridge.bridge_id(), "tf-grpc");
        assert_eq!(bridge.kind(), BridgeKind::Grpc);
        assert_eq!(bridge.trust_domain(), "example.com");
    }
}
