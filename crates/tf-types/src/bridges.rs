//! Common compatibility-bridge framework. Concrete bridges live in
//! sibling modules (e.g. `bridge_spiffe`) and register themselves with a
//! `BridgeRegistry` so higher-level code can look up a bridge by kind at
//! runtime.

use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeKind {
    Spiffe,
    Webauthn,
    Mcp,
    Oauth,
    Tls,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeError {
    #[error("bridge unsupported: {0}")]
    Unsupported(String),
    #[error("bridge invalid input: {0}")]
    InvalidInput(String),
    #[error("bridge rejected input: {0}")]
    Rejected(String),
    #[error("bridge internal error: {0}")]
    Internal(String),
}

pub trait Bridge: Send + Sync {
    fn bridge_id(&self) -> &str;
    fn kind(&self) -> BridgeKind;
    fn trust_domain(&self) -> &str;
}

#[derive(Default)]
pub struct BridgeRegistry {
    bridges: Vec<Arc<dyn Bridge>>,
}

impl BridgeRegistry {
    pub fn new() -> Self {
        BridgeRegistry { bridges: Vec::new() }
    }

    pub fn register(&mut self, bridge: Arc<dyn Bridge>) {
        self.bridges.push(bridge);
    }

    pub fn get(&self, kind: BridgeKind) -> Option<Arc<dyn Bridge>> {
        self.bridges.iter().find(|b| b.kind() == kind).cloned()
    }

    pub fn list(&self) -> &[Arc<dyn Bridge>] {
        &self.bridges
    }
}
