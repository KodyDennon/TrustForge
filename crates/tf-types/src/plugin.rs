//! PluginRegistry — native-plugin mirror of
//! `tools/tf-types-ts/src/core/plugin.ts`.
//!
//! Native plugins in Rust register a trait implementation up-front (plugins
//! are compiled in, not dlopen'd — safe subset for the prototype). The
//! registry validates the manifest's ed25519 signature over its canonical
//! JSON form with signature.signature cleared.
//!
//! WASM plugins are handled by the sibling `plugin_wasm` module; instantiate
//! a `WasmPlugin` for capability-gated WASM execution. Native Rust plugins
//! continue to be compiled in (the registry doesn't dlopen).

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use serde_json::Value;

use crate::canonical::canonicalize;
use crate::crypto::{b64decode, ed25519_verify, CryptoError};

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("plugin I/O error: {0}")]
    Io(String),
    #[error("plugin parse error: {0}")]
    Parse(String),
    #[error("plugin signature invalid: {0}")]
    BadSignature(String),
    #[error("unknown plugin kind: {0}")]
    UnknownKind(String),
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<CryptoError> for PluginError {
    fn from(e: CryptoError) -> Self {
        PluginError::Crypto(e.to_string())
    }
}

/// Opaque handler. Native Rust plugins register concrete implementations.
pub type NativeHandler = Arc<dyn Fn(&Value) -> Result<Value, String> + Send + Sync + 'static>;

pub struct LoadedPlugin {
    pub plugin_id: String,
    pub actor_id: String,
    pub kind: String,
    pub capabilities: Vec<String>,
    /// Map from capability name → handler. Populated for native plugins that
    /// supplied handlers via `register_handler`.
    pub handlers: HashMap<String, NativeHandler>,
}

impl std::fmt::Debug for LoadedPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedPlugin")
            .field("plugin_id", &self.plugin_id)
            .field("actor_id", &self.actor_id)
            .field("kind", &self.kind)
            .field("capabilities", &self.capabilities)
            .field("handler_count", &self.handlers.len())
            .finish()
    }
}

pub struct PluginRegistry {
    plugins: Vec<LoadedPlugin>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        PluginRegistry {
            plugins: Vec::new(),
        }
    }

    /// Verify a manifest's signature and register it. Native Rust plugins
    /// supply their handlers in `handlers` keyed by capability name.
    pub fn load_native<P: AsRef<Path>>(
        &mut self,
        manifest_path: P,
        handlers: HashMap<String, NativeHandler>,
    ) -> Result<&LoadedPlugin, PluginError> {
        let raw = fs::read_to_string(manifest_path.as_ref())
            .map_err(|e| PluginError::Io(e.to_string()))?;
        let manifest: Value = {
            let yaml: serde_yaml::Value =
                serde_yaml::from_str(&raw).map_err(|e| PluginError::Parse(e.to_string()))?;
            serde_json::to_value(yaml).map_err(|e| PluginError::Parse(e.to_string()))?
        };
        let kind = manifest
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if kind != "native" {
            return Err(PluginError::UnknownKind(kind));
        }
        let plugin_id = manifest
            .get("plugin_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        verify_signature_value(&manifest, &plugin_id)?;
        let actor_id = manifest
            .get("actor_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let capability_names: Vec<String> = manifest
            .get("capabilities")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let plugin = LoadedPlugin {
            plugin_id,
            actor_id,
            kind,
            capabilities: capability_names,
            handlers,
        };
        self.plugins.push(plugin);
        Ok(self.plugins.last().unwrap())
    }

    pub fn list(&self) -> &[LoadedPlugin] {
        &self.plugins
    }

    pub fn invoke(
        &self,
        plugin_id: &str,
        capability: &str,
        request: &Value,
    ) -> Result<Value, PluginError> {
        let plugin = self
            .plugins
            .iter()
            .find(|p| p.plugin_id == plugin_id)
            .ok_or_else(|| PluginError::Parse(format!("plugin not loaded: {}", plugin_id)))?;
        let handler = plugin.handlers.get(capability).ok_or_else(|| {
            PluginError::Parse(format!("no handler for capability: {}", capability))
        })?;
        handler(request).map_err(PluginError::Parse)
    }
}

/// Standalone signature verifier for tooling (a CLI's `tf plugin verify`).
pub fn verify_plugin_signature<P: AsRef<Path>>(manifest_path: P) -> Result<String, PluginError> {
    let raw =
        fs::read_to_string(manifest_path.as_ref()).map_err(|e| PluginError::Io(e.to_string()))?;
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(&raw).map_err(|e| PluginError::Parse(e.to_string()))?;
    let manifest: Value =
        serde_json::to_value(yaml).map_err(|e| PluginError::Parse(e.to_string()))?;
    let plugin_id = manifest
        .get("plugin_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    verify_signature_value(&manifest, &plugin_id)?;
    Ok(plugin_id)
}

fn verify_signature_value(manifest: &Value, plugin_id: &str) -> Result<(), PluginError> {
    let sig_b64 = manifest
        .get("signature")
        .and_then(|s| s.get("signature"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| PluginError::BadSignature(plugin_id.to_string()))?
        .to_string();
    let ident_pub = manifest
        .get("identity_pub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PluginError::BadSignature(plugin_id.to_string()))?
        .to_string();

    // Clone manifest and clear signature.signature.
    let mut cleared = manifest.clone();
    if let Some(sig) = cleared.get_mut("signature").and_then(|s| s.as_object_mut()) {
        sig.insert("signature".to_string(), Value::String(String::new()));
    }
    let canonical = canonicalize(&cleared).map_err(|e| PluginError::Parse(e.to_string()))?;
    let sig_bytes = b64decode(&sig_b64)?;
    let pubkey_bytes = b64decode(&ident_pub)?;
    ed25519_verify(&pubkey_bytes, canonical.as_bytes(), &sig_bytes)
        .map_err(|_| PluginError::BadSignature(plugin_id.to_string()))?;
    Ok(())
}

impl Default for PluginRegistry {
    fn default() -> Self {
        PluginRegistry::new()
    }
}
