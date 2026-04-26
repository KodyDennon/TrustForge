//! Rust mirror of `tools/tf-types-ts/src/core/bridges-registry.ts`.
//!
//! Loads + validates `.tf/bridges.yaml` against
//! `schemas/bridges-registry.schema.json` and exposes
//! `resolve_by_issuer` so the daemon (or any host that wants to re-use
//! the same logic in Rust) can map an incoming credential's `iss`
//! claim / SPIFFE trust-domain / Clerk publishable-key prefix to a
//! `BridgeEntry`.
//!
//! When the file is missing the registry is empty — the
//! credential-resolver's built-in defaults cover that case. When the
//! file is malformed `from_str` returns `BridgesRegistryError::Invalid`
//! and the daemon refuses to start.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgesRegistryKind {
    Oauth,
    Clerk,
    NextAuth,
    BetterAuth,
    Webauthn,
    Tls,
    Spiffe,
    Did,
    Gnap,
    Mcp,
    Matrix,
    Webhook,
    Grpc,
    ServiceMesh,
    A2a,
    SessionCookie,
    Aws,
    Gcp,
    Azure,
    Vault,
    Doppler,
}

impl BridgesRegistryKind {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "oauth" => Self::Oauth,
            "clerk" => Self::Clerk,
            "next-auth" => Self::NextAuth,
            "better-auth" => Self::BetterAuth,
            "webauthn" => Self::Webauthn,
            "tls" => Self::Tls,
            "spiffe" => Self::Spiffe,
            "did" => Self::Did,
            "gnap" => Self::Gnap,
            "mcp" => Self::Mcp,
            "matrix" => Self::Matrix,
            "webhook" => Self::Webhook,
            "grpc" => Self::Grpc,
            "service-mesh" => Self::ServiceMesh,
            "a2a" => Self::A2a,
            "session-cookie" => Self::SessionCookie,
            "aws" => Self::Aws,
            "gcp" => Self::Gcp,
            "azure" => Self::Azure,
            "vault" => Self::Vault,
            "doppler" => Self::Doppler,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Oauth => "oauth",
            Self::Clerk => "clerk",
            Self::NextAuth => "next-auth",
            Self::BetterAuth => "better-auth",
            Self::Webauthn => "webauthn",
            Self::Tls => "tls",
            Self::Spiffe => "spiffe",
            Self::Did => "did",
            Self::Gnap => "gnap",
            Self::Mcp => "mcp",
            Self::Matrix => "matrix",
            Self::Webhook => "webhook",
            Self::Grpc => "grpc",
            Self::ServiceMesh => "service-mesh",
            Self::A2a => "a2a",
            Self::SessionCookie => "session-cookie",
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
            Self::Vault => "vault",
            Self::Doppler => "doppler",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeEntry {
    pub kind: BridgesRegistryKind,
    pub issuer_match: Option<String>,
    pub iss_pattern: Option<String>,
    pub trust_domain: Option<String>,
    pub trust_level: Option<String>,
    pub capability_map: Option<BTreeMap<String, String>>,
    pub profile: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BridgesRegistry {
    pub registry_version: String,
    pub default_profile: Option<String>,
    pub bridges: Vec<BridgeEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum BridgesRegistryError {
    #[error("invalid registry: {0}")]
    Invalid(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(String),
}

const TRUST_LEVELS: &[&str] = &["T0", "T1", "T2", "T3", "T4", "T5", "T6", "T7"];

fn validate_profile(s: &str) -> bool {
    // ^tf-[a-z][a-z0-9-]*-compatible$
    let mut chars = s.chars();
    if chars.next() != Some('t') || chars.next() != Some('f') || chars.next() != Some('-') {
        return false;
    }
    let body: String = chars.collect();
    if !body.ends_with("-compatible") {
        return false;
    }
    let middle = &body[..body.len() - "-compatible".len()];
    if middle.is_empty() {
        return false;
    }
    let mut it = middle.chars();
    let first = match it.next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    for c in it {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return false;
        }
    }
    true
}

fn validate_action_name(s: &str) -> bool {
    // ^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$
    let mut segs = s.split('.');
    let first = match segs.next() {
        Some(v) if !v.is_empty() => v,
        _ => return false,
    };
    if !valid_action_segment(first) {
        return false;
    }
    let mut count = 0;
    for seg in segs {
        if !valid_action_segment(seg) {
            return false;
        }
        count += 1;
    }
    count >= 1
}

fn valid_action_segment(s: &str) -> bool {
    let mut it = s.chars();
    let first = match it.next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    for c in it {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return false;
        }
    }
    true
}

impl BridgesRegistry {
    /// Load `.tf/bridges.yaml` from disk. A missing file resolves to
    /// an empty registry — the resolver falls back to its built-in
    /// defaults in that case.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, BridgesRegistryError> {
        let path = path.as_ref();
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BridgesRegistry {
                    registry_version: "1".into(),
                    default_profile: None,
                    bridges: Vec::new(),
                });
            }
            Err(e) => return Err(BridgesRegistryError::Io(e)),
        };
        Self::from_str(&text)
    }

    /// Parse + validate a YAML/JSON registry document from a string.
    pub fn from_str(text: &str) -> Result<Self, BridgesRegistryError> {
        let raw: serde_yaml::Value =
            serde_yaml::from_str(text).map_err(|e| BridgesRegistryError::Parse(format!("{e}")))?;
        let doc = match raw {
            serde_yaml::Value::Mapping(m) => m,
            _ => {
                return Err(BridgesRegistryError::Invalid(
                    "registry root must be a mapping".into(),
                ))
            }
        };
        let mut registry_version: Option<String> = None;
        let mut default_profile: Option<String> = None;
        let mut bridges_value: Option<serde_yaml::Value> = None;
        for (k, v) in doc {
            let key = k
                .as_str()
                .ok_or_else(|| BridgesRegistryError::Invalid("non-string key in registry".into()))?
                .to_string();
            match key.as_str() {
                "registry_version" => {
                    let s = v.as_str().ok_or_else(|| {
                        BridgesRegistryError::Invalid("registry_version must be a string".into())
                    })?;
                    registry_version = Some(s.to_string());
                }
                "default_profile" => {
                    if let serde_yaml::Value::Null = v {
                        continue;
                    }
                    let s = v.as_str().ok_or_else(|| {
                        BridgesRegistryError::Invalid("default_profile must be a string".into())
                    })?;
                    if !validate_profile(s) {
                        return Err(BridgesRegistryError::Invalid(format!(
                            "default_profile must match ^tf-[a-z][a-z0-9-]*-compatible$, got {s}"
                        )));
                    }
                    default_profile = Some(s.to_string());
                }
                "bridges" => {
                    bridges_value = Some(v);
                }
                other => {
                    return Err(BridgesRegistryError::Invalid(format!(
                        "unknown registry key: {other}"
                    )));
                }
            }
        }
        let registry_version = registry_version
            .ok_or_else(|| BridgesRegistryError::Invalid("registry_version is required".into()))?;
        if registry_version != "1" {
            return Err(BridgesRegistryError::Invalid(format!(
                "registry_version must be \"1\", got {registry_version:?}"
            )));
        }
        let bridges_value = bridges_value
            .ok_or_else(|| BridgesRegistryError::Invalid("bridges is required".into()))?;
        let entries = match bridges_value {
            serde_yaml::Value::Sequence(s) => s,
            _ => {
                return Err(BridgesRegistryError::Invalid(
                    "bridges must be a sequence".into(),
                ))
            }
        };
        let mut bridges = Vec::with_capacity(entries.len());
        for (i, entry) in entries.into_iter().enumerate() {
            bridges.push(parse_entry(entry, i)?);
        }
        Ok(BridgesRegistry {
            registry_version: "1".into(),
            default_profile,
            bridges,
        })
    }

    /// Resolve an incoming credential's issuer to a bridge entry.
    /// Match precedence:
    ///   1. exact `issuer_match` equality.
    ///   2. `iss_pattern` substring match.
    /// Returns `None` when nothing matches.
    pub fn resolve_by_issuer(&self, iss: &str) -> Option<&BridgeEntry> {
        if iss.is_empty() {
            return None;
        }
        for entry in &self.bridges {
            if let Some(m) = &entry.issuer_match {
                if m == iss {
                    return Some(entry);
                }
            }
        }
        for entry in &self.bridges {
            if let Some(p) = &entry.iss_pattern {
                if iss.contains(p.as_str()) {
                    return Some(entry);
                }
            }
        }
        None
    }

    /// Resolve by bridge kind — returns the first matching entry.
    pub fn resolve_by_kind(&self, kind: &BridgesRegistryKind) -> Option<&BridgeEntry> {
        self.bridges.iter().find(|e| &e.kind == kind)
    }
}

fn parse_entry(
    value: serde_yaml::Value,
    index: usize,
) -> Result<BridgeEntry, BridgesRegistryError> {
    let map = match value {
        serde_yaml::Value::Mapping(m) => m,
        _ => {
            return Err(BridgesRegistryError::Invalid(format!(
                "bridges[{index}] must be a mapping"
            )))
        }
    };
    let mut kind: Option<BridgesRegistryKind> = None;
    let mut issuer_match: Option<String> = None;
    let mut iss_pattern: Option<String> = None;
    let mut trust_domain: Option<String> = None;
    let mut trust_level: Option<String> = None;
    let mut capability_map: Option<BTreeMap<String, String>> = None;
    let mut profile: Option<String> = None;
    for (k, v) in map {
        let key = k
            .as_str()
            .ok_or_else(|| {
                BridgesRegistryError::Invalid(format!("bridges[{index}] has non-string key"))
            })?
            .to_string();
        match key.as_str() {
            "kind" => {
                let s = v.as_str().ok_or_else(|| {
                    BridgesRegistryError::Invalid(format!("bridges[{index}].kind must be a string"))
                })?;
                kind = Some(BridgesRegistryKind::parse(s).ok_or_else(|| {
                    BridgesRegistryError::Invalid(format!("bridges[{index}].kind invalid: {s}"))
                })?);
            }
            "issuer_match" => {
                if let serde_yaml::Value::Null = v {
                    continue;
                }
                let s = v.as_str().ok_or_else(|| {
                    BridgesRegistryError::Invalid(format!(
                        "bridges[{index}].issuer_match must be a string"
                    ))
                })?;
                if s.is_empty() {
                    return Err(BridgesRegistryError::Invalid(format!(
                        "bridges[{index}].issuer_match must be non-empty"
                    )));
                }
                issuer_match = Some(s.to_string());
            }
            "iss_pattern" => {
                if let serde_yaml::Value::Null = v {
                    continue;
                }
                let s = v.as_str().ok_or_else(|| {
                    BridgesRegistryError::Invalid(format!(
                        "bridges[{index}].iss_pattern must be a string"
                    ))
                })?;
                if s.is_empty() {
                    return Err(BridgesRegistryError::Invalid(format!(
                        "bridges[{index}].iss_pattern must be non-empty"
                    )));
                }
                iss_pattern = Some(s.to_string());
            }
            "trust_domain" => {
                if let serde_yaml::Value::Null = v {
                    continue;
                }
                let s = v.as_str().ok_or_else(|| {
                    BridgesRegistryError::Invalid(format!(
                        "bridges[{index}].trust_domain must be a string"
                    ))
                })?;
                trust_domain = Some(s.to_string());
            }
            "trust_level" => {
                if let serde_yaml::Value::Null = v {
                    continue;
                }
                let s = v.as_str().ok_or_else(|| {
                    BridgesRegistryError::Invalid(format!(
                        "bridges[{index}].trust_level must be a string"
                    ))
                })?;
                if !TRUST_LEVELS.contains(&s) {
                    return Err(BridgesRegistryError::Invalid(format!(
                        "bridges[{index}].trust_level must be T0..T7"
                    )));
                }
                trust_level = Some(s.to_string());
            }
            "capability_map" => {
                if let serde_yaml::Value::Null = v {
                    continue;
                }
                let m = match v {
                    serde_yaml::Value::Mapping(m) => m,
                    _ => {
                        return Err(BridgesRegistryError::Invalid(format!(
                            "bridges[{index}].capability_map must be a mapping"
                        )))
                    }
                };
                let mut out = BTreeMap::new();
                for (mk, mv) in m {
                    let mk = mk.as_str().ok_or_else(|| {
                        BridgesRegistryError::Invalid(format!(
                            "bridges[{index}].capability_map has non-string key"
                        ))
                    })?;
                    let mv = mv.as_str().ok_or_else(|| {
                        BridgesRegistryError::Invalid(format!(
                            "bridges[{index}].capability_map[{mk}] must be a string"
                        ))
                    })?;
                    if !validate_action_name(mv) {
                        return Err(BridgesRegistryError::Invalid(format!(
                            "bridges[{index}].capability_map[{mk}] must be a dotted action name"
                        )));
                    }
                    out.insert(mk.to_string(), mv.to_string());
                }
                capability_map = Some(out);
            }
            "profile" => {
                if let serde_yaml::Value::Null = v {
                    continue;
                }
                let s = v.as_str().ok_or_else(|| {
                    BridgesRegistryError::Invalid(format!(
                        "bridges[{index}].profile must be a string"
                    ))
                })?;
                if !validate_profile(s) {
                    return Err(BridgesRegistryError::Invalid(format!(
                        "bridges[{index}].profile must match ^tf-[a-z][a-z0-9-]*-compatible$"
                    )));
                }
                profile = Some(s.to_string());
            }
            other => {
                return Err(BridgesRegistryError::Invalid(format!(
                    "bridges[{index}]: unknown key {other}"
                )));
            }
        }
    }
    let kind = kind.ok_or_else(|| {
        BridgesRegistryError::Invalid(format!("bridges[{index}].kind is required"))
    })?;
    Ok(BridgeEntry {
        kind,
        issuer_match,
        iss_pattern,
        trust_domain,
        trust_level,
        capability_map,
        profile,
    })
}
