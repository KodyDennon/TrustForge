//! SPIFFE bridge. Mirrors `tools/tf-types-ts/src/core/bridge-spiffe.ts`.

use regex::Regex;

use crate::bridges::{Bridge, BridgeError, BridgeKind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedSpiffeId {
    pub trust_domain: String,
    pub path: String,
    pub raw: String,
}

pub fn parse_spiffe_id(id: &str) -> Result<ParsedSpiffeId, BridgeError> {
    if id.is_empty() {
        return Err(BridgeError::InvalidInput("empty SPIFFE ID".into()));
    }
    let rest = id
        .strip_prefix("spiffe://")
        .ok_or_else(|| BridgeError::InvalidInput(format!("SPIFFE ID must start with spiffe://, got {:?}", id)))?;
    let (trust_domain, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    if trust_domain.is_empty() {
        return Err(BridgeError::InvalidInput("SPIFFE ID has no trust domain".into()));
    }
    if path.is_empty() {
        return Err(BridgeError::InvalidInput("SPIFFE ID has no path".into()));
    }
    let re = Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$").unwrap();
    if !re.is_match(trust_domain) {
        return Err(BridgeError::InvalidInput(format!(
            "SPIFFE trust domain is not DNS-like: {}",
            trust_domain
        )));
    }
    Ok(ParsedSpiffeId {
        trust_domain: trust_domain.to_owned(),
        path: path.to_owned(),
        raw: id.to_owned(),
    })
}

pub fn spiffe_to_actor_id(id: &str) -> Result<String, BridgeError> {
    let parsed = parse_spiffe_id(id)?;
    Ok(format!(
        "tf:actor:service:{}/{}",
        parsed.trust_domain, parsed.path
    ))
}

pub fn actor_id_to_spiffe(actor_id: &str) -> Result<String, BridgeError> {
    let re = Regex::new(r"^tf:actor:([^:]+):(.+)$").unwrap();
    let caps = re
        .captures(actor_id)
        .ok_or_else(|| BridgeError::InvalidInput(format!("malformed actor URI: {}", actor_id)))?;
    let type_segment = caps.get(1).unwrap().as_str();
    let path_segment = caps.get(2).unwrap().as_str();
    if type_segment != "service" {
        return Err(BridgeError::Unsupported(format!(
            "SPIFFE bridge only projects service actors, got {}",
            type_segment
        )));
    }
    let slash = path_segment
        .find('/')
        .ok_or_else(|| BridgeError::InvalidInput(format!(
            "service actor path must be <trust-domain>/<path>, got {}",
            path_segment
        )))?;
    let trust_domain = &path_segment[..slash];
    let tail = &path_segment[slash + 1..];
    Ok(format!("spiffe://{}/{}", trust_domain, tail))
}

pub struct SpiffeBridge {
    pub bridge_id: String,
    pub trust_domain: String,
}

impl SpiffeBridge {
    pub fn new(bridge_id: impl Into<String>, trust_domain: impl Into<String>) -> Self {
        SpiffeBridge {
            bridge_id: bridge_id.into(),
            trust_domain: trust_domain.into(),
        }
    }

    pub fn to_actor_id(&self, id: &str) -> Result<String, BridgeError> {
        spiffe_to_actor_id(id)
    }

    pub fn to_spiffe(&self, actor_id: &str) -> Result<String, BridgeError> {
        actor_id_to_spiffe(actor_id)
    }
}

impl Bridge for SpiffeBridge {
    fn bridge_id(&self) -> &str {
        &self.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::Spiffe
    }
    fn trust_domain(&self) -> &str {
        &self.trust_domain
    }
}
