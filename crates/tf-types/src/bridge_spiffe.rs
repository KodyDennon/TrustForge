//! SPIFFE bridge. Mirrors `tools/tf-types-ts/src/core/bridge-spiffe.ts`.

use crate::bridges::{Bridge, BridgeError, BridgeKind};

/// DNS-like label check, equivalent to the anchored pattern
/// `[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?`: alphanumeric first and
/// last byte, alphanumeric / `.` / `-` in between.
fn is_dns_like(s: &str) -> bool {
    let bytes = s.as_bytes();
    let Some((&first, rest)) = bytes.split_first() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    let Some((&last, middle)) = rest.split_last() else {
        return true; // single character
    };
    last.is_ascii_alphanumeric()
        && middle
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

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
    let rest = id.strip_prefix("spiffe://").ok_or_else(|| {
        BridgeError::InvalidInput(format!("SPIFFE ID must start with spiffe://, got {:?}", id))
    })?;
    let (trust_domain, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    if trust_domain.is_empty() {
        return Err(BridgeError::InvalidInput(
            "SPIFFE ID has no trust domain".into(),
        ));
    }
    if path.is_empty() {
        return Err(BridgeError::InvalidInput("SPIFFE ID has no path".into()));
    }
    if !is_dns_like(trust_domain) {
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
    // Shape: `tf:actor:<type>:<path>` where <type> has no `:` and <path>
    // is non-empty (may itself contain `:`).
    let malformed =
        || BridgeError::InvalidInput(format!("malformed actor URI: {}", actor_id));
    let rest = actor_id.strip_prefix("tf:actor:").ok_or_else(malformed)?;
    let colon = rest.find(':').ok_or_else(malformed)?;
    let (type_segment, path_segment) = (&rest[..colon], &rest[colon + 1..]);
    // `path` may contain further `:` but not a newline (parity with the
    // former `(.+)$` pattern, where `.` excluded `\n`).
    if type_segment.is_empty() || path_segment.is_empty() || path_segment.contains('\n') {
        return Err(malformed());
    }
    if type_segment != "service" {
        return Err(BridgeError::Unsupported(format!(
            "SPIFFE bridge only projects service actors, got {}",
            type_segment
        )));
    }
    let slash = path_segment.find('/').ok_or_else(|| {
        BridgeError::InvalidInput(format!(
            "service actor path must be <trust-domain>/<path>, got {}",
            path_segment
        ))
    })?;
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
