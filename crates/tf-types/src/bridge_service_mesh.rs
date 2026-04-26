//! Service-mesh bridge — Envoy XFCC, Istio AuthN, Linkerd l5d-client-id.
//!
//! This module exposes three public parser entry points used by the
//! daemon to convert sidecar-supplied trust signals into TrustForge
//! actor identities and proof events:
//!
//! * [`parse_xfcc`]              — Envoy `X-Forwarded-Client-Cert` header.
//! * [`parse_istio_attributes`]  — Istio `x-istio-attributes` header
//!                                 (base64 protobuf) or a JWT bearer
//!                                 token surfacing `source.principal`.
//! * [`parse_linkerd_client_id`] — Linkerd `l5d-client-id` header.
//!
//! Each parser returns a pure data struct; emission of a signed proof
//! event is the daemon's responsibility, but a [`ProofEventStub`] is
//! returned alongside so the daemon can stamp and sign it directly.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::bridge_spiffe::{parse_spiffe_id, spiffe_to_actor_id, ParsedSpiffeId};
use crate::bridges::{Bridge, BridgeError, BridgeKind};
use crate::generated::{
    ActorIdentity, ActorIdentity_IdentityVersion, ActorType, AuthorityRoot, AuthorityRoot_Kind,
    PublicKey, PublicKey_Purpose, TrustLevel,
};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One decoded entry of an `X-Forwarded-Client-Cert` header. Envoy adds
/// one per hop; the inner-most (leftmost) entry represents the original
/// peer the bridge cares about. Field names match the upstream XFCC keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfccEntry {
    /// SPIFFE / URI SAN (XFCC `URI=`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Hex-encoded fingerprint of the leaf cert (XFCC `Hash=`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Issuer URI (XFCC `By=`). Often a SPIFFE id of the issuing CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// RFC 2253 leaf subject (XFCC `Subject=`). When `Subject=` is
    /// absent but `DNS=` is set, the parser folds the DNS list into
    /// this field as `dns:<comma-separated>` so downstream code has
    /// one fallback identity field to look at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

/// Istio AuthN principal, extracted either from a base64-encoded
/// protobuf (`x-istio-attributes`) or from a JWT carried in
/// `Authorization: Bearer …`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IstioPrincipal {
    /// Canonical SPIFFE id, e.g. `spiffe://cluster.local/ns/foo/sa/bar`.
    pub spiffe_id: String,
    /// Kubernetes namespace (parsed from the SPIFFE path).
    pub namespace: String,
}

/// Linkerd `l5d-client-id` header value. Linkerd 2.x emits a SPIFFE
/// SVID URI; this struct re-exposes the canonical id after validation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkerdClient {
    /// Verified `spiffe://…` URI from the header.
    pub spiffe_id: String,
}

/// A pre-built proof-event payload the daemon can sign and append to
/// the chain. The daemon fills in actor / instance / signature; the
/// bridge only states the event type and the (canonicalised) payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEventStub {
    /// Event type, e.g. `bridge.service_mesh.envoy.accepted`.
    pub event_type: String,
    /// Free-form JSON payload. The shape is stable per `event_type`.
    pub payload: Value,
}

#[derive(Clone, Debug, Default)]
pub struct ServiceMeshBridgeConfig {
    pub bridge_id: String,
    pub trust_domain: String,
}

pub struct ServiceMeshBridge {
    cfg: ServiceMeshBridgeConfig,
}

// ---------------------------------------------------------------------------
// Envoy XFCC parser
// ---------------------------------------------------------------------------

/// Parse a full `X-Forwarded-Client-Cert` header into one or more
/// [`XfccEntry`]s.
///
/// The header is comma-separated. Each entry is a list of
/// `Key=Value` pairs separated by `;`. Values may be unquoted (no
/// commas/semicolons/quotes) or wrapped in `"…"` with `\\` and `\"`
/// escapes. Mismatched quotes are a hard error.
///
/// Reference: <https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert>.
pub fn parse_xfcc(header: &str) -> Result<Vec<XfccEntry>, BridgeError> {
    let header = header.trim();
    if header.is_empty() {
        return Err(BridgeError::InvalidInput("empty XFCC header".into()));
    }
    let raw_entries = split_xfcc_entries(header)?;
    let mut out = Vec::with_capacity(raw_entries.len());
    for raw in raw_entries {
        out.push(parse_xfcc_entry(&raw)?);
    }
    if out.is_empty() {
        return Err(BridgeError::InvalidInput(
            "XFCC header parsed to zero entries".into(),
        ));
    }
    // Validate that at least one identifying field is present in each
    // entry — Envoy never emits an entry with nothing but commas, so
    // such input is always malformed. (DNS folds into `subject` so
    // the check on `subject` catches DNS-only entries too.)
    for (i, e) in out.iter().enumerate() {
        if e.uri.is_none() && e.subject.is_none() && e.by.is_none() {
            return Err(BridgeError::InvalidInput(format!(
                "XFCC entry #{} has no URI/By/Subject/DNS fields",
                i
            )));
        }
    }
    Ok(out)
}

/// Split the top-level comma-separated XFCC entries, honouring quoted
/// values that may themselves contain commas.
fn split_xfcc_entries(header: &str) -> Result<Vec<String>, BridgeError> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = header.chars().peekable();
    let mut in_quotes = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' if in_quotes => {
                // Preserve escape sequence verbatim — the per-entry
                // parser strips it later.
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            ',' if !in_quotes => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    out.push(trimmed);
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if in_quotes {
        return Err(BridgeError::InvalidInput(
            "XFCC header has mismatched quotes".into(),
        ));
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        out.push(trimmed);
    }
    Ok(out)
}

/// Parse a single XFCC entry (the bit between commas) into an
/// [`XfccEntry`].
fn parse_xfcc_entry(entry: &str) -> Result<XfccEntry, BridgeError> {
    let pairs = split_xfcc_pairs(entry)?;
    let mut out = XfccEntry::default();
    let mut dns: Vec<String> = Vec::new();
    for (k, v) in pairs {
        match k.to_ascii_lowercase().as_str() {
            "uri" => out.uri = Some(v),
            "hash" => out.hash = Some(v),
            "by" => out.by = Some(v),
            "subject" => out.subject = Some(v),
            "dns" => dns.push(v),
            // `Cert=` / `Chain=` are accepted but not surfaced —
            // the daemon's TLS bridge handles chain re-validation
            // when a chain is needed.
            "cert" | "chain" => {}
            // Unknown keys are ignored — the spec is permissive.
            _ => {}
        }
    }
    // Fold DNS list into `subject` if no explicit Subject was given.
    if out.subject.is_none() && !dns.is_empty() {
        out.subject = Some(format!("dns:{}", dns.join(",")));
    }
    Ok(out)
}

/// Split a single entry into `(key, value)` pairs, honouring quoted
/// values. Returns `BridgeError::InvalidInput` for unterminated quotes
/// or pairs missing an `=`.
fn split_xfcc_pairs(entry: &str) -> Result<Vec<(String, String)>, BridgeError> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = entry.chars().peekable();
    let mut in_quotes = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' if in_quotes => {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            ';' if !in_quotes => {
                push_pair(&mut out, &current)?;
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if in_quotes {
        return Err(BridgeError::InvalidInput(
            "XFCC entry has mismatched quotes".into(),
        ));
    }
    push_pair(&mut out, &current)?;
    Ok(out)
}

fn push_pair(out: &mut Vec<(String, String)>, raw: &str) -> Result<(), BridgeError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(());
    }
    let eq = raw
        .find('=')
        .ok_or_else(|| BridgeError::InvalidInput(format!("XFCC pair missing '=': {}", raw)))?;
    let key = raw[..eq].trim().to_string();
    if key.is_empty() {
        return Err(BridgeError::InvalidInput("XFCC pair has empty key".into()));
    }
    let value = unquote_xfcc_value(raw[eq + 1..].trim())?;
    out.push((key, value));
    Ok(())
}

/// Strip surrounding double-quotes and decode `\\` / `\"` escapes.
fn unquote_xfcc_value(raw: &str) -> Result<String, BridgeError> {
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        let inner = &raw[1..raw.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some(esc @ ('"' | '\\')) => out.push(esc),
                    Some(other) => {
                        // Unknown escapes pass through verbatim.
                        out.push('\\');
                        out.push(other);
                    }
                    None => {
                        return Err(BridgeError::InvalidInput(
                            "XFCC value ends with dangling backslash".into(),
                        ))
                    }
                }
            } else if c == '"' {
                return Err(BridgeError::InvalidInput(
                    "XFCC value contains unescaped quote".into(),
                ));
            } else {
                out.push(c);
            }
        }
        Ok(out)
    } else if raw.contains('"') {
        Err(BridgeError::InvalidInput(
            "XFCC value has mismatched quotes".into(),
        ))
    } else {
        Ok(raw.to_string())
    }
}

// ---------------------------------------------------------------------------
// Istio AuthN parser
// ---------------------------------------------------------------------------

/// Parse an Istio principal from one of:
///
/// * a base64-encoded protobuf surfaced via `x-istio-attributes`, with
///   a single string field for `source.principal`, or
/// * a JWT (`xxx.yyy.zzz`) whose payload contains a `sub` claim that
///   is a `spiffe://` URI, optionally with `iss` set to an Istio-style
///   issuer.
///
/// Returns an [`IstioPrincipal`] with the SPIFFE id and the namespace
/// extracted from the SPIFFE path (`/ns/<namespace>/sa/<sa>`).
pub fn parse_istio_attributes(header: &str) -> Result<IstioPrincipal, BridgeError> {
    let header = header.trim();
    if header.is_empty() {
        return Err(BridgeError::InvalidInput("empty Istio header".into()));
    }
    // JWT shape: three base64url segments separated by dots. We never
    // verify the signature here — that's the OAuth bridge's job — but
    // we do require an Istio-shaped issuer to reject random tokens.
    if let Some(p) = try_parse_istio_jwt(header)? {
        return Ok(p);
    }
    // Otherwise treat the value as a base64(-url) encoded protobuf
    // whose only field of interest is `source.principal` (string).
    let bytes = decode_base64_either(header)
        .ok_or_else(|| BridgeError::InvalidInput("Istio header is not base64 or a JWT".into()))?;
    let principal = decode_istio_protobuf_principal(&bytes)?;
    spiffe_to_principal(&principal)
}

/// Attempt to interpret the header as a JWT. Returns `Ok(None)` if the
/// header is clearly not a JWT (e.g. doesn't have three dot-separated
/// segments) so the caller can fall through to the protobuf path.
fn try_parse_istio_jwt(header: &str) -> Result<Option<IstioPrincipal>, BridgeError> {
    let header = header.strip_prefix("Bearer ").unwrap_or(header).trim();
    let parts: Vec<&str> = header.split('.').collect();
    if parts.len() != 3 {
        return Ok(None);
    }
    // Each segment must be valid base64url.
    let payload_bytes = match URL_SAFE_NO_PAD.decode(parts[1].as_bytes()) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let payload: Value = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    // We require an Istio-shaped issuer; the canonical Istio CA
    // issuer is `https://kubernetes.default.svc.cluster.local` or
    // `istio-ca`. Anything else is rejected to avoid happily
    // accepting third-party JWTs as Istio principals.
    let issuer = payload
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !is_istio_issuer(issuer) {
        return Err(BridgeError::Rejected(format!(
            "Istio JWT has non-Istio issuer: {}",
            issuer
        )));
    }
    // Istio surfaces the SPIFFE id either as `sub` or in a `spiffe`
    // claim.
    let spiffe = payload
        .get("sub")
        .and_then(Value::as_str)
        .or_else(|| payload.get("spiffe").and_then(Value::as_str))
        .ok_or_else(|| BridgeError::InvalidInput("Istio JWT missing sub/spiffe claim".into()))?;
    Ok(Some(spiffe_to_principal(spiffe)?))
}

fn is_istio_issuer(iss: &str) -> bool {
    // Common Istio CA / SDS issuer values.
    matches!(
        iss,
        "https://kubernetes.default.svc.cluster.local"
            | "kubernetes/serviceaccount"
            | "istio-ca"
            | "istiod.istio-system.svc"
    ) || iss.starts_with("https://kubernetes.default.svc")
        || iss.starts_with("istiod.")
}

/// Hand-decode the protobuf message Istio puts in `x-istio-attributes`.
/// We don't pull in `prost`; the wire format we care about is one
/// length-delimited string field whose number we treat as
/// "the only string in the message". The full Mixer `Attributes`
/// proto is more complex, but every Istio mesh in the wild surfaces
/// `source.principal` as a top-level string.
fn decode_istio_protobuf_principal(bytes: &[u8]) -> Result<String, BridgeError> {
    let mut i = 0;
    let mut best: Option<String> = None;
    while i < bytes.len() {
        let (tag, n) = read_varint(&bytes[i..])
            .ok_or_else(|| BridgeError::InvalidInput("Istio proto: bad varint tag".into()))?;
        i += n;
        let wire = (tag & 0x7) as u8;
        match wire {
            0 => {
                // varint payload — skip
                let (_, n) = read_varint(&bytes[i..])
                    .ok_or_else(|| BridgeError::InvalidInput("Istio proto: bad varint".into()))?;
                i += n;
            }
            1 => {
                // 64-bit fixed
                if bytes.len() < i + 8 {
                    return Err(BridgeError::InvalidInput(
                        "Istio proto: truncated fixed64".into(),
                    ));
                }
                i += 8;
            }
            2 => {
                // length-delimited
                let (len, n) = read_varint(&bytes[i..]).ok_or_else(|| {
                    BridgeError::InvalidInput("Istio proto: bad length-delim varint".into())
                })?;
                i += n;
                let len = len as usize;
                if bytes.len() < i + len {
                    return Err(BridgeError::InvalidInput(
                        "Istio proto: truncated length-delim".into(),
                    ));
                }
                let payload = &bytes[i..i + len];
                i += len;
                // Heuristic: a SPIFFE principal always starts with
                // `spiffe://`. Pick the first such string we see.
                if let Ok(s) = std::str::from_utf8(payload) {
                    if s.starts_with("spiffe://") && best.is_none() {
                        best = Some(s.to_string());
                    }
                }
            }
            5 => {
                if bytes.len() < i + 4 {
                    return Err(BridgeError::InvalidInput(
                        "Istio proto: truncated fixed32".into(),
                    ));
                }
                i += 4;
            }
            other => {
                return Err(BridgeError::InvalidInput(format!(
                    "Istio proto: unknown wire type {}",
                    other
                )));
            }
        }
    }
    best.ok_or_else(|| {
        BridgeError::InvalidInput("Istio proto: no spiffe:// principal field present".into())
    })
}

fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, b) in bytes.iter().enumerate() {
        if i >= 10 {
            return None;
        }
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

fn decode_base64_either(s: &str) -> Option<Vec<u8>> {
    if let Ok(v) = STANDARD.decode(s.as_bytes()) {
        return Some(v);
    }
    URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()
}

fn spiffe_to_principal(spiffe: &str) -> Result<IstioPrincipal, BridgeError> {
    let parsed: ParsedSpiffeId = parse_spiffe_id(spiffe)?;
    // Istio path is `/ns/<ns>/sa/<sa>`; `path` here has no leading `/`.
    let segments: Vec<&str> = parsed.path.split('/').collect();
    let mut namespace = String::new();
    let mut i = 0;
    while i + 1 < segments.len() {
        if segments[i] == "ns" {
            namespace = segments[i + 1].to_string();
            break;
        }
        i += 1;
    }
    if namespace.is_empty() {
        return Err(BridgeError::InvalidInput(format!(
            "Istio SPIFFE id has no /ns/<namespace>/ segment: {}",
            spiffe
        )));
    }
    Ok(IstioPrincipal {
        spiffe_id: spiffe.to_string(),
        namespace,
    })
}

// ---------------------------------------------------------------------------
// Linkerd parser
// ---------------------------------------------------------------------------

/// Parse a Linkerd `l5d-client-id` header. Modern Linkerd emits a
/// SPIFFE SVID URI; older deployments emit the legacy
/// `<sa>.<ns>.serviceaccount.identity.<cluster>.cluster.local`
/// form. Both are accepted.
pub fn parse_linkerd_client_id(header: &str) -> Result<LinkerdClient, BridgeError> {
    let header = header.trim();
    if header.is_empty() {
        return Err(BridgeError::InvalidInput(
            "empty l5d-client-id header".into(),
        ));
    }
    if header.starts_with("spiffe://") {
        // Validate via the SPIFFE bridge.
        parse_spiffe_id(header)?;
        return Ok(LinkerdClient {
            spiffe_id: header.to_string(),
        });
    }
    if header.contains("://") {
        return Err(BridgeError::InvalidInput(format!(
            "l5d-client-id has non-spiffe scheme: {}",
            header
        )));
    }
    // Legacy form: convert to a synthetic SPIFFE id so downstream
    // consumers can treat all Linkerd identities uniformly.
    let suffix = ".serviceaccount.identity.";
    let idx = header.find(suffix).ok_or_else(|| {
        BridgeError::InvalidInput(format!(
            "l5d-client-id has no `.serviceaccount.identity.` segment: {}",
            header
        ))
    })?;
    let pre = &header[..idx];
    let post = &header[idx + suffix.len()..];
    let cluster = post.strip_suffix(".cluster.local").ok_or_else(|| {
        BridgeError::InvalidInput(format!(
            "l5d-client-id missing `.cluster.local` suffix: {}",
            header
        ))
    })?;
    let dot = pre.find('.').ok_or_else(|| {
        BridgeError::InvalidInput(format!("l5d-client-id missing `<sa>.<ns>`: {}", header))
    })?;
    let sa = &pre[..dot];
    let ns = &pre[dot + 1..];
    if sa.is_empty() || ns.is_empty() || cluster.is_empty() {
        return Err(BridgeError::InvalidInput(format!(
            "l5d-client-id has empty sa/ns/cluster: {}",
            header
        )));
    }
    let synthetic = format!("spiffe://{}/ns/{}/sa/{}", cluster, ns, sa);
    parse_spiffe_id(&synthetic)?;
    Ok(LinkerdClient {
        spiffe_id: synthetic,
    })
}

// ---------------------------------------------------------------------------
// Proof-event helpers
// ---------------------------------------------------------------------------

/// Build the canonical `bridge.service_mesh.envoy.accepted` stub.
pub fn envoy_accepted_event(entry: &XfccEntry) -> ProofEventStub {
    ProofEventStub {
        event_type: "bridge.service_mesh.envoy.accepted".into(),
        payload: serde_json::json!({
            "uri": entry.uri,
            "by": entry.by,
            "hash": entry.hash,
            "subject": entry.subject,
        }),
    }
}

/// Build the canonical `bridge.service_mesh.istio.accepted` stub.
pub fn istio_accepted_event(p: &IstioPrincipal) -> ProofEventStub {
    ProofEventStub {
        event_type: "bridge.service_mesh.istio.accepted".into(),
        payload: serde_json::json!({
            "spiffe_id": p.spiffe_id,
            "namespace": p.namespace,
        }),
    }
}

/// Build the canonical `bridge.service_mesh.linkerd.accepted` stub.
pub fn linkerd_accepted_event(c: &LinkerdClient) -> ProofEventStub {
    ProofEventStub {
        event_type: "bridge.service_mesh.linkerd.accepted".into(),
        payload: serde_json::json!({ "spiffe_id": c.spiffe_id }),
    }
}

// ---------------------------------------------------------------------------
// High-level bridge object — kept compatible with sprint-5 callers.
// ---------------------------------------------------------------------------

impl ServiceMeshBridge {
    pub fn new(cfg: ServiceMeshBridgeConfig) -> Self {
        ServiceMeshBridge { cfg }
    }

    /// Project a parsed XFCC entry into a TrustForge identity. Inputs
    /// should already be the output of [`parse_xfcc`]; this method is
    /// retained for the existing sprint-5 callers that build entries
    /// by hand.
    pub fn accept_envoy(&self, entry: &XfccEntry) -> Result<ActorIdentity, BridgeError> {
        let uri = entry.uri.as_deref().ok_or_else(|| {
            BridgeError::InvalidInput("XFCC entry needs URI in this Rust path".into())
        })?;
        if !uri.starts_with("spiffe://") {
            return Err(BridgeError::Rejected(
                "Rust XFCC bridge only accepts spiffe:// URIs".into(),
            ));
        }
        let actor = spiffe_to_actor_id(uri)?;
        Ok(self.identity_from(actor, entry.by.clone()))
    }

    pub fn accept_istio(&self, spiffe_id: &str) -> Result<ActorIdentity, BridgeError> {
        if !spiffe_id.starts_with("spiffe://") {
            return Err(BridgeError::InvalidInput(
                "Istio context.spiffe_id must be a spiffe:// URI".into(),
            ));
        }
        let actor = spiffe_to_actor_id(spiffe_id)?;
        Ok(self.identity_from(actor, Some("istio".into())))
    }

    pub fn accept_linkerd(&self, client_id: &str) -> Result<ActorIdentity, BridgeError> {
        // Accept either the legacy `…serviceaccount.identity…` form
        // (kept for the sprint-5 fixture) or the modern SPIFFE shape.
        if client_id.starts_with("spiffe://") {
            let actor = spiffe_to_actor_id(client_id)?;
            return Ok(self.identity_from(actor, Some("linkerd".into())));
        }
        let suffix = ".serviceaccount.identity.";
        let idx = client_id.find(suffix).ok_or_else(|| {
            BridgeError::InvalidInput(format!("not a linkerd client_id: {}", client_id))
        })?;
        let pre = &client_id[..idx];
        let post = &client_id[idx + suffix.len()..];
        let cluster_local = post.strip_suffix(".cluster.local").ok_or_else(|| {
            BridgeError::InvalidInput(format!("not a linkerd client_id: {}", client_id))
        })?;
        let dot = pre.find('.').ok_or_else(|| {
            BridgeError::InvalidInput(format!("not a linkerd client_id: {}", client_id))
        })?;
        let sa = &pre[..dot];
        let ns = &pre[dot + 1..];
        let actor = format!("tf:actor:service:{}/{}/{}", cluster_local, ns, sa);
        Ok(self.identity_from(actor, Some("linkerd".into())))
    }

    fn identity_from(&self, actor: String, federation: Option<String>) -> ActorIdentity {
        ActorIdentity {
            identity_version: ActorIdentity_IdentityVersion::V1,
            actor_id: actor,
            actor_type: ActorType::Service,
            instance_id: None,
            public_keys: vec![PublicKey {
                key_id: "service-mesh".into(),
                algorithm: "ed25519".into(),
                public_key: "AA==".into(),
                purpose: PublicKey_Purpose::Signing,
                valid_from: None,
                valid_until: None,
            }],
            trust_levels: vec![TrustLevel::T3],
            authority_roots: vec![AuthorityRoot {
                kind: AuthorityRoot_Kind::Federation,
                id: federation.unwrap_or_else(|| "service-mesh".into()),
            }],
            attestations: None,
            valid_from: now_iso8601(),
            valid_until: None,
            revocation_ref: None,
            signature: None,
        }
    }
}

impl Bridge for ServiceMeshBridge {
    fn bridge_id(&self) -> &str {
        &self.cfg.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::ServiceMesh
    }
    fn trust_domain(&self) -> &str {
        &self.cfg.trust_domain
    }
}

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (y, m, d, h, mi, s) = secs_to_ymdhms(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, mi, s)
}

fn secs_to_ymdhms(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let time = secs.rem_euclid(86_400);
    let hour = (time / 3600) as u32;
    let minute = ((time % 3600) / 60) as u32;
    let second = (time % 60) as u32;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 {
        (mp + 3) as u32
    } else {
        (mp - 9) as u32
    };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d, hour, minute, second)
}
