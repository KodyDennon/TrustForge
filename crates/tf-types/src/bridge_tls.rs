//! TLS / mTLS bridge — accept a peer-supplied X.509 certificate chain,
//! verify it against a configured set of trust anchors, and project the
//! verified leaf into a TrustForge actor identity + capabilities.
//!
//! Uses `x509-parser` for ASN.1 parsing and signature verification, so we
//! avoid embedding our own ASN.1/DER walker.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::pem::Pem;
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;

use crate::bridges::{Bridge, BridgeError, BridgeKind};
use crate::generated::{
    ActorIdentity, ActorIdentity_IdentityVersion, ActorType, AuthorityRoot, AuthorityRoot_Kind,
    PublicKey, PublicKey_Purpose, TrustLevel,
};

/// Mapping from X.509 Extended Key Usage OIDs to TrustForge action names.
pub fn default_eku_to_action(oid: &str) -> Option<&'static str> {
    match oid {
        "1.3.6.1.5.5.7.3.1" => Some("tls.server-auth"),
        "1.3.6.1.5.5.7.3.2" => Some("tls.client-auth"),
        "1.3.6.1.5.5.7.3.3" => Some("code.sign"),
        "1.3.6.1.5.5.7.3.4" => Some("email.protect"),
        "1.3.6.1.5.5.7.3.8" => Some("timestamp.sign"),
        "1.3.6.1.5.5.7.3.9" => Some("ocsp.sign"),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct TlsBridgeConfig {
    pub bridge_id: String,
    pub trust_domain: String,
    pub root_certificates_pem: Vec<String>,
    pub max_chain_length: Option<usize>,
    pub required_san_uri: Option<String>,
    pub now_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct TlsVerificationResult {
    pub identity: ActorIdentity,
    pub capabilities: Vec<String>,
    pub leaf_subject: String,
    pub chain_subjects: Vec<String>,
}

pub struct TlsBridge {
    cfg: TlsBridgeConfig,
    roots: Vec<Vec<u8>>, // owned DER for each configured root
}

impl TlsBridge {
    pub fn new(cfg: TlsBridgeConfig) -> Result<Self, BridgeError> {
        if cfg.root_certificates_pem.is_empty() {
            return Err(BridgeError::InvalidInput(
                "TLS bridge requires at least one trust anchor".into(),
            ));
        }
        let mut roots = Vec::with_capacity(cfg.root_certificates_pem.len());
        for (i, pem) in cfg.root_certificates_pem.iter().enumerate() {
            let der = parse_single_pem(pem)
                .map_err(|e| BridgeError::InvalidInput(format!("root[{}]: {}", i, e)))?;
            roots.push(der);
        }
        Ok(TlsBridge { cfg, roots })
    }

    pub fn verify_chain(&self, chain_pem: &[String]) -> Result<TlsVerificationResult, BridgeError> {
        let mut chain_der: Vec<Vec<u8>> = Vec::new();
        for (i, pem) in chain_pem.iter().enumerate() {
            for der in parse_pem_bundle(pem)
                .map_err(|e| BridgeError::InvalidInput(format!("chain[{}]: {}", i, e)))?
            {
                chain_der.push(der);
            }
        }
        if chain_der.is_empty() {
            return Err(BridgeError::InvalidInput("empty chain".into()));
        }
        let max = self.cfg.max_chain_length.unwrap_or(6);
        if chain_der.len() > max {
            return Err(BridgeError::Rejected(format!(
                "chain longer than max ({} > {})",
                chain_der.len(),
                max
            )));
        }

        let now = self
            .cfg
            .now_unix_seconds
            .unwrap_or_else(|| SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
        let now_asn1 = ASN1Time::from_timestamp(now as i64)
            .map_err(|e| BridgeError::InvalidInput(format!("now overflow: {}", e)))?;

        // Parse all certs once; we'll re-borrow as we walk.
        let parsed: Vec<X509Certificate> = chain_der
            .iter()
            .map(|d| {
                let (_, c) = X509Certificate::from_der(d)
                    .map_err(|e| BridgeError::InvalidInput(format!("DER parse: {}", e)))?;
                Ok::<_, BridgeError>(c)
            })
            .collect::<Result<_, _>>()?;

        // Validity windows for everything in the chain.
        for c in &parsed {
            let validity = c.validity();
            if !validity.is_valid_at(now_asn1) {
                return Err(BridgeError::Rejected(format!(
                    "cert {} outside validity window",
                    c.subject()
                )));
            }
        }

        // Walk leaf → chain → root.
        let leaf = &parsed[0];
        let mut chain_subjects: Vec<String> = vec![leaf.subject().to_string()];
        let mut current_idx: Option<usize> = Some(0);
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert(leaf.subject().to_string());

        let roots_parsed: Vec<X509Certificate> = self
            .roots
            .iter()
            .map(|d| X509Certificate::from_der(d).map(|p| p.1))
            .collect::<Result<_, _>>()
            .map_err(|e| BridgeError::Internal(format!("root DER reparse: {}", e)))?;

        for _ in 0..max {
            let cur = &parsed[current_idx.expect("current set")];
            // Try to find an issuer in the supplied chain (other than `cur`).
            let inter_idx = parsed
                .iter()
                .enumerate()
                .find(|(i, c)| *i != current_idx.unwrap() && c.subject() == cur.issuer())
                .map(|(i, _)| i);
            let issuer_in_chain = inter_idx.map(|i| &parsed[i]);
            let root_match = roots_parsed.iter().find(|r| r.subject() == cur.issuer());

            let issuer = match issuer_in_chain.or(root_match) {
                Some(c) => c,
                None => {
                    return Err(BridgeError::Rejected(format!(
                        "no issuer cert for {} (issuer={})",
                        cur.subject(),
                        cur.issuer()
                    )))
                }
            };

            cur.verify_signature(Some(issuer.public_key()))
                .map_err(|e| {
                    BridgeError::Rejected(format!(
                        "signature verification failed for {}: {}",
                        cur.subject(),
                        e
                    ))
                })?;

            chain_subjects.push(issuer.subject().to_string());
            if root_match.is_some() && issuer_in_chain.is_none() {
                // Reached a configured trust anchor; validate the root is
                // self-signed and current.
                issuer
                    .verify_signature(Some(issuer.public_key()))
                    .map_err(|e| {
                        BridgeError::Rejected(format!(
                            "root {} not self-consistent: {}",
                            issuer.subject(),
                            e
                        ))
                    })?;
                return self.project(leaf, issuer, chain_subjects);
            }
            current_idx = inter_idx;
            if !visited.insert(issuer.subject().to_string()) {
                return Err(BridgeError::Rejected("chain loop detected".into()));
            }
        }
        Err(BridgeError::Rejected(format!(
            "chain exceeds max depth {} without reaching trust anchor",
            max
        )))
    }

    fn project(
        &self,
        leaf: &X509Certificate,
        root: &X509Certificate,
        chain_subjects: Vec<String>,
    ) -> Result<TlsVerificationResult, BridgeError> {
        let san_uris = collect_san_uris(leaf);
        if let Some(req) = &self.cfg.required_san_uri {
            if !san_uris.iter().any(|u| u == req) {
                return Err(BridgeError::Rejected(format!(
                    "leaf SAN URIs {:?} missing required {}",
                    san_uris, req
                )));
            }
        }
        let cn = parse_common_name(&leaf.subject().to_string());
        let san_dns = collect_san_dns(leaf);
        let spiffe_san = san_uris.iter().find(|u| u.starts_with("spiffe://")).cloned();
        let subject = spiffe_san
            .clone()
            .or(cn.clone())
            .or_else(|| san_dns.first().cloned())
            .unwrap_or_else(|| leaf.subject().to_string());
        let actor_type = if spiffe_san.is_some() {
            ActorType::Service
        } else {
            ActorType::Device
        };
        let type_str = match actor_type {
            ActorType::Service => "service",
            _ => "device",
        };
        let actor_id = format!(
            "tf:actor:{}:{}/{}",
            type_str,
            self.cfg.trust_domain,
            encode_actor_path(&subject)
        );

        let pk = leaf.public_key();
        let alg_oid = pk.algorithm.algorithm.to_id_string();
        let algorithm = match alg_oid.as_str() {
            "1.2.840.113549.1.1.1" => "rsa",
            "1.2.840.10045.2.1" => "p256",
            "1.3.101.112" => "ed25519",
            _ => "unknown",
        };
        let public_key_b64 = base64::engine::general_purpose::STANDARD
            .encode(pk.subject_public_key.data.as_ref());

        let fingerprint = sha256_hex(leaf.as_ref());

        let identity = ActorIdentity {
            identity_version: ActorIdentity_IdentityVersion::V1,
            actor_id,
            actor_type: actor_type.clone(),
            instance_id: None,
            public_keys: vec![PublicKey {
                key_id: fingerprint,
                algorithm: algorithm.to_string(),
                public_key: public_key_b64,
                purpose: PublicKey_Purpose::Signing,
                valid_from: None,
                valid_until: None,
            }],
            trust_levels: vec![if matches!(actor_type, ActorType::Service) {
                TrustLevel::T4
            } else {
                TrustLevel::T3
            }],
            authority_roots: vec![AuthorityRoot {
                kind: AuthorityRoot_Kind::Organization,
                id: parse_common_name(&root.subject().to_string())
                    .unwrap_or_else(|| root.subject().to_string()),
            }],
            attestations: None,
            valid_from: rfc3339_from_unix(leaf.validity().not_before.timestamp()),
            valid_until: Some(rfc3339_from_unix(leaf.validity().not_after.timestamp())),
            revocation_ref: None,
            signature: None,
        };

        let capabilities = collect_eku_actions(leaf);

        Ok(TlsVerificationResult {
            identity,
            capabilities,
            leaf_subject: leaf.subject().to_string(),
            chain_subjects,
        })
    }
}

impl Bridge for TlsBridge {
    fn bridge_id(&self) -> &str {
        &self.cfg.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::Tls
    }
    fn trust_domain(&self) -> &str {
        &self.cfg.trust_domain
    }
}

fn parse_single_pem(pem: &str) -> Result<Vec<u8>, String> {
    let mut all = parse_pem_bundle(pem)?;
    if all.is_empty() {
        return Err("no CERTIFICATE block".into());
    }
    Ok(all.remove(0))
}

fn parse_pem_bundle(pem: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut bytes = pem.as_bytes();
    let mut out = Vec::new();
    while !bytes.is_empty() {
        match Pem::read(std::io::Cursor::new(bytes)) {
            Ok((p, consumed)) => {
                if p.label != "CERTIFICATE" {
                    bytes = &bytes[consumed..];
                    continue;
                }
                out.push(p.contents);
                bytes = &bytes[consumed..];
            }
            Err(_) => break,
        }
    }
    Ok(out)
}

fn collect_san_uris(cert: &X509Certificate) -> Vec<String> {
    cert.extensions()
        .iter()
        .flat_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => san
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::URI(u) => Some(u.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        })
        .collect()
}

fn collect_san_dns(cert: &X509Certificate) -> Vec<String> {
    cert.extensions()
        .iter()
        .flat_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => san
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::DNSName(d) => Some(d.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        })
        .collect()
}

fn collect_eku_actions(cert: &X509Certificate) -> Vec<String> {
    let mut out = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
            if eku.any {
                continue;
            }
            for oid in &eku.other {
                if let Some(action) = default_eku_to_action(&oid.to_id_string()) {
                    out.push(action.to_string());
                }
            }
            if eku.client_auth {
                out.push("tls.client-auth".to_string());
            }
            if eku.server_auth {
                out.push("tls.server-auth".to_string());
            }
            if eku.code_signing {
                out.push("code.sign".to_string());
            }
            if eku.email_protection {
                out.push("email.protect".to_string());
            }
            if eku.time_stamping {
                out.push("timestamp.sign".to_string());
            }
            if eku.ocsp_signing {
                out.push("ocsp.sign".to_string());
            }
        }
    }
    // Deduplicate while preserving order.
    let mut seen = HashSet::new();
    out.into_iter()
        .filter(|s| seen.insert(s.clone()))
        .collect()
}

fn parse_common_name(distinguished_name: &str) -> Option<String> {
    for part in distinguished_name.split(['\n', ',']) {
        let trimmed = part.trim();
        if let Some(rest) = trimmed
            .strip_prefix("CN=")
            .or_else(|| trimmed.strip_prefix("cn="))
        {
            return Some(rest.to_string());
        }
    }
    None
}

fn encode_actor_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

fn rfc3339_from_unix(secs: i64) -> String {
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
    let m = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d, hour, minute, second)
}

use base64::Engine as _;

// =============================================================================
// OCSP, CRL, exporter binding, and post-handshake re-auth modules.
//
// These extensions mirror the TS surface in `tools/tf-types-ts/src/core/bridge-tls.ts`
// (`checkRevocation`, `deriveExporterKey`, `postHandshakeReauth`). They are
// intentionally network-free: the caller supplies an `OcspFetcher` for OCSP
// lookups and pre-loaded DER bytes for CRL parsing. RFC references:
//   - RFC 6960 (OCSP)
//   - RFC 5280 (CRL profile)
//   - RFC 5705 / RFC 8446 §7.5 (TLS exporters)
//   - RFC 8446 §4.6.2 (post-handshake authentication)
// =============================================================================

/// X.509 certificate handle used by the OCSP / CRL helpers. We deliberately
/// keep this thin (raw DER + cached subject + serial) so callers don't have
/// to depend on `x509-parser`'s `X509Certificate` lifetime in their own
/// types.
#[derive(Clone, Debug)]
pub struct X509Cert {
    pub der: Vec<u8>,
    pub subject: String,
    pub serial_be: Vec<u8>,
}

impl X509Cert {
    /// Parse a single DER blob into an `X509Cert` snapshot.
    pub fn from_der(der: &[u8]) -> Result<Self, BridgeError> {
        let (_, parsed) = X509Certificate::from_der(der)
            .map_err(|e| BridgeError::InvalidInput(format!("X509Cert: {}", e)))?;
        let serial_be = parsed.tbs_certificate.raw_serial().to_vec();
        Ok(X509Cert {
            der: der.to_vec(),
            subject: parsed.subject().to_string(),
            serial_be,
        })
    }

    /// Parse a single PEM block into an `X509Cert`.
    pub fn from_pem(pem: &str) -> Result<Self, BridgeError> {
        let der = parse_single_pem(pem)
            .map_err(|e| BridgeError::InvalidInput(format!("X509Cert PEM: {}", e)))?;
        Self::from_der(&der)
    }
}

// ----- OCSP -----------------------------------------------------------------

/// The decision an OCSP responder returned for a particular certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OcspStatus {
    Good,
    Revoked,
    Unknown,
}

/// Trait for callers who actually speak OCSP. Implementations receive the
/// `(cert, issuer, ocsp_url)` triple and return DER bytes of an
/// `OCSPResponse` (RFC 6960). The bridge does no network IO itself.
pub trait OcspFetcher {
    fn fetch(
        &self,
        cert: &X509Cert,
        issuer: &X509Cert,
        ocsp_url: &str,
    ) -> Result<Vec<u8>, BridgeError>;
}

/// Errors that can come out of OCSP DER parsing / status extraction.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OcspError {
    #[error("OCSP DER parse failed: {0}")]
    Parse(String),
    #[error("OCSP responder returned status code {0}")]
    ResponderError(u8),
    #[error("OCSP response is not a BasicOCSPResponse")]
    NotBasic,
    #[error("OCSP response thisUpdate={this_update} > now={now}")]
    NotYetValid { this_update: i64, now: i64 },
    #[error("OCSP response nextUpdate={next_update} < now={now}")]
    Stale { next_update: i64, now: i64 },
    #[error("OCSP response contained no SingleResponse entries")]
    NoSingleResponses,
}

/// Stateless OCSP checker. Holds no configuration; the caller selects a
/// fetcher and clock per call.
pub struct OcspCheck;

impl OcspCheck {
    /// Run an OCSP query for `cert` (issued by `issuer`). The `fetcher`
    /// returns DER for an `OCSPResponse`; we parse it, sanity-check the
    /// `thisUpdate`/`nextUpdate` window against `now_unix_seconds`, and
    /// extract the status for the first `SingleResponse`.
    pub fn query(
        cert: &X509Cert,
        issuer: &X509Cert,
        fetcher: &dyn OcspFetcher,
        ocsp_url: &str,
        now_unix_seconds: i64,
    ) -> Result<OcspStatus, BridgeError> {
        let der = fetcher.fetch(cert, issuer, ocsp_url)?;
        Self::parse_response(&der, now_unix_seconds).map_err(|e| match e {
            OcspError::Parse(s) => BridgeError::InvalidInput(format!("OCSP: {}", s)),
            OcspError::ResponderError(n) => {
                BridgeError::Rejected(format!("OCSP responder error {}", n))
            }
            OcspError::NotBasic => BridgeError::Rejected("OCSP not BasicOCSPResponse".into()),
            OcspError::NotYetValid { this_update, now } => BridgeError::Rejected(format!(
                "OCSP thisUpdate={} > now={}",
                this_update, now
            )),
            OcspError::Stale { next_update, now } => {
                BridgeError::Rejected(format!("OCSP nextUpdate={} < now={}", next_update, now))
            }
            OcspError::NoSingleResponses => {
                BridgeError::Rejected("OCSP had no SingleResponse entries".into())
            }
        })
    }

    /// Pure parser: walks the DER tree, validates the time window, and
    /// returns the status of the first `SingleResponse`. Exposed for
    /// testing.
    pub fn parse_response(der: &[u8], now_unix_seconds: i64) -> Result<OcspStatus, OcspError> {
        let parsed = ocsp::parse_ocsp_response(der)?;
        if parsed.response_status != 0 {
            return Err(OcspError::ResponderError(parsed.response_status));
        }
        let basic = parsed.basic.ok_or(OcspError::NotBasic)?;
        let single = basic
            .single_responses
            .first()
            .ok_or(OcspError::NoSingleResponses)?;
        if single.this_update > now_unix_seconds {
            return Err(OcspError::NotYetValid {
                this_update: single.this_update,
                now: now_unix_seconds,
            });
        }
        if let Some(next) = single.next_update {
            if next < now_unix_seconds {
                return Err(OcspError::Stale {
                    next_update: next,
                    now: now_unix_seconds,
                });
            }
        }
        Ok(single.status.clone())
    }
}

/// Internal OCSP DER walker. Implements the *minimum* RFC 6960 surface needed
/// to decide good / revoked / unknown for the first SingleResponse and
/// validate the freshness window. We do not verify the responder signature
/// here; callers that need that should layer their own verification on top
/// (the responder ID is exposed in `BasicResponseData`). This is consistent
/// with the TS bridge, which also delegates signature verification to the
/// caller via the `OcspStatusResolver` callback.
pub mod ocsp {
    use super::OcspError;
    use super::OcspStatus;

    #[derive(Clone, Debug)]
    pub struct SingleResponse {
        pub status: OcspStatus,
        pub this_update: i64,
        pub next_update: Option<i64>,
    }

    #[derive(Clone, Debug)]
    pub struct BasicResponseData {
        pub single_responses: Vec<SingleResponse>,
    }

    #[derive(Clone, Debug)]
    pub struct OcspResponse {
        pub response_status: u8,
        pub basic: Option<BasicResponseData>,
    }

    /// OID `1.3.6.1.5.5.7.48.1.1` — `id-pkix-ocsp-basic`.
    const ID_PKIX_OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

    pub fn parse_ocsp_response(der: &[u8]) -> Result<OcspResponse, OcspError> {
        let outer = read_seq(der, 0).ok_or_else(|| OcspError::Parse("outer SEQUENCE".into()))?;
        let mut p = outer.content_start;
        let end = outer.content_start + outer.content_len;

        // responseStatus ENUMERATED
        let status_tlv =
            read_tlv(der, p).ok_or_else(|| OcspError::Parse("responseStatus tag".into()))?;
        if status_tlv.tag != 0x0a {
            return Err(OcspError::Parse(format!(
                "responseStatus expected ENUMERATED (0x0a), got 0x{:02x}",
                status_tlv.tag
            )));
        }
        if status_tlv.content_len != 1 {
            return Err(OcspError::Parse("responseStatus len != 1".into()));
        }
        let response_status = der[status_tlv.content_start];
        p = status_tlv.content_start + status_tlv.content_len;

        let mut basic: Option<BasicResponseData> = None;
        if p < end {
            // [0] EXPLICIT ResponseBytes OPTIONAL
            let rb_tlv = read_tlv(der, p).ok_or_else(|| OcspError::Parse("[0] tag".into()))?;
            if rb_tlv.tag == 0xa0 {
                let rb_seq = read_seq(der, rb_tlv.content_start)
                    .ok_or_else(|| OcspError::Parse("ResponseBytes SEQUENCE".into()))?;
                let mut q = rb_seq.content_start;
                let oid_tlv =
                    read_tlv(der, q).ok_or_else(|| OcspError::Parse("responseType OID".into()))?;
                if oid_tlv.tag != 0x06 {
                    return Err(OcspError::Parse("responseType not OID".into()));
                }
                let oid_bytes =
                    &der[oid_tlv.content_start..oid_tlv.content_start + oid_tlv.content_len];
                if oid_bytes != ID_PKIX_OCSP_BASIC {
                    // Not a BasicOCSPResponse — leave `basic` as None.
                } else {
                    q = oid_tlv.content_start + oid_tlv.content_len;
                    let response_octets = read_tlv(der, q)
                        .ok_or_else(|| OcspError::Parse("response OCTET STRING".into()))?;
                    if response_octets.tag != 0x04 {
                        return Err(OcspError::Parse("response not OCTET STRING".into()));
                    }
                    let basic_der = &der[response_octets.content_start
                        ..response_octets.content_start + response_octets.content_len];
                    basic = Some(parse_basic_response(basic_der)?);
                }
            }
        }

        Ok(OcspResponse {
            response_status,
            basic,
        })
    }

    fn parse_basic_response(der: &[u8]) -> Result<BasicResponseData, OcspError> {
        let basic_seq =
            read_seq(der, 0).ok_or_else(|| OcspError::Parse("BasicOCSPResponse SEQ".into()))?;
        let tbs = read_seq(der, basic_seq.content_start)
            .ok_or_else(|| OcspError::Parse("tbsResponseData SEQ".into()))?;
        // Inside tbsResponseData: skip optional [0] version, responderID,
        // producedAt, responses SEQUENCE OF SingleResponse, [1] responseExtensions.
        let mut p = tbs.content_start;
        let end = tbs.content_start + tbs.content_len;
        // optional [0] version
        if p < end && der[p] == 0xa0 {
            let v = read_tlv(der, p).ok_or_else(|| OcspError::Parse("version".into()))?;
            p = v.content_start + v.content_len;
        }
        // responderID is CHOICE [1] byName Name | [2] byKey KeyHash; both are tagged.
        if p < end {
            let r = read_tlv(der, p).ok_or_else(|| OcspError::Parse("responderID".into()))?;
            p = r.content_start + r.content_len;
        }
        // producedAt GeneralizedTime
        if p < end {
            let pa = read_tlv(der, p).ok_or_else(|| OcspError::Parse("producedAt".into()))?;
            p = pa.content_start + pa.content_len;
        }
        // responses SEQUENCE OF SingleResponse
        let resp_seq = read_seq(der, p)
            .ok_or_else(|| OcspError::Parse("responses SEQUENCE OF".into()))?;
        let mut single_responses: Vec<SingleResponse> = Vec::new();
        let mut q = resp_seq.content_start;
        let qend = resp_seq.content_start + resp_seq.content_len;
        while q < qend {
            let sr = read_seq(der, q).ok_or_else(|| OcspError::Parse("SingleResponse".into()))?;
            single_responses.push(parse_single_response(
                &der[sr.content_start..sr.content_start + sr.content_len],
            )?);
            q = sr.content_start + sr.content_len;
        }
        Ok(BasicResponseData { single_responses })
    }

    fn parse_single_response(der: &[u8]) -> Result<SingleResponse, OcspError> {
        // SingleResponse ::= SEQUENCE { certID, certStatus, thisUpdate,
        //                                nextUpdate [0] OPTIONAL, ... }
        let mut p = 0usize;
        let end = der.len();
        // certID SEQUENCE
        let cert_id =
            read_seq(der, p).ok_or_else(|| OcspError::Parse("certID".into()))?;
        p = cert_id.content_start + cert_id.content_len;
        // certStatus CHOICE
        let cs = read_tlv(der, p).ok_or_else(|| OcspError::Parse("certStatus".into()))?;
        let status = match cs.tag {
            0x80 => OcspStatus::Good,    // [0] IMPLICIT NULL
            0xa1 => OcspStatus::Revoked, // [1] IMPLICIT RevokedInfo
            0x82 => OcspStatus::Unknown, // [2] IMPLICIT UnknownInfo
            other => {
                return Err(OcspError::Parse(format!(
                    "unknown certStatus tag 0x{:02x}",
                    other
                )))
            }
        };
        p = cs.content_start + cs.content_len;
        // thisUpdate GeneralizedTime (tag 0x18)
        let tu = read_tlv(der, p).ok_or_else(|| OcspError::Parse("thisUpdate".into()))?;
        if tu.tag != 0x18 {
            return Err(OcspError::Parse(format!(
                "thisUpdate expected 0x18, got 0x{:02x}",
                tu.tag
            )));
        }
        let this_update =
            parse_generalized_time(&der[tu.content_start..tu.content_start + tu.content_len])?;
        p = tu.content_start + tu.content_len;
        // optional [0] nextUpdate
        let mut next_update: Option<i64> = None;
        if p < end && der[p] == 0xa0 {
            let nu_outer =
                read_tlv(der, p).ok_or_else(|| OcspError::Parse("nextUpdate [0]".into()))?;
            let inner = read_tlv(der, nu_outer.content_start)
                .ok_or_else(|| OcspError::Parse("nextUpdate inner".into()))?;
            if inner.tag != 0x18 {
                return Err(OcspError::Parse(format!(
                    "nextUpdate expected 0x18, got 0x{:02x}",
                    inner.tag
                )));
            }
            next_update = Some(parse_generalized_time(
                &der[inner.content_start..inner.content_start + inner.content_len],
            )?);
        }
        Ok(SingleResponse {
            status,
            this_update,
            next_update,
        })
    }

    /// Parse a YYYYMMDDHHMMSS[.fff]Z GeneralizedTime into a unix timestamp.
    /// Only the `Z` (UTC) form is accepted — RFC 5280 / 6960 require it.
    fn parse_generalized_time(bytes: &[u8]) -> Result<i64, OcspError> {
        let s = std::str::from_utf8(bytes)
            .map_err(|_| OcspError::Parse("generalized time non-utf8".into()))?;
        if !s.ends_with('Z') {
            return Err(OcspError::Parse(
                "generalized time must be Zulu-suffixed".into(),
            ));
        }
        let core = &s[..s.len() - 1];
        if core.len() < 14 {
            return Err(OcspError::Parse("generalized time too short".into()));
        }
        let y: i32 = core[0..4]
            .parse()
            .map_err(|_| OcspError::Parse("year".into()))?;
        let m: u32 = core[4..6]
            .parse()
            .map_err(|_| OcspError::Parse("month".into()))?;
        let d: u32 = core[6..8]
            .parse()
            .map_err(|_| OcspError::Parse("day".into()))?;
        let hh: u32 = core[8..10]
            .parse()
            .map_err(|_| OcspError::Parse("hour".into()))?;
        let mm: u32 = core[10..12]
            .parse()
            .map_err(|_| OcspError::Parse("min".into()))?;
        let ss: u32 = core[12..14]
            .parse()
            .map_err(|_| OcspError::Parse("sec".into()))?;
        Ok(ymdhms_to_unix(y, m, d, hh, mm, ss))
    }

    fn ymdhms_to_unix(y: i32, m: u32, d: u32, hh: u32, mm: u32, ss: u32) -> i64 {
        // Inverse of `secs_to_ymdhms` in the surrounding module. Howard Hinnant's
        // days_from_civil algorithm.
        let yy = if m <= 2 { y - 1 } else { y } as i64;
        let era = if yy >= 0 { yy } else { yy - 399 } / 400;
        let yoe = (yy - era * 400) as u64;
        let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
        let doy = (153 * mp + 2) / 5 + (d as u64) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe as i64 - 719_468;
        days * 86_400 + hh as i64 * 3600 + mm as i64 * 60 + ss as i64
    }

    // ---- TLV walker ---------------------------------------------------------

    pub(crate) struct Tlv {
        pub tag: u8,
        pub content_start: usize,
        pub content_len: usize,
    }

    pub(crate) fn read_seq(buf: &[u8], pos: usize) -> Option<Tlv> {
        let t = read_tlv(buf, pos)?;
        if t.tag != 0x30 {
            return None;
        }
        Some(t)
    }

    pub(crate) fn read_tlv(buf: &[u8], pos: usize) -> Option<Tlv> {
        if pos >= buf.len() {
            return None;
        }
        let tag = buf[pos];
        let (len, header) = read_length(buf, pos + 1)?;
        if pos + 1 + header + len > buf.len() {
            return None;
        }
        Some(Tlv {
            tag,
            content_start: pos + 1 + header,
            content_len: len,
        })
    }

    fn read_length(buf: &[u8], pos: usize) -> Option<(usize, usize)> {
        if pos >= buf.len() {
            return None;
        }
        let b = buf[pos];
        if b < 0x80 {
            return Some((b as usize, 1));
        }
        let n = (b & 0x7f) as usize;
        if n == 0 || n > 4 || pos + n >= buf.len() {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..n {
            len = (len << 8) | buf[pos + 1 + i] as usize;
        }
        Some((len, 1 + n))
    }
}

// ----- CRL ------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationEntry {
    /// Big-endian serial number bytes (no DER tag/length prefix, no sign byte).
    pub serial_be: Vec<u8>,
    /// `revocationDate` as a unix timestamp.
    pub revocation_date: i64,
    /// Optional `reasonCode` extension (RFC 5280 §5.3.1). `None` if absent.
    pub reason_code: Option<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CrlError {
    #[error("CRL DER parse failed: {0}")]
    Parse(String),
}

/// Indexed CRL — a parsed RFC 5280 v2 CRL with a `BTreeMap` keyed on serial
/// for `O(log n)` lookups. We hold the *normalised* big-endian serial bytes
/// (leading 0x00 sign-extension byte stripped), so callers can pass
/// either `cert.serial_be` or a raw hex value normalised the same way.
pub struct CrlIndex {
    pub issuer: String,
    pub this_update: i64,
    pub next_update: Option<i64>,
    revoked: std::collections::BTreeMap<Vec<u8>, RevocationEntry>,
}

impl CrlIndex {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn len(&self) -> usize {
        self.revoked.len()
    }
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
    /// Fast lookup. Pass big-endian serial bytes; we normalise the leading
    /// 0x00 byte that DER inserts on positive integers whose top bit is
    /// set, so `0x00 || …` and the bare integer compare equal.
    pub fn is_revoked(&self, serial_be: &[u8]) -> Option<&RevocationEntry> {
        let key = normalise_serial(serial_be);
        self.revoked.get(&key)
    }
    /// Iterator over all entries (sorted by serial).
    pub fn entries(&self) -> impl Iterator<Item = &RevocationEntry> {
        self.revoked.values()
    }
}

fn normalise_serial(serial_be: &[u8]) -> Vec<u8> {
    let mut s = serial_be;
    while s.len() > 1 && s[0] == 0x00 {
        s = &s[1..];
    }
    s.to_vec()
}

pub struct CrlCheck;

impl CrlCheck {
    pub fn load(crl_bytes: &[u8]) -> Result<CrlIndex, CrlError> {
        use x509_parser::revocation_list::CertificateRevocationList;
        let (_, crl) = CertificateRevocationList::from_der(crl_bytes)
            .map_err(|e| CrlError::Parse(format!("{}", e)))?;
        let issuer = crl.issuer().to_string();
        let this_update = crl.last_update().timestamp();
        let next_update = crl.next_update().map(|t| t.timestamp());
        let mut revoked = std::collections::BTreeMap::new();
        for r in crl.iter_revoked_certificates() {
            let serial_be = normalise_serial(r.raw_serial());
            let revocation_date = r.revocation_date.timestamp();
            let reason_code = r
                .extensions()
                .iter()
                .find_map(|ext| match ext.parsed_extension() {
                    x509_parser::extensions::ParsedExtension::ReasonCode(rc) => Some(rc.0),
                    _ => None,
                });
            revoked.insert(
                serial_be.clone(),
                RevocationEntry {
                    serial_be,
                    revocation_date,
                    reason_code,
                },
            );
        }
        Ok(CrlIndex {
            issuer,
            this_update,
            next_update,
            revoked,
        })
    }
}

// ----- Exporter binding ------------------------------------------------------

pub struct ExporterBinding;

impl ExporterBinding {
    /// Mirrors `TlsBridge.deriveExporterKey` in TS:
    ///   salt = utf8("tf-tls-exporter:" + label)
    ///   ikm  = transport_secret || context
    ///   prk1 = HMAC-SHA256(salt, ikm)
    ///   okm  = HKDF(sha256, prk1, salt=undefined, info=salt, length)
    ///        = HKDF-Expand(HMAC-SHA256(zeros[32], prk1), info=salt, length)
    ///
    /// This is *not* RFC 5705 by itself — the `transport_secret` is the
    /// output of `RFC 5705 §4` exporter on the underlying TLS / QUIC
    /// session, and we layer another HKDF on top so the TrustForge
    /// session PSK is domain-separated from anything the application
    /// may already derive from the same exporter.
    pub fn derive(
        transport_secret: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Vec<u8> {
        if transport_secret.is_empty() {
            // Stay in lock-step with the TS bridge, which throws on empty.
            // We can't return BridgeError here; the TS shape uses a runtime
            // exception. Returning an empty vec would be misleading, so we
            // panic — same effect as a thrown exception, same surface as
            // `expect("non-empty")` elsewhere in this crate.
            panic!("ExporterBinding::derive: transport_secret must be non-empty");
        }
        let salt_str = format!("tf-tls-exporter:{}", label);
        let salt = salt_str.as_bytes();

        // prk1 = HMAC-SHA256(salt, ikm)
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(salt).expect("hmac key");
        mac.update(transport_secret);
        mac.update(context);
        let prk1 = mac.finalize().into_bytes();

        // okm = HKDF(prk1, salt=undefined → zero, info=salt, length)
        // i.e. extract zeros over prk1, then expand with info=salt.
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &prk1);
        let mut out = vec![0u8; length];
        hk.expand(salt, &mut out).expect("HKDF expand");
        out
    }
}

// ----- Post-handshake re-auth ------------------------------------------------

pub struct PostHandshakeReauth;

impl PostHandshakeReauth {
    /// Returns 32 random challenge bytes the verifier sends to the peer.
    pub fn challenge() -> Vec<u8> {
        use rand::RngCore;
        let mut buf = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        buf
    }

    /// Verifies an Ed25519 signature over the previously issued challenge.
    /// Returns `true` iff the signature is valid.
    pub fn verify_response(
        challenge: &[u8],
        pubkey: &[u8; 32],
        signature: &[u8; 64],
    ) -> bool {
        crate::crypto::ed25519_verify(pubkey, challenge, signature).is_ok()
    }
}
