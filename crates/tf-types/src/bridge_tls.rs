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
