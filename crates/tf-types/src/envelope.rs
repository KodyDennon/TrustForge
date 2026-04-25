//! Signature envelope shape validator — mirrors
//! `tools/tf-types-ts/src/core/envelope.ts`. No crypto is performed here;
//! real signing/verification lives in `crypto.rs`.

use crate::generated::common::SignatureEnvelope;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeIssue {
    MissingAlgorithm,
    MissingSigner,
    MissingSignature,
    InvalidBase64 { field: &'static str },
    AltWithoutAlgorithm,
    UnknownAlgorithm { algorithm: String },
    UnknownAltAlgorithm { algorithm: String },
}

impl EnvelopeIssue {
    pub fn is_warning(&self) -> bool {
        matches!(
            self,
            EnvelopeIssue::UnknownAlgorithm { .. } | EnvelopeIssue::UnknownAltAlgorithm { .. }
        )
    }
}

pub struct EnvelopeValidation {
    pub ok: bool,
    pub issues: Vec<EnvelopeIssue>,
}

const KNOWN_ALGORITHMS: &[&str] = &[
    "ed25519",
    "ed448",
    "p256",
    "p384",
    "p521",
    "rsa-pss-sha256",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "slh-dsa-sha2-128s",
    "slh-dsa-sha2-192s",
];

pub fn validate_envelope_shape(e: &SignatureEnvelope) -> EnvelopeValidation {
    let mut issues = Vec::new();

    if e.algorithm.is_empty() {
        issues.push(EnvelopeIssue::MissingAlgorithm);
    }
    if e.signer.is_empty() {
        issues.push(EnvelopeIssue::MissingSigner);
    }
    if e.signature.is_empty() {
        issues.push(EnvelopeIssue::MissingSignature);
    }
    if !e.signature.is_empty() && !is_base64(&e.signature) {
        issues.push(EnvelopeIssue::InvalidBase64 { field: "signature" });
    }
    if let Some(alt) = &e.alt_signature {
        if !is_base64(alt) {
            issues.push(EnvelopeIssue::InvalidBase64 {
                field: "alt_signature",
            });
        }
        if e.alt_algorithm.is_none() {
            issues.push(EnvelopeIssue::AltWithoutAlgorithm);
        }
    }

    let fatal_count = issues.iter().filter(|i| !i.is_warning()).count();

    if !e.algorithm.is_empty() && !KNOWN_ALGORITHMS.contains(&e.algorithm.as_str()) {
        issues.push(EnvelopeIssue::UnknownAlgorithm {
            algorithm: e.algorithm.clone(),
        });
    }
    if let Some(alt) = &e.alt_algorithm {
        if !KNOWN_ALGORITHMS.contains(&alt.as_str()) {
            issues.push(EnvelopeIssue::UnknownAltAlgorithm {
                algorithm: alt.clone(),
            });
        }
    }

    EnvelopeValidation {
        ok: fatal_count == 0,
        issues,
    }
}

fn is_base64(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut eq_seen = 0;
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' => {
                if eq_seen > 0 {
                    return false;
                }
            }
            '=' => {
                eq_seen += 1;
                if eq_seen > 2 {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}
