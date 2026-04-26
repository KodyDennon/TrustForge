//! Trust-domain parser mirroring `tools/tf-types-ts/src/core/trust-domain.ts`.

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrustDomainParseError {
    #[error("empty trust-domain")]
    Empty,
    #[error("malformed DNS trust-domain: {0:?}")]
    BadDns(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustDomainKind {
    Dns,
    Local,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTrustDomain {
    pub kind: TrustDomainKind,
    pub value: String,
    pub raw: String,
}

pub fn parse_trust_domain(s: &str) -> Result<ParsedTrustDomain, TrustDomainParseError> {
    if s.is_empty() {
        return Err(TrustDomainParseError::Empty);
    }
    if let Some(rest) = s.strip_prefix("local/") {
        if rest.is_empty() {
            return Err(TrustDomainParseError::Empty);
        }
        return Ok(ParsedTrustDomain {
            kind: TrustDomainKind::Local,
            value: rest.to_owned(),
            raw: s.to_owned(),
        });
    }
    if !is_dns_like(s) {
        return Err(TrustDomainParseError::BadDns(s.to_owned()));
    }
    Ok(ParsedTrustDomain {
        kind: TrustDomainKind::Dns,
        value: s.to_ascii_lowercase(),
        raw: s.to_owned(),
    })
}

pub fn trust_domain_equals(a: &str, b: &str) -> bool {
    match (parse_trust_domain(a), parse_trust_domain(b)) {
        (Ok(pa), Ok(pb)) => pa.kind == pb.kind && pa.value == pb.value,
        _ => false,
    }
}

fn is_dns_like(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if !is_alnum(first) || !is_alnum(last) {
        return false;
    }
    bytes
        .iter()
        .all(|b| is_alnum(*b) || *b == b'.' || *b == b'-')
}

fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}
