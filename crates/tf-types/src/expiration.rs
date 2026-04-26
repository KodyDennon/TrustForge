//! Capability / authority / token expiration helpers — Rust mirror of
//! `tools/tf-types-ts/src/core/expiration.ts`. Lexicographic RFC 3339
//! comparison so byte-for-byte parity with TS holds when both sides use
//! `Z`-suffixed UTC timestamps.

#[derive(Clone, Debug, Default)]
pub struct Window<'a> {
    pub valid_from: Option<&'a str>,
    pub valid_until: Option<&'a str>,
    pub expires_at: Option<&'a str>,
    pub not_before: Option<&'a str>,
    pub not_after: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpirationVerdict<'a> {
    Ok,
    NotYetValid { threshold: &'a str },
    Expired { threshold: &'a str },
}

impl<'a> ExpirationVerdict<'a> {
    pub fn ok(&self) -> bool {
        matches!(self, ExpirationVerdict::Ok)
    }
}

pub fn check_window<'a>(window: &'a Window<'a>, now: &str) -> ExpirationVerdict<'a> {
    let start = window.valid_from.or(window.not_before);
    let end = window
        .valid_until
        .or(window.expires_at)
        .or(window.not_after);
    if let Some(s) = start {
        if now < s {
            return ExpirationVerdict::NotYetValid { threshold: s };
        }
    }
    if let Some(e) = end {
        if now > e {
            return ExpirationVerdict::Expired { threshold: e };
        }
    }
    ExpirationVerdict::Ok
}

pub fn is_within_window(window: &Window<'_>, now: &str) -> bool {
    matches!(check_window(window, now), ExpirationVerdict::Ok)
}

pub fn is_expired(window: &Window<'_>, now: &str) -> bool {
    matches!(check_window(window, now), ExpirationVerdict::Expired { .. })
}
