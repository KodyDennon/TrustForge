// SPDX-License-Identifier: Apache-2.0
//
// tf-envoy-filter — TrustForge proxy-wasm HTTP filter for Envoy.
//
// On every HTTP request the filter:
//   1. Pulls `:authority`, `:path`, `Authorization`, `Cookie` headers.
//   2. Calls out to a configured `tf-daemon` cluster via Envoy's
//      `dispatch_http_call` (Envoy wasm callouts can only target a
//      cluster declared in the static config, typically the same cluster
//      ext_authz would point at).
//   3. On `decision: "allow"` it resumes the request; otherwise it
//      replies 403 with the daemon-supplied reason.
//
// Status: Draft (Phase 0). Experimental, not production-ready.

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};

#[cfg(target_arch = "wasm32")]
use alloc::boxed::Box;
#[cfg(target_arch = "wasm32")]
use alloc::vec;

#[cfg(target_arch = "wasm32")]
use proxy_wasm::traits::{Context, HttpContext, RootContext};
#[cfg(target_arch = "wasm32")]
use proxy_wasm::types::{Action, ContextType, LogLevel};

/// Default daemon cluster name. Override via filter config (`tf_cluster`).
pub const DEFAULT_DAEMON_CLUSTER: &str = "tf_daemon";

/// Default decide path on the daemon.
pub const DECIDE_PATH: &str = "/v1/decide";

/// Soft callout timeout in milliseconds.
pub const CALLOUT_TIMEOUT_MS: u64 = 2_000;

// ---------------------------------------------------------------------------
// Pure-data helpers (host-testable, no proxy-wasm runtime needed)
// ---------------------------------------------------------------------------

/// What we send to tf-daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecideRequest {
    pub actor: String,
    pub action: String,
    pub target: String,
}

impl DecideRequest {
    /// Hand-rolled JSON serialiser. Avoids pulling serde into the wasm cdylib.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"actor":{},"action":{},"target":{}}}"#,
            json_str(&self.actor),
            json_str(&self.action),
            json_str(&self.target),
        )
    }
}

/// What we expect back from tf-daemon.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DecideResponse {
    pub decision: String,
    pub reason: String,
}

/// Tiny one-shot JSON parser that pulls `decision` and `reason` out of a
/// flat `{...}` object. Good enough for our wire shape; **not** a general
/// JSON parser.
pub fn parse_decide_response(body: &[u8]) -> DecideResponse {
    let s = match core::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return DecideResponse::default(),
    };
    DecideResponse {
        decision: extract_str_field(s, "decision").unwrap_or_default(),
        reason: extract_str_field(s, "reason").unwrap_or_default(),
    }
}

/// Build a TF decide request from request headers.
///
/// `actor` is taken from the bearer/cookie credentials when present; an
/// empty string means "anonymous" and policy gets to decide. Real
/// deployments will configure the daemon to do its own credential
/// resolution — the filter just forwards the raw token.
pub fn build_decide_request(
    authority: &str,
    method: &str,
    path: &str,
    authz_header: Option<&str>,
    cookie_header: Option<&str>,
) -> DecideRequest {
    let actor = authz_header
        .map(|s| s.to_string())
        .or_else(|| cookie_header.map(|s| s.to_string()))
        .unwrap_or_default();

    DecideRequest {
        actor,
        action: format!("http.{}.{}", method.to_lowercase(), path_first_segment(path)),
        target: format!("{}{}", authority, path),
    }
}

fn path_first_segment(path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    let seg = trimmed.split(&['/', '?'][..]).next().unwrap_or("");
    if seg.is_empty() { "_root".to_string() } else { seg.to_string() }
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn extract_str_field(s: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let start = s.find(&needle)?;
    let after = &s[start + needle.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let body = &rest[1..];
    // Walk to the closing quote, honouring backslash escapes.
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                other => out.push(other),
            },
            c => out.push(c),
        }
    }
    None
}

// ---------------------------------------------------------------------------
// proxy-wasm bindings (only compiled for the wasm cdylib build)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(TfRoot { cluster: DEFAULT_DAEMON_CLUSTER.to_string() })
    });
}}

#[cfg(target_arch = "wasm32")]
struct TfRoot {
    cluster: String,
}

#[cfg(target_arch = "wasm32")]
impl Context for TfRoot {}

#[cfg(target_arch = "wasm32")]
impl RootContext for TfRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(TfHttp {
            cluster: self.cluster.clone(),
            pending: None,
        }))
    }
}

#[cfg(target_arch = "wasm32")]
struct TfHttp {
    cluster: String,
    pending: Option<u32>, // callout token
}

#[cfg(target_arch = "wasm32")]
impl Context for TfHttp {
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        let body = self
            .get_http_call_response_body(0, body_size)
            .unwrap_or_default();
        let resp = parse_decide_response(&body);
        if resp.decision == "allow" {
            self.resume_http_request();
        } else {
            let reason = if resp.reason.is_empty() {
                "TrustForge denied request".to_string()
            } else {
                resp.reason
            };
            self.send_http_response(
                403,
                vec![("content-type", "text/plain")],
                Some(reason.as_bytes()),
            );
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl HttpContext for TfHttp {
    fn on_http_request_headers(&mut self, _: usize, _end_of_stream: bool) -> Action {
        let authority = self.get_http_request_header(":authority").unwrap_or_default();
        let method = self.get_http_request_header(":method").unwrap_or_default();
        let path = self.get_http_request_header(":path").unwrap_or_default();
        let authz = self.get_http_request_header("authorization");
        let cookie = self.get_http_request_header("cookie");

        let req = build_decide_request(&authority, &method, &path, authz.as_deref(), cookie.as_deref());
        let body = req.to_json();

        let token = self.dispatch_http_call(
            &self.cluster,
            vec![
                (":method", "POST"),
                (":path", DECIDE_PATH),
                (":authority", &self.cluster),
                ("content-type", "application/json"),
            ],
            Some(body.as_bytes()),
            vec![],
            core::time::Duration::from_millis(CALLOUT_TIMEOUT_MS),
        );

        match token {
            Ok(tok) => {
                self.pending = Some(tok);
                Action::Pause
            }
            Err(_) => {
                // Fail closed.
                self.send_http_response(
                    503,
                    vec![("content-type", "text/plain")],
                    Some(b"TrustForge daemon unreachable"),
                );
                Action::Pause
            }
        }
    }
}
