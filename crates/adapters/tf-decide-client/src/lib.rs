//! tf-decide-client — minimal HTTP client to call tf-daemon's `/v1/decide` endpoint.
//!
//! This crate is consumed by every framework adapter (axum, tonic, actix-web,
//! rocket, warp, poem, salvo, hyper) so they share one wire format and one set
//! of decision/result types.
//!
//! Usage:
//!
//! ```no_run
//! # use tf_decide_client::{TfDecideClient, DecideRequest};
//! # async fn run() {
//! let client = TfDecideClient::new("http://127.0.0.1:7080", "admin-token");
//! let req = DecideRequest {
//!     action: "GET /api/widgets".into(),
//!     ..Default::default()
//! };
//! let _resp = client.decide(&req).await.unwrap();
//! # }
//! ```

use std::time::Duration;

use tf_transport::{HttpError, HttpRequest};

/// Errors returned by [`TfDecideClient::decide`].
#[derive(Debug)]
pub enum ClientError {
    Transport(HttpError),
    Status { status: u16, body: String },
    Encode(String),
    Decode(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Transport(e) => write!(f, "transport error: {e}"),
            ClientError::Status { status, body } => {
                write!(f, "daemon returned non-success status {status}: {body}")
            }
            ClientError::Encode(e) => write!(f, "encode error: {e}"),
            ClientError::Decode(e) => write!(f, "decode error: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<HttpError> for ClientError {
    fn from(e: HttpError) -> Self {
        ClientError::Transport(e)
    }
}

/// Decide-request body sent to tf-daemon.
#[derive(serde::Serialize, Default, Debug, Clone)]
pub struct DecideRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_token_kind: Option<String>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default)]
    pub context: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

/// Decide-response body returned by tf-daemon.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct DecideResponse {
    pub decision: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub approval_id: Option<String>,
    #[serde(default)]
    pub proof_id: String,
    #[serde(default)]
    pub actor_resolved: Option<String>,
    #[serde(default)]
    pub trust_level: Option<String>,
    #[serde(default)]
    pub authority_mode: Option<String>,
    #[serde(default)]
    pub danger_tags: Vec<String>,
}

/// Shared mini-client for `/v1/decide`.
#[derive(Clone, Debug)]
pub struct TfDecideClient {
    daemon_url: String,
    admin_token: String,
    timeout: Duration,
}

impl TfDecideClient {
    /// Build a new client. `daemon_url` must NOT end with a trailing slash.
    pub fn new(daemon_url: impl Into<String>, admin_token: impl Into<String>) -> Self {
        let mut url = daemon_url.into();
        while url.ends_with('/') {
            url.pop();
        }
        Self {
            daemon_url: url,
            admin_token: admin_token.into(),
            timeout: Duration::from_secs(5),
        }
    }

    /// Override the per-request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The daemon URL this client is bound to (sans trailing slash).
    pub fn daemon_url(&self) -> &str {
        &self.daemon_url
    }

    /// Call `POST {daemon}/v1/decide` and decode the response.
    pub async fn decide(&self, req: &DecideRequest) -> Result<DecideResponse, ClientError> {
        let url = format!("{}/v1/decide", self.daemon_url);
        let body = serde_json::to_vec(req).map_err(|e| ClientError::Encode(e.to_string()))?;
        let resp = HttpRequest::post(url)
            .bearer_auth(&self.admin_token)
            .json_body(body)
            .timeout(self.timeout)
            .send()
            .await?;
        if !(200..300).contains(&resp.status) {
            let body = String::from_utf8_lossy(&resp.body).to_string();
            return Err(ClientError::Status {
                status: resp.status,
                body,
            });
        }
        let parsed: DecideResponse =
            serde_json::from_slice(&resp.body).map_err(|e| ClientError::Decode(e.to_string()))?;
        Ok(parsed)
    }
}

/// Convenience: decision string is "allow" (case-insensitive).
pub fn is_allow(d: &DecideResponse) -> bool {
    d.decision.eq_ignore_ascii_case("allow")
}

/// Convenience: decision string is "deny" (case-insensitive).
pub fn is_deny(d: &DecideResponse) -> bool {
    d.decision.eq_ignore_ascii_case("deny")
}

/// Convenience: decision string is "approval" or "approval_required".
pub fn is_approval(d: &DecideResponse) -> bool {
    let s = d.decision.to_ascii_lowercase();
    s == "approval" || s == "approval_required" || s == "approval-required"
}
