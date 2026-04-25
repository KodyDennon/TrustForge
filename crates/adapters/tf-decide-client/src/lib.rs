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

use reqwest::Client;
use std::time::Duration;

/// Errors returned by [`TfDecideClient::decide`].
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("daemon returned non-success status {status}: {body}")]
    Status { status: u16, body: String },
    #[error("decode error: {0}")]
    Decode(String),
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
    http: Client,
}

impl TfDecideClient {
    /// Build a new client. `daemon_url` must NOT end with a trailing slash.
    pub fn new(daemon_url: impl Into<String>, admin_token: impl Into<String>) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest client");
        let mut url = daemon_url.into();
        while url.ends_with('/') {
            url.pop();
        }
        Self {
            daemon_url: url,
            admin_token: admin_token.into(),
            http,
        }
    }

    /// Build a client using a custom underlying [`reqwest::Client`].
    pub fn with_client(
        daemon_url: impl Into<String>,
        admin_token: impl Into<String>,
        http: Client,
    ) -> Self {
        let mut url = daemon_url.into();
        while url.ends_with('/') {
            url.pop();
        }
        Self {
            daemon_url: url,
            admin_token: admin_token.into(),
            http,
        }
    }

    /// The daemon URL this client is bound to (sans trailing slash).
    pub fn daemon_url(&self) -> &str {
        &self.daemon_url
    }

    /// Call `POST {daemon}/v1/decide` and decode the response.
    pub async fn decide(&self, req: &DecideRequest) -> Result<DecideResponse, ClientError> {
        let url = format!("{}/v1/decide", self.daemon_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.admin_token)
            .json(req)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Status {
                status: status.as_u16(),
                body,
            });
        }
        let parsed: DecideResponse = resp
            .json()
            .await
            .map_err(|e| ClientError::Decode(e.to_string()))?;
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
