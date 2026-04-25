//! tf-rocket — Rocket fairing that calls `tf-daemon`'s `/v1/decide`.
//!
//! Attach [`TrustForgeFairing`] with `rocket::build().attach(...)`. Every
//! incoming request is gated against the daemon. On allow, the [`TfDecision`]
//! is stashed in `request.local_cache` for handlers to inspect.
//! On deny / approval, the response is rewritten to 403 / 202 before the
//! handler runs.

use std::sync::Arc;

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Status;
use rocket::tokio::sync::Mutex;
use rocket::{Data, Request, Response};

use tf_decide_client::{DecideRequest, DecideResponse, TfDecideClient};

pub use tf_decide_client;

#[derive(Clone, Debug)]
pub struct TrustForgeOpts {
    pub host_token_header: String,
    pub host_token_kind: Option<String>,
    pub strip_bearer: bool,
    pub fail_open: bool,
}

impl Default for TrustForgeOpts {
    fn default() -> Self {
        Self {
            host_token_header: "authorization".into(),
            host_token_kind: None,
            strip_bearer: true,
            fail_open: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TfDecision(pub DecideResponse);

#[derive(Default, Clone)]
struct TfSlot {
    inner: Arc<Mutex<Option<TfOutcome>>>,
}

#[derive(Clone)]
enum TfOutcome {
    Allow(DecideResponse),
    Deny(DecideResponse),
    Approval(DecideResponse),
    Error(String),
    Unknown(String),
}

#[derive(Clone)]
pub struct TrustForgeFairing {
    client: TfDecideClient,
    opts: Arc<TrustForgeOpts>,
}

impl TrustForgeFairing {
    pub fn new(client: TfDecideClient, opts: TrustForgeOpts) -> Self {
        Self {
            client,
            opts: Arc::new(opts),
        }
    }
}

#[rocket::async_trait]
impl Fairing for TrustForgeFairing {
    fn info(&self) -> Info {
        Info {
            name: "tf-rocket TrustForge gate",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _data: &mut Data<'_>) {
        let action = format!("{} {}", req.method().as_str(), req.uri().path());
        let target = req.uri().to_string();
        let raw_token = req
            .headers()
            .get_one(self.opts.host_token_header.as_str())
            .map(|s| s.to_string());
        let host_token = raw_token.map(|s| {
            if self.opts.strip_bearer {
                s.strip_prefix("Bearer ")
                    .or_else(|| s.strip_prefix("bearer "))
                    .map(|x| x.to_string())
                    .unwrap_or(s)
            } else {
                s
            }
        });
        let trace_id = req.headers().get_one("x-trace-id").map(|s| s.to_string());

        let body = DecideRequest {
            action,
            host_token,
            host_token_kind: self.opts.host_token_kind.clone(),
            target: Some(target),
            trace_id,
            ..Default::default()
        };

        let outcome = match self.client.decide(&body).await {
            Ok(d) => match d.decision.to_ascii_lowercase().as_str() {
                "allow" => TfOutcome::Allow(d),
                "deny" => TfOutcome::Deny(d),
                "approval" | "approval_required" | "approval-required" => TfOutcome::Approval(d),
                other => TfOutcome::Unknown(other.to_string()),
            },
            Err(e) => {
                if self.opts.fail_open {
                    TfOutcome::Allow(DecideResponse {
                        decision: "allow".into(),
                        reason: format!("fail_open: {e}"),
                        approval_id: None,
                        proof_id: String::new(),
                        actor_resolved: None,
                        trust_level: None,
                        authority_mode: None,
                        danger_tags: vec![],
                    })
                } else {
                    TfOutcome::Error(e.to_string())
                }
            }
        };

        let slot: &TfSlot = req.local_cache(TfSlot::default);
        *slot.inner.lock().await = Some(outcome);
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, resp: &mut Response<'r>) {
        let slot: &TfSlot = req.local_cache(TfSlot::default);
        let outcome = slot.inner.lock().await.clone();
        match outcome {
            Some(TfOutcome::Allow(_)) | None => {}
            Some(TfOutcome::Deny(d)) => {
                let body = serde_json::json!({
                    "error": "tf_denied",
                    "reason": d.reason,
                    "proof_id": d.proof_id,
                    "danger_tags": d.danger_tags,
                });
                resp.set_status(Status::Forbidden);
                resp.set_sized_body(None, std::io::Cursor::new(body.to_string()));
                resp.set_raw_header("content-type", "application/json");
            }
            Some(TfOutcome::Approval(d)) => {
                let body = serde_json::json!({
                    "status": "approval_required",
                    "approval_id": d.approval_id,
                    "proof_id": d.proof_id,
                    "reason": d.reason,
                });
                resp.set_status(Status::Accepted);
                resp.set_sized_body(None, std::io::Cursor::new(body.to_string()));
                resp.set_raw_header("content-type", "application/json");
            }
            Some(TfOutcome::Error(detail)) => {
                let body = serde_json::json!({
                    "error": "tf_decide_unreachable",
                    "detail": detail,
                });
                resp.set_status(Status::ServiceUnavailable);
                resp.set_sized_body(None, std::io::Cursor::new(body.to_string()));
                resp.set_raw_header("content-type", "application/json");
            }
            Some(TfOutcome::Unknown(other)) => {
                let body = serde_json::json!({
                    "error": "tf_unknown_decision",
                    "decision": other,
                });
                resp.set_status(Status::BadGateway);
                resp.set_sized_body(None, std::io::Cursor::new(body.to_string()));
                resp.set_raw_header("content-type", "application/json");
            }
        }
    }
}
