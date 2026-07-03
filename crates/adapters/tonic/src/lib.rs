#![allow(clippy::result_large_err)]
//! tf-tonic — tonic gRPC interceptor that calls `tf-daemon`'s `/v1/decide`.
//!
//! `tonic`'s `Interceptor` trait is synchronous; it inspects request metadata
//! and either returns the request or rejects it with a `Status`. Because our
//! decide call is async, this crate exposes two flavours:
//!
//!  * [`TrustForgeInterceptor::check`] — async helper used by code that wants
//!    to pre-flight a `Request` before it hits the inner service.
//!  * [`tonic_interceptor`] — convenience that runs `check` on the current
//!    runtime via `tokio::runtime::Handle::current().block_on(...)`. This is
//!    the form that plugs into `tonic::service::interceptor`.
//!
//! Both produce a `tonic::Status::permission_denied` on `deny`,
//! `failed_precondition` on `approval_required`, and `unavailable` on
//! transport error (unless `fail_open` is set).

use std::sync::Arc;

use tf_decide_client::{DecideRequest, DecideResponse, TfDecideClient};
use tonic::{Request, Status};

pub use tf_decide_client;
pub use tf_otel;

/// Interceptor configuration.
#[derive(Clone, Debug)]
pub struct TrustForgeOpts {
    pub host_token_metadata: String,
    pub host_token_kind: Option<String>,
    pub strip_bearer: bool,
    pub fail_open: bool,
}

impl Default for TrustForgeOpts {
    fn default() -> Self {
        Self {
            host_token_metadata: "authorization".into(),
            host_token_kind: None,
            strip_bearer: true,
            fail_open: false,
        }
    }
}

/// Decision attached to allow-passed requests via `request.extensions_mut()`.
#[derive(Clone, Debug)]
pub struct TfDecision(pub DecideResponse);

#[derive(Clone)]
pub struct TrustForgeInterceptor {
    inner: Arc<Inner>,
}

struct Inner {
    client: TfDecideClient,
    opts: TrustForgeOpts,
}

impl std::fmt::Debug for TrustForgeInterceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustForgeInterceptor")
            .field("daemon_url", &self.inner.client.daemon_url())
            .field("opts", &self.inner.opts)
            .finish()
    }
}

impl TrustForgeInterceptor {
    pub fn new(client: TfDecideClient, opts: TrustForgeOpts) -> Self {
        Self {
            inner: Arc::new(Inner { client, opts }),
        }
    }

    pub fn opts(&self) -> &TrustForgeOpts {
        &self.inner.opts
    }

    /// Async preflight: returns `Ok(req)` (with `TfDecision` attached) on
    /// allow, or a `Status` rejection otherwise.
    pub async fn check<T>(&self, mut req: Request<T>) -> Result<Request<T>, Status> {
        // One `tf.daemon.decide` span per gRPC call. We populate
        // tf.action up front (it's the gRPC method path) and fill in
        // tf.decision / tf.actor_resolved once the daemon answers.
        let span = tracing::info_span!(
            "tf.daemon.decide",
            otel.name = "tf.daemon.decide",
            tf.action = tracing::field::Empty,
            tf.decision = tracing::field::Empty,
            tf.actor_resolved = tracing::field::Empty,
        );
        let _enter = span.enter();
        let action = req
            .metadata()
            .get(":path")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("/")
            .to_string();
        span.record("tf.action", action.as_str());
        let host_token = req
            .metadata()
            .get(self.inner.opts.host_token_metadata.as_str())
            .and_then(|v| v.to_str().ok())
            .map(|s| {
                if self.inner.opts.strip_bearer {
                    s.strip_prefix("Bearer ")
                        .or_else(|| s.strip_prefix("bearer "))
                        .unwrap_or(s)
                        .to_string()
                } else {
                    s.to_string()
                }
            });
        let trace_id = req
            .metadata()
            .get("x-trace-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body = DecideRequest {
            action,
            host_token,
            host_token_kind: self.inner.opts.host_token_kind.clone(),
            trace_id,
            ..Default::default()
        };

        let decision = match self.inner.client.decide(&body).await {
            Ok(d) => d,
            Err(e) => {
                if self.inner.opts.fail_open {
                    req.extensions_mut().insert(TfDecision(DecideResponse {
                        decision: "allow".into(),
                        reason: format!("fail_open: {e}"),
                        approval_id: None,
                        proof_id: String::new(),
                        actor_resolved: None,
                        trust_level: None,
                        authority_mode: None,
                        danger_tags: vec![],
                    }));
                    return Ok(req);
                }
                return Err(Status::unavailable(format!("tf_decide_unreachable: {e}")));
            }
        };

        // Record the decision attributes on the active span so traces
        // capture allow/deny/approval branches uniformly.
        span.record("tf.decision", decision.decision.as_str());
        if let Some(ref actor) = decision.actor_resolved {
            span.record("tf.actor_resolved", actor.as_str());
        }
        match decision.decision.to_ascii_lowercase().as_str() {
            "allow" => {
                req.extensions_mut().insert(TfDecision(decision));
                Ok(req)
            }
            "deny" => Err(Status::permission_denied(format!(
                "tf_denied: {}",
                decision.reason
            ))),
            "approval" | "approval_required" | "approval-required" => {
                Err(Status::failed_precondition(format!(
                    "tf_approval_required: approval_id={:?}",
                    decision.approval_id
                )))
            }
            other => Err(Status::internal(format!("tf_unknown_decision: {other}"))),
        }
    }
}

/// Synchronous `tonic::service::Interceptor` impl that block-on's the async
/// decide call on the current tokio runtime. This is the form used by
/// `Server::builder().add_service(InterceptedService::new(svc, ic))`.
impl tonic::service::Interceptor for TrustForgeInterceptor {
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        let this = self.clone();
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => {
                return Err(Status::internal(
                    "tf-tonic interceptor requires a tokio runtime",
                ));
            }
        };
        // Use `block_in_place` so we don't deadlock the current worker.
        tokio::task::block_in_place(move || handle.block_on(async move { this.check(req).await }))
    }
}

/// Free-function form for callers that prefer the closure shape that
/// `tonic::service::interceptor()` expects.
pub fn tonic_interceptor(
    ic: TrustForgeInterceptor,
) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone {
    move |req| {
        let this = ic.clone();
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => {
                return Err(Status::internal(
                    "tf-tonic interceptor requires a tokio runtime",
                ));
            }
        };
        tokio::task::block_in_place(move || handle.block_on(async move { this.check(req).await }))
    }
}
