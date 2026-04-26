//! tf-axum — axum/tower middleware that calls `tf-daemon`'s `/v1/decide`.
//!
//! Drop [`TrustForgeLayer`] into any axum `Router` (or any `tower` stack) and
//! every inbound request will:
//!
//! 1. extract a host token (default: `Authorization: Bearer …`),
//! 2. POST to `tf-daemon`'s `/v1/decide`,
//! 3. on `allow`: attach `Extension<TfDecision>` and forward,
//! 4. on `deny`: short-circuit with `403 Forbidden` and a JSON body,
//! 5. on `approval` (or `approval_required`): short-circuit with `202 Accepted`.
//!
//! The middleware is profile-agnostic and intentionally small: it only
//! enforces the live-mode authority gate; replay packets and per-route
//! capability mapping are handled by higher-level helpers.

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{to_bytes, Body};
use axum::extract::Extension;
use axum::http::{HeaderMap, Request, Response, StatusCode};
use axum::response::IntoResponse;
use futures_util::future::BoxFuture;
use tower_layer::Layer;
use tower_service::Service;

use tf_decide_client::{DecideRequest, DecideResponse, TfDecideClient};

pub use tf_decide_client;
pub use tf_otel;

/// Per-layer configuration.
#[derive(Clone, Debug)]
pub struct TrustForgeOpts {
    /// Header to read the host token from. Defaults to `authorization`.
    pub host_token_header: String,
    /// Optional kind tag forwarded to the daemon (e.g. `"oauth_jwt"`).
    pub host_token_kind: Option<String>,
    /// Strip the `Bearer ` prefix from the header value before forwarding.
    pub strip_bearer: bool,
    /// If true, deny-fail-open: on transport error treat as allow (default false).
    pub fail_open: bool,
}

impl Default for TrustForgeOpts {
    fn default() -> Self {
        Self {
            host_token_header: "authorization".to_string(),
            host_token_kind: None,
            strip_bearer: true,
            fail_open: false,
        }
    }
}

/// Decision attached to each `allow`-ed request as `Extension<TfDecision>`.
#[derive(Clone, Debug)]
pub struct TfDecision(pub DecideResponse);

/// Tower `Layer` that wraps an inner service with a TrustForge gate.
#[derive(Clone)]
pub struct TrustForgeLayer {
    inner: Arc<Inner>,
}

struct Inner {
    client: TfDecideClient,
    opts: TrustForgeOpts,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("daemon_url", &self.client.daemon_url())
            .field("opts", &self.opts)
            .finish()
    }
}

impl TrustForgeLayer {
    pub fn new(client: TfDecideClient, opts: TrustForgeOpts) -> Self {
        Self {
            inner: Arc::new(Inner { client, opts }),
        }
    }
}

impl<S> Layer<S> for TrustForgeLayer {
    type Service = TrustForgeService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        TrustForgeService {
            inner,
            cfg: self.inner.clone(),
        }
    }
}

/// Tower `Service` produced by [`TrustForgeLayer`].
#[derive(Clone)]
pub struct TrustForgeService<S> {
    inner: S,
    cfg: Arc<Inner>,
}

fn extract_token(headers: &HeaderMap, opts: &TrustForgeOpts) -> Option<String> {
    let v = headers.get(opts.host_token_header.as_str())?;
    let s = v.to_str().ok()?;
    let s = if opts.strip_bearer {
        s.strip_prefix("Bearer ")
            .or_else(|| s.strip_prefix("bearer "))
            .unwrap_or(s)
    } else {
        s
    };
    Some(s.to_string())
}

impl<S> Service<Request<Body>> for TrustForgeService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        // Hyper/tower note: `inner` may not be ready, replace with `std::mem::replace`
        // pattern used by axum docs.
        let cfg = self.cfg.clone();
        // Open one `tf.daemon.decide` span per inbound request. Fields
        // are filled in once the daemon answers; until then they are
        // recorded as `Empty` so the span shape is stable.
        let span_for_async = tracing::info_span!(
            "tf.daemon.decide",
            otel.name = "tf.daemon.decide",
            tf.action = tracing::field::Empty,
            tf.target = tracing::field::Empty,
            tf.decision = tracing::field::Empty,
            tf.actor_resolved = tracing::field::Empty,
        );
        Box::pin(async move {
            let _enter = span_for_async.enter();
            let (parts, body) = req.into_parts();

            // Buffer the body so the inner service still gets it.
            let body_bytes = to_bytes(body, usize::MAX).await.unwrap_or_default();

            let action = format!("{} {}", parts.method.as_str(), parts.uri.path());
            // Populate the always-known span attributes now; the
            // decision-side fields are recorded once the daemon answers.
            span_for_async.record("tf.action", action.as_str());
            span_for_async.record("tf.target", parts.uri.to_string().as_str());
            let host_token = extract_token(&parts.headers, &cfg.opts);
            let trace_id = parts
                .headers
                .get("x-trace-id")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let req_body = DecideRequest {
                action,
                host_token,
                host_token_kind: cfg.opts.host_token_kind.clone(),
                target: Some(parts.uri.to_string()),
                trace_id,
                ..Default::default()
            };

            let decision = match cfg.client.decide(&req_body).await {
                Ok(d) => d,
                Err(e) => {
                    if cfg.opts.fail_open {
                        let mut req = Request::from_parts(parts, Body::from(body_bytes));
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
                        return inner.call(req).await;
                    }
                    let body = serde_json::json!({
                        "error": "tf_decide_unreachable",
                        "detail": e.to_string(),
                    });
                    return Ok((
                        StatusCode::SERVICE_UNAVAILABLE,
                        Extension(()),
                        axum::Json(body),
                    )
                        .into_response());
                }
            };

            // Record the decision on the span, regardless of branch.
            span_for_async.record("tf.decision", decision.decision.as_str());
            if let Some(ref actor) = decision.actor_resolved {
                span_for_async.record("tf.actor_resolved", actor.as_str());
            }
            match decision.decision.to_ascii_lowercase().as_str() {
                "allow" => {
                    let mut req = Request::from_parts(parts, Body::from(body_bytes));
                    req.extensions_mut().insert(TfDecision(decision));
                    inner.call(req).await
                }
                "deny" => {
                    let body = serde_json::json!({
                        "error": "tf_denied",
                        "reason": decision.reason,
                        "proof_id": decision.proof_id,
                        "danger_tags": decision.danger_tags,
                    });
                    Ok((StatusCode::FORBIDDEN, axum::Json(body)).into_response())
                }
                "approval" | "approval_required" | "approval-required" => {
                    let body = serde_json::json!({
                        "status": "approval_required",
                        "approval_id": decision.approval_id,
                        "proof_id": decision.proof_id,
                        "reason": decision.reason,
                    });
                    Ok((StatusCode::ACCEPTED, axum::Json(body)).into_response())
                }
                other => {
                    let body = serde_json::json!({
                        "error": "tf_unknown_decision",
                        "decision": other,
                    });
                    Ok((StatusCode::BAD_GATEWAY, axum::Json(body)).into_response())
                }
            }
        })
    }
}
