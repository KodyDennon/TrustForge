//! tf-actix-web — actix-web middleware that calls `tf-daemon`'s `/v1/decide`.
//!
//! Use [`TrustForgeMiddleware`] as a transform on `App::wrap(...)`. On allow,
//! the [`TfDecision`] is attached to the request `extensions()` so handlers
//! can inspect it. On deny / approval the middleware short-circuits without
//! invoking the inner service.

use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use actix_service::{Service, Transform};
use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::StatusCode;
use actix_web::{Error, HttpMessage, HttpResponse};

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

/// Middleware factory.
#[derive(Clone)]
pub struct TrustForgeMiddleware {
    inner: Rc<Inner>,
}

struct Inner {
    client: TfDecideClient,
    opts: TrustForgeOpts,
}

impl TrustForgeMiddleware {
    pub fn new(client: TfDecideClient, opts: TrustForgeOpts) -> Self {
        Self {
            inner: Rc::new(Inner { client, opts }),
        }
    }
}

impl<S> Transform<S, ServiceRequest> for TrustForgeMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<EitherBody<BoxBody>>;
    type Error = Error;
    type InitError = ();
    type Transform = TrustForgeService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(TrustForgeService {
            service: Rc::new(service),
            cfg: self.inner.clone(),
        }))
    }
}

pub struct TrustForgeService<S> {
    service: Rc<S>,
    cfg: Rc<Inner>,
}

impl<S> Service<ServiceRequest> for TrustForgeService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<EitherBody<BoxBody>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let cfg = self.cfg.clone();
        Box::pin(async move {
            let action = format!("{} {}", req.method().as_str(), req.path());
            let target = req.uri().to_string();
            let raw_token = req
                .headers()
                .get(cfg.opts.host_token_header.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let host_token = raw_token.map(|s| {
                if cfg.opts.strip_bearer {
                    s.strip_prefix("Bearer ")
                        .or_else(|| s.strip_prefix("bearer "))
                        .map(|x| x.to_string())
                        .unwrap_or(s)
                } else {
                    s
                }
            });
            let trace_id = req
                .headers()
                .get("x-trace-id")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let body = DecideRequest {
                action,
                host_token,
                host_token_kind: cfg.opts.host_token_kind.clone(),
                target: Some(target),
                trace_id,
                ..Default::default()
            };

            let decision = match cfg.client.decide(&body).await {
                Ok(d) => d,
                Err(e) => {
                    if cfg.opts.fail_open {
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
                        let resp = svc.call(req).await?;
                        return Ok(resp.map_into_left_body());
                    }
                    let body = serde_json::json!({
                        "error": "tf_decide_unreachable",
                        "detail": e.to_string(),
                    });
                    let resp = HttpResponse::ServiceUnavailable().json(body);
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            };

            match decision.decision.to_ascii_lowercase().as_str() {
                "allow" => {
                    req.extensions_mut().insert(TfDecision(decision));
                    let resp = svc.call(req).await?;
                    Ok(resp.map_into_left_body())
                }
                "deny" => {
                    let body = serde_json::json!({
                        "error": "tf_denied",
                        "reason": decision.reason,
                        "proof_id": decision.proof_id,
                        "danger_tags": decision.danger_tags,
                    });
                    let resp = HttpResponse::Forbidden().json(body);
                    Ok(req.into_response(resp).map_into_right_body())
                }
                "approval" | "approval_required" | "approval-required" => {
                    let body = serde_json::json!({
                        "status": "approval_required",
                        "approval_id": decision.approval_id,
                        "proof_id": decision.proof_id,
                        "reason": decision.reason,
                    });
                    let resp = HttpResponse::Accepted().json(body);
                    Ok(req.into_response(resp).map_into_right_body())
                }
                other => {
                    let body = serde_json::json!({
                        "error": "tf_unknown_decision",
                        "decision": other,
                    });
                    let resp = HttpResponse::build(StatusCode::BAD_GATEWAY).json(body);
                    Ok(req.into_response(resp).map_into_right_body())
                }
            }
        })
    }
}
