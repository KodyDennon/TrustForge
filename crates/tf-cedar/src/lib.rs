//! TrustForge Cedar policy engine adapter.
//!
//! Wraps the upstream `cedar-policy` crate and exposes a thin façade that
//! produces TrustForge `PolicyDecision` records from Cedar `Authorizer`
//! responses. This crate is opt-in: `tf-types` only depends on it when the
//! `cedar` feature is enabled, so lightweight deployments never pull Cedar
//! in transitively.
//!
//! Translation rules:
//!
//! * `PolicyQuery.subject`  -> Cedar `principal` UID. The translator parses
//!   the subject as a Cedar entity reference; if it isn't already a valid
//!   `Type::"id"` form (the common case for `tf:actor:…`) the engine wraps
//!   it as `Subject::"<escaped>"`.
//! * `PolicyQuery.action`   -> `Action::"<action>"`.
//! * `PolicyQuery.target`   -> `Resource::"<target>"` when present, else
//!   `Resource::"unknown"` (Cedar requires a resource UID; the policies
//!   are responsible for handling that placeholder).
//! * `PolicyQuery.context`  -> Cedar context built via JSON.
//!
//! Cedar's `Authorizer::is_authorized` returns Allow/Deny + a list of
//! contributing policy IDs. We map them to the `PolicyDecision` shape:
//! `decision` is `"allow"` or `"deny"`; `rule_id` is the first
//! contributing policy id; `reason` summarises diagnostics. Errors during
//! evaluation (e.g. malformed entities) are surfaced via the explicit
//! `CedarError` returned from `new`; runtime evaluation errors degrade to
//! a safe `deny` decision with a descriptive reason.

use std::str::FromStr;

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request};
use serde_json::Value;
use thiserror::Error;

use tf_types::policy_engine::{PolicyDecision, PolicyEngineImpl, PolicyQuery};

/// Errors produced when constructing a [`CedarPolicyEngine`].
///
/// Construction is the only place we hard-fail; once the engine exists, all
/// runtime evaluation errors are converted into safe `deny` decisions so a
/// single bad request can never crash the daemon.
#[derive(Debug, Error)]
pub enum CedarError {
    #[error("invalid Cedar policy source: {0}")]
    Policy(String),
    #[error("invalid Cedar entities JSON: {0}")]
    Entities(String),
}

/// Cedar-backed policy engine.
pub struct CedarPolicyEngine {
    pub policy_set: PolicySet,
    pub entities: Entities,
    authorizer: Authorizer,
    trust_domain: String,
}

impl CedarPolicyEngine {
    /// Construct an engine from the textual Cedar policy bundle and an
    /// `Entities` JSON document. Both are parsed eagerly so callers learn
    /// about syntax / schema problems at startup, not on the first
    /// request.
    pub fn new(policy_src: &str, entities_json: &str) -> Result<Self, CedarError> {
        let policy_set =
            PolicySet::from_str(policy_src).map_err(|e| CedarError::Policy(e.to_string()))?;
        let entities = Entities::from_json_str(entities_json, None)
            .map_err(|e| CedarError::Entities(e.to_string()))?;
        Ok(CedarPolicyEngine {
            policy_set,
            entities,
            authorizer: Authorizer::new(),
            trust_domain: "cedar".into(),
        })
    }

    /// Override the `trust_domain` reported in decisions. Defaults to
    /// `"cedar"` so a stand-alone engine still produces a coherent
    /// audit record.
    pub fn with_trust_domain(mut self, domain: impl Into<String>) -> Self {
        self.trust_domain = domain.into();
        self
    }

    /// Evaluate a TrustForge `PolicyQuery` through the underlying Cedar
    /// authorizer. Always returns a `PolicyDecision`: malformed inputs
    /// degrade to a deny rather than panicking.
    pub fn evaluate(&self, query: &PolicyQuery) -> PolicyDecision {
        let now = query.now.clone().unwrap_or_else(now_iso8601);

        let principal = match parse_or_wrap_uid(&query.subject, "Subject") {
            Ok(uid) => uid,
            Err(e) => {
                return self.deny(
                    query,
                    &now,
                    None,
                    format!("invalid subject UID: {e}"),
                );
            }
        };
        let action = match parse_or_wrap_uid(&query.action, "Action") {
            Ok(uid) => uid,
            Err(e) => {
                return self.deny(
                    query,
                    &now,
                    None,
                    format!("invalid action UID: {e}"),
                );
            }
        };
        let resource_str = query
            .target
            .clone()
            .unwrap_or_else(|| "Resource::\"unknown\"".to_string());
        let resource = match parse_or_wrap_uid(&resource_str, "Resource") {
            Ok(uid) => uid,
            Err(e) => {
                return self.deny(
                    query,
                    &now,
                    None,
                    format!("invalid resource UID: {e}"),
                );
            }
        };

        let context = match build_context(&query.context) {
            Ok(c) => c,
            Err(e) => {
                return self.deny(
                    query,
                    &now,
                    None,
                    format!("invalid context: {e}"),
                );
            }
        };

        let request = match Request::new(principal, action, resource, context, None) {
            Ok(r) => r,
            Err(e) => {
                return self.deny(
                    query,
                    &now,
                    None,
                    format!("could not build cedar request: {e}"),
                );
            }
        };

        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &self.entities);
        let reason_ids: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|p| p.to_string())
            .collect();
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();

        let (decision, default_reason) = match response.decision() {
            Decision::Allow => ("allow", "cedar permit policy matched".to_string()),
            Decision::Deny => {
                if reason_ids.is_empty() {
                    if errors.is_empty() {
                        ("deny", "no cedar permit policy matched (default deny)".to_string())
                    } else {
                        (
                            "deny",
                            format!("cedar evaluation errors: {}", errors.join("; ")),
                        )
                    }
                } else {
                    ("deny", "cedar forbid policy matched".to_string())
                }
            }
        };

        let rule_id = reason_ids.into_iter().next();
        self.decision(query, &now, decision, rule_id, default_reason)
    }

    fn decision(
        &self,
        query: &PolicyQuery,
        now: &str,
        decision: &str,
        rule_id: Option<String>,
        reason: String,
    ) -> PolicyDecision {
        PolicyDecision {
            decision_version: "1".into(),
            policy_engine: "cedar".into(),
            engine_version: Some(format!("cedar-policy-{}", env!("CARGO_PKG_VERSION"))),
            trust_domain: self.trust_domain.clone(),
            subject: query.subject.clone(),
            instance: query.instance.clone(),
            action: query.action.clone(),
            target: query.target.clone(),
            decision: decision.into(),
            rule_id,
            reason: Some(reason),
            approval: None,
            proof_required: None,
            constraints_applied: None,
            negative_capabilities_consulted: if query.negative_capabilities.is_empty() {
                None
            } else {
                Some(query.negative_capabilities.clone())
            },
            enforcement_level: query.enforcement_level.clone(),
            evaluated_at: now.to_string(),
            policy_manifest_hash: None,
            context: if query.context.is_empty() {
                None
            } else {
                Some(query.context.clone())
            },
        }
    }

    fn deny(
        &self,
        query: &PolicyQuery,
        now: &str,
        rule_id: Option<String>,
        reason: String,
    ) -> PolicyDecision {
        self.decision(query, now, "deny", rule_id, reason)
    }
}

/// Parse `s` as a Cedar EntityUid; if parsing fails, wrap it as
/// `<fallback_type>::"<escaped>"`. The wrapping path supports the common
/// TrustForge case where subjects look like `tf:actor:agent:example.com/x`
/// and aren't valid Cedar UIDs out of the box.
fn parse_or_wrap_uid(s: &str, fallback_type: &str) -> Result<EntityUid, String> {
    if let Ok(uid) = EntityUid::from_str(s) {
        return Ok(uid);
    }
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    let fallback = format!("{}::\"{}\"", fallback_type, escaped);
    EntityUid::from_str(&fallback).map_err(|e| e.to_string())
}

fn build_context(
    ctx: &std::collections::HashMap<String, Value>,
) -> Result<Context, String> {
    if ctx.is_empty() {
        return Ok(Context::empty());
    }
    let json = serde_json::to_value(ctx).map_err(|e| e.to_string())?;
    Context::from_json_value(json, None).map_err(|e| e.to_string())
}

impl PolicyEngineImpl for CedarPolicyEngine {
    fn evaluate(&self, query: &PolicyQuery) -> PolicyDecision {
        CedarPolicyEngine::evaluate(self, query)
    }
}

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (year, month, day, hour, minute, second) = secs_to_ymdhms(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn secs_to_ymdhms(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let time = secs.rem_euclid(86_400);
    let hour = (time / 3600) as u32;
    let minute = ((time % 3600) / 60) as u32;
    let second = (time % 60) as u32;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d, hour, minute, second)
}
