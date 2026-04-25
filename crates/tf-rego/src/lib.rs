//! TrustForge Rego policy engine adapter.
//!
//! Wraps the upstream `regorus` Rego interpreter (a pure-Rust port of OPA's
//! evaluation core) and exposes a thin façade that produces TrustForge
//! `PolicyDecision` records from the raw Rego output. This crate is opt-in:
//! `tf-types` only depends on it when the `rego` feature is enabled.
//!
//! Translation rules:
//!
//! * `PolicyQuery` is rendered as a JSON object with the same keys
//!   (`subject`, `instance`, `action`, `target`, `context`,
//!   `negative_capabilities`, `enforcement_level`, `now`) and supplied as
//!   the engine's `input`.
//! * The engine evaluates `data.trustforge.allow`. The result MAY be a
//!   plain boolean (allow/deny) or a richer object of the form
//!   `{decision, reason, rule_id}`. Both shapes are accepted.
//! * Rego compilation errors become `RegoError::Policy`. Runtime evaluation
//!   errors collapse into a safe `deny` decision so a single bad request
//!   cannot crash the daemon.

use std::collections::HashMap;

use regorus::{Engine, Value as RegoValue};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use tf_types::policy_engine::{PolicyDecision, PolicyEngineImpl, PolicyQuery};

/// Errors produced when constructing a [`RegoPolicyEngine`].
#[derive(Debug, Error)]
pub enum RegoError {
    #[error("invalid Rego policy source: {0}")]
    Policy(String),
}

/// Rego-backed policy engine.
pub struct RegoPolicyEngine {
    engine: Engine,
    trust_domain: String,
    /// Fully-qualified Rego rule path the engine evaluates per query.
    /// Defaults to `data.trustforge.allow`.
    rule_path: String,
}

#[derive(Serialize)]
struct InputView<'a> {
    subject: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance: Option<&'a str>,
    action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    context: &'a HashMap<String, Value>,
    negative_capabilities: &'a [tf_types::guard::NegativeCapability],
    #[serde(skip_serializing_if = "Option::is_none")]
    enforcement_level: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    now: Option<&'a str>,
}

impl RegoPolicyEngine {
    /// Construct an engine from a single Rego source file. The source must
    /// declare a rule that resolves at `data.trustforge.allow`.
    pub fn new(rego_src: &str) -> Result<Self, RegoError> {
        let mut engine = Engine::new();
        engine
            .add_policy("trustforge.rego".to_string(), rego_src.to_string())
            .map_err(|e| RegoError::Policy(e.to_string()))?;
        Ok(RegoPolicyEngine {
            engine,
            trust_domain: "rego".into(),
            rule_path: "data.trustforge.allow".into(),
        })
    }

    /// Override the trust domain reported in decisions.
    pub fn with_trust_domain(mut self, domain: impl Into<String>) -> Self {
        self.trust_domain = domain.into();
        self
    }

    /// Override the Rego rule path the engine evaluates. Useful for
    /// policies that publish their decision under a non-standard name
    /// (e.g. `data.trustforge.decision`).
    pub fn with_rule_path(mut self, path: impl Into<String>) -> Self {
        self.rule_path = path.into();
        self
    }

    /// Evaluate a `PolicyQuery`. Always returns a `PolicyDecision`:
    /// runtime errors degrade to a deny.
    pub fn evaluate(&self, query: &PolicyQuery) -> PolicyDecision {
        let now = query.now.clone().unwrap_or_else(now_iso8601);

        let input = InputView {
            subject: &query.subject,
            instance: query.instance.as_deref(),
            action: &query.action,
            target: query.target.as_deref(),
            context: &query.context,
            negative_capabilities: &query.negative_capabilities,
            enforcement_level: query.enforcement_level.as_deref(),
            now: query.now.as_deref(),
        };
        let input_json = match serde_json::to_string(&input) {
            Ok(s) => s,
            Err(e) => {
                return self.deny(query, &now, format!("could not serialize input: {e}"));
            }
        };

        // `Engine::set_input` mutates state, so each evaluation gets its
        // own clone — keeping `evaluate` an `&self` method and avoiding
        // cross-request leakage of input.
        let mut engine = self.engine.clone();
        let value = match RegoValue::from_json_str(&input_json) {
            Ok(v) => v,
            Err(e) => {
                return self.deny(query, &now, format!("input is not valid JSON: {e}"));
            }
        };
        engine.set_input(value);

        let result = match engine.eval_rule(self.rule_path.clone()) {
            Ok(v) => v,
            Err(e) => {
                return self.deny(
                    query,
                    &now,
                    format!("rego evaluation error: {e}"),
                );
            }
        };

        // Result shape can be Bool or Object{decision, reason?, rule_id?}.
        match result {
            RegoValue::Bool(true) => self.decision(
                query,
                &now,
                "allow",
                None,
                "rego rule evaluated to true".to_string(),
            ),
            RegoValue::Bool(false) => self.decision(
                query,
                &now,
                "deny",
                None,
                "rego rule evaluated to false".to_string(),
            ),
            other => {
                let json_str = match other.to_json_str() {
                    Ok(s) => s,
                    Err(e) => return self.deny(query, &now, format!("rego output not JSON: {e}")),
                };
                let parsed: Value = match serde_json::from_str(&json_str) {
                    Ok(v) => v,
                    Err(e) => {
                        return self.deny(
                            query,
                            &now,
                            format!("rego output is not valid JSON: {e}"),
                        );
                    }
                };
                let obj = match parsed.as_object() {
                    Some(o) => o,
                    None => {
                        return self.deny(
                            query,
                            &now,
                            format!("rego output is not an object: {parsed}"),
                        );
                    }
                };
                let decision = obj
                    .get("decision")
                    .and_then(|v| v.as_str())
                    .unwrap_or("deny")
                    .to_string();
                let reason = obj
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("rego rule decided {decision}"));
                let rule_id = obj
                    .get("rule_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                self.decision(query, &now, &decision, rule_id, reason)
            }
        }
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
            policy_engine: "rego".into(),
            engine_version: Some(format!("regorus-{}", env!("CARGO_PKG_VERSION"))),
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

    fn deny(&self, query: &PolicyQuery, now: &str, reason: String) -> PolicyDecision {
        self.decision(query, now, "deny", None, reason)
    }
}

impl PolicyEngineImpl for RegoPolicyEngine {
    fn evaluate(&self, query: &PolicyQuery) -> PolicyDecision {
        RegoPolicyEngine::evaluate(self, query)
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
