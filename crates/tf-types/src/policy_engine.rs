//! Native TrustForge policy engine — Rust mirror of
//! `tools/tf-types-ts/src/core/policy-engine.ts`.

use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonicalize;
use crate::guard::NegativeCapability;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PolicyQuery {
    pub subject: String,
    #[serde(default)]
    pub instance: Option<String>,
    pub action: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub context: HashMap<String, Value>,
    #[serde(default)]
    pub negative_capabilities: Vec<NegativeCapability>,
    #[serde(default)]
    pub enforcement_level: Option<String>,
    #[serde(default)]
    pub now: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecision {
    pub decision_version: String,
    pub policy_engine: String,
    pub engine_version: Option<String>,
    pub trust_domain: String,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub instance: Option<String>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub target: Option<String>,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub approval: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proof_required: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub constraints_applied: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub negative_capabilities_consulted: Option<Vec<NegativeCapability>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub enforcement_level: Option<String>,
    pub evaluated_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub policy_manifest_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub context: Option<HashMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub effect: String,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub action_pattern: Option<String>,
    #[serde(default)]
    pub subject_pattern: Option<String>,
    #[serde(default)]
    pub target_patterns: Option<Vec<String>>,
    #[serde(default)]
    pub approval: Option<String>,
    #[serde(default)]
    pub proof_required: Option<String>,
    #[serde(default)]
    pub constraints: Option<Vec<Value>>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyManifest {
    pub policy_version: String,
    pub trust_domain: String,
    #[serde(default)]
    pub engine_hint: Option<String>,
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub negative_capabilities: Vec<NegativeCapability>,
    #[serde(default)]
    pub continuous_reevaluation: Option<ContinuousReeval>,
    #[serde(default)]
    pub quorum_defaults: Option<QuorumDefaults>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContinuousReeval {
    pub triggers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumDefaults {
    pub min_approvers: u32,
    pub of: Vec<String>,
}

/// A pluggable policy engine. Implemented by the native engine, the
/// `tf-cedar` crate, and the `tf-rego` crate. Decoupling via a trait
/// (rather than a feature-gated dependency on the adapter crates) lets
/// `tf-types` stay lightweight while still letting the daemon dispatch
/// the right engine for a given `engine_hint`.
pub trait PolicyEngineImpl {
    fn evaluate(&self, query: &PolicyQuery) -> PolicyDecision;
}

pub struct NativePolicyEngine {
    policy: PolicyManifest,
    manifest_hash: String,
}

impl PolicyEngineImpl for NativePolicyEngine {
    fn evaluate(&self, query: &PolicyQuery) -> PolicyDecision {
        NativePolicyEngine::evaluate(self, query)
    }
}

/// Dispatch a `PolicyQuery` to the appropriate backend based on
/// `engine_hint`. Pass an explicit backend for the hints that need one;
/// `native` falls back to the supplied native engine. When the requested
/// hint has no backend wired in (e.g. caller didn't construct a Cedar
/// engine yet) the dispatcher returns a safe deny.
///
/// The signature uses `dyn` trait objects so callers don't have to leak
/// the cedar / rego crate types through `tf-types`. `tf-cedar` and
/// `tf-rego` each export an adapter that implements `PolicyEngineImpl`.
pub fn evaluate_with_engine(
    hint: Option<&str>,
    native: &NativePolicyEngine,
    cedar: Option<&dyn PolicyEngineImpl>,
    rego: Option<&dyn PolicyEngineImpl>,
    query: &PolicyQuery,
) -> PolicyDecision {
    match hint {
        Some("cedar") => match cedar {
            Some(eng) => eng.evaluate(query),
            None => unavailable_decision("cedar", query, native.policy.trust_domain.as_str()),
        },
        Some("rego") => match rego {
            Some(eng) => eng.evaluate(query),
            None => unavailable_decision("rego", query, native.policy.trust_domain.as_str()),
        },
        _ => native.evaluate(query),
    }
}

fn unavailable_decision(engine: &str, query: &PolicyQuery, trust_domain: &str) -> PolicyDecision {
    PolicyDecision {
        decision_version: "1".into(),
        policy_engine: engine.into(),
        engine_version: Some(format!("{engine}-stub")),
        trust_domain: trust_domain.into(),
        subject: query.subject.clone(),
        instance: query.instance.clone(),
        action: query.action.clone(),
        target: query.target.clone(),
        decision: "deny".into(),
        rule_id: None,
        reason: Some(format!(
            "{engine} engine not configured for this dispatcher (no adapter supplied)"
        )),
        approval: None,
        proof_required: None,
        constraints_applied: None,
        negative_capabilities_consulted: None,
        enforcement_level: query.enforcement_level.clone(),
        evaluated_at: now_iso8601(),
        policy_manifest_hash: None,
        context: if query.context.is_empty() {
            None
        } else {
            Some(query.context.clone())
        },
    }
}

impl NativePolicyEngine {
    pub fn new(policy: PolicyManifest) -> Self {
        let canonical_value = serde_json::to_value(&policy).unwrap_or(Value::Null);
        let canonical = canonicalize(&canonical_value).unwrap_or_default();
        let digest: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        let manifest_hash = format!("sha256-{}", hex);
        NativePolicyEngine {
            policy,
            manifest_hash,
        }
    }

    pub fn evaluate(&self, query: &PolicyQuery) -> PolicyDecision {
        let now = query.now.clone().unwrap_or_else(|| now_iso8601());
        let neg_caps = if query.negative_capabilities.is_empty() {
            self.policy.negative_capabilities.clone()
        } else {
            query.negative_capabilities.clone()
        };
        for neg in &neg_caps {
            if negative_matches(neg, query) {
                return self.decision(
                    query,
                    "deny",
                    neg.reason
                        .clone()
                        .unwrap_or_else(|| format!("denied by negative_capability {}", neg.name)),
                    None,
                    None,
                    None,
                    None,
                    Some(&neg_caps),
                    &now,
                );
            }
        }
        for rule in &self.policy.rules {
            if !rule_matches(rule, query) {
                continue;
            }
            let reason = rule
                .reason
                .clone()
                .unwrap_or_else(|| format!("matched rule {}", rule.id));
            match rule.effect.as_str() {
                "allow" => {
                    return self.decision(
                        query,
                        "allow",
                        reason,
                        Some(rule.id.clone()),
                        rule.constraints.clone(),
                        rule.proof_required.clone(),
                        rule.approval.clone(),
                        Some(&neg_caps),
                        &now,
                    );
                }
                "deny" => {
                    return self.decision(
                        query,
                        "deny",
                        reason,
                        Some(rule.id.clone()),
                        None,
                        None,
                        None,
                        Some(&neg_caps),
                        &now,
                    );
                }
                "escalate" => {
                    let decision = if rule.approval.as_deref() == Some("quorum") {
                        "escalate"
                    } else {
                        "approval-required"
                    };
                    return self.decision(
                        query,
                        decision,
                        reason,
                        Some(rule.id.clone()),
                        rule.constraints.clone(),
                        rule.proof_required.clone(),
                        rule.approval.clone().or_else(|| Some("required".into())),
                        Some(&neg_caps),
                        &now,
                    );
                }
                "log_only" => {
                    return self.decision(
                        query,
                        "log-only",
                        reason,
                        Some(rule.id.clone()),
                        rule.constraints.clone(),
                        rule.proof_required.clone(),
                        None,
                        Some(&neg_caps),
                        &now,
                    );
                }
                _ => continue,
            }
        }
        self.decision(
            query,
            "deny",
            "no matching rule (default deny)".into(),
            None,
            None,
            None,
            None,
            Some(&neg_caps),
            &now,
        )
    }

    pub fn continuous_triggers(&self) -> Vec<String> {
        self.policy
            .continuous_reevaluation
            .as_ref()
            .map(|c| c.triggers.clone())
            .unwrap_or_default()
    }

    pub fn quorum_defaults(&self) -> Option<&QuorumDefaults> {
        self.policy.quorum_defaults.as_ref()
    }

    pub fn manifest_hash(&self) -> &str {
        &self.manifest_hash
    }

    #[allow(clippy::too_many_arguments)]
    fn decision(
        &self,
        query: &PolicyQuery,
        decision: &str,
        reason: String,
        rule_id: Option<String>,
        constraints: Option<Vec<Value>>,
        proof: Option<String>,
        approval: Option<String>,
        neg_caps: Option<&[NegativeCapability]>,
        now: &str,
    ) -> PolicyDecision {
        PolicyDecision {
            decision_version: "1".into(),
            policy_engine: "native".into(),
            engine_version: Some("tf-policy-native-0.1.0".into()),
            trust_domain: self.policy.trust_domain.clone(),
            subject: query.subject.clone(),
            instance: query.instance.clone(),
            action: query.action.clone(),
            target: query.target.clone(),
            decision: decision.into(),
            rule_id,
            reason: Some(reason),
            approval,
            proof_required: proof,
            constraints_applied: constraints.filter(|c| !c.is_empty()),
            negative_capabilities_consulted: neg_caps.map(|c| c.to_vec()).filter(|v| !v.is_empty()),
            enforcement_level: query.enforcement_level.clone(),
            evaluated_at: now.into(),
            policy_manifest_hash: Some(self.manifest_hash.clone()),
            context: if query.context.is_empty() {
                None
            } else {
                Some(query.context.clone())
            },
        }
    }
}

fn rule_matches(rule: &PolicyRule, query: &PolicyQuery) -> bool {
    if let Some(action) = &rule.action {
        if action != &query.action {
            return false;
        }
    }
    if let Some(pattern) = &rule.action_pattern {
        let re = match Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => return false,
        };
        if !re.is_match(&query.action) {
            return false;
        }
    }
    if let Some(pattern) = &rule.subject_pattern {
        let re = match Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => return false,
        };
        if !re.is_match(&query.subject) {
            return false;
        }
    }
    if let Some(targets) = &rule.target_patterns {
        if !targets.is_empty() {
            let Some(target) = &query.target else {
                return false;
            };
            if !targets.iter().any(|p| glob_match(p, target)) {
                return false;
            }
        }
    }
    true
}

fn negative_matches(neg: &NegativeCapability, q: &PolicyQuery) -> bool {
    if neg.name != q.action {
        return false;
    }
    let Some(target_pattern) = neg.target.as_deref() else {
        return true;
    };
    let Some(query_target) = q.target.as_deref() else {
        return false;
    };
    glob_match(target_pattern, query_target)
}

fn glob_match(pattern: &str, value: &str) -> bool {
    let mut re = String::from("^");
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'*' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                    re.push_str(".*");
                    i += 2;
                } else {
                    re.push_str("[^/]*");
                    i += 1;
                }
            }
            b'.' | b'+' | b'^' | b'$' | b'{' | b'}' | b'(' | b')' | b'|' | b'[' | b']' | b'\\' => {
                re.push('\\');
                re.push(b as char);
                i += 1;
            }
            _ => {
                re.push(b as char);
                i += 1;
            }
        }
    }
    re.push('$');
    Regex::new(&re).map(|r| r.is_match(value)).unwrap_or(false)
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
    let m = if mp < 10 {
        (mp + 3) as u32
    } else {
        (mp - 9) as u32
    };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d, hour, minute, second)
}
