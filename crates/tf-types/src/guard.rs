//! AgentGuard — Rust mirror of `tools/tf-types-ts/src/core/guard.ts`.
//!
//! Accepts a parsed agent-contract value (as serde_json::Value so the Rust
//! crate doesn't need to generate a full typed binding here), and answers
//! guard queries with a structured GuardDecision.

use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum GuardDecision {
    Allow {
        danger_tags: Vec<String>,
    },
    ApprovalRequired {
        approval: String,
        reason: String,
        danger_tags: Vec<String>,
    },
    Escalate {
        reason: String,
        danger_tags: Vec<String>,
    },
    Deny {
        reason: String,
        danger_tags: Vec<String>,
    },
}

impl GuardDecision {
    pub fn kind(&self) -> &'static str {
        match self {
            GuardDecision::Allow { .. } => "allow",
            GuardDecision::ApprovalRequired { .. } => "approval-required",
            GuardDecision::Escalate { .. } => "escalate",
            GuardDecision::Deny { .. } => "deny",
        }
    }

    pub fn danger_tags(&self) -> &[String] {
        match self {
            GuardDecision::Allow { danger_tags }
            | GuardDecision::ApprovalRequired { danger_tags, .. }
            | GuardDecision::Escalate { danger_tags, .. }
            | GuardDecision::Deny { danger_tags, .. } => danger_tags,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct GuardQuery {
    pub actor: Option<String>,
    pub action: String,
    pub target: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardEventStub {
    #[serde(rename = "type")]
    pub kind: String,
    pub actor: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub decision: String,
    pub danger_tags: Vec<String>,
}

#[derive(Clone, Debug)]
struct IndexedAction {
    name: String,
    approval: Option<String>,
    danger_tags: Vec<String>,
    allow_targets: Vec<String>,
    deny_targets: Vec<String>,
}

const ESCALATE_TAGS: &[&str] = &[
    "destructive",
    "irreversible",
    "financial",
    "security-sensitive",
    "legal-exposure",
];

pub struct AgentGuard {
    action_by_name: HashMap<String, IndexedAction>,
    forbidden_by_name: HashMap<String, String>,
    target_sets: HashMap<String, Vec<String>>,
    on_event: Option<Box<dyn Fn(&GuardEventStub) + Send + Sync>>,
}

impl AgentGuard {
    pub fn from_contract(contract: &Value) -> Self {
        let empty_arr = Vec::<Value>::new();
        let actions_val = contract
            .get("actions")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_arr);
        let mut actions = HashMap::new();
        for a in actions_val {
            let name = a
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let approval = a
                .get("approval")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let danger_tags = a
                .get("danger_tags")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| t.as_str())
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let allow_targets = a
                .get("allow_targets")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|t| t.as_str()).map(str::to_string).collect::<Vec<_>>())
                .unwrap_or_default();
            let deny_targets = a
                .get("deny_targets")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|t| t.as_str()).map(str::to_string).collect::<Vec<_>>())
                .unwrap_or_default();
            actions.insert(
                name.clone(),
                IndexedAction {
                    name,
                    approval,
                    danger_tags,
                    allow_targets,
                    deny_targets,
                },
            );
        }

        let mut forbidden = HashMap::new();
        for f in contract
            .get("forbidden")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_arr)
        {
            let name = f
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let reason = f
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            forbidden.insert(name, reason);
        }

        let mut target_sets = HashMap::new();
        if let Some(Value::Object(map)) = contract.get("target_sets") {
            for (k, v) in map {
                if let Some(arr) = v.as_array() {
                    let patterns: Vec<String> = arr
                        .iter()
                        .filter_map(|t| t.as_str())
                        .map(str::to_string)
                        .collect();
                    target_sets.insert(k.clone(), patterns);
                }
            }
        }

        AgentGuard {
            action_by_name: actions,
            forbidden_by_name: forbidden,
            target_sets,
            on_event: None,
        }
    }

    pub fn set_event_listener<F>(&mut self, f: F)
    where
        F: Fn(&GuardEventStub) + Send + Sync + 'static,
    {
        self.on_event = Some(Box::new(f));
    }

    pub fn check(&self, query: &GuardQuery) -> GuardDecision {
        let actor = query
            .actor
            .clone()
            .unwrap_or_else(|| "tf:actor:process:local/unknown".to_string());

        if let Some(reason) = self.forbidden_by_name.get(&query.action) {
            let decision = GuardDecision::Deny {
                reason: if reason.is_empty() {
                    "action listed in forbidden".to_string()
                } else {
                    reason.clone()
                },
                danger_tags: Vec::new(),
            };
            self.emit(&decision, &actor, query);
            return decision;
        }

        let Some(action) = self.action_by_name.get(&query.action) else {
            let decision = GuardDecision::Deny {
                reason: format!("action \"{}\" is not declared", query.action),
                danger_tags: Vec::new(),
            };
            self.emit(&decision, &actor, query);
            return decision;
        };

        let tags = action.danger_tags.clone();

        if let Some(target) = &query.target {
            for pattern in &action.deny_targets {
                if self.match_target(pattern, target) {
                    let decision = GuardDecision::Deny {
                        reason: format!("target {} is in deny_targets ({})", target, pattern),
                        danger_tags: tags.clone(),
                    };
                    self.emit(&decision, &actor, query);
                    return decision;
                }
            }
            if !action.allow_targets.is_empty() {
                let allowed = action
                    .allow_targets
                    .iter()
                    .any(|p| self.match_target(p, target));
                if !allowed {
                    let decision = GuardDecision::Deny {
                        reason: format!("target {} is not in allow_targets", target),
                        danger_tags: tags.clone(),
                    };
                    self.emit(&decision, &actor, query);
                    return decision;
                }
            }
        }

        let should_escalate = tags.iter().any(|t| ESCALATE_TAGS.contains(&t.as_str()));
        if should_escalate {
            let escalating: Vec<&str> = tags
                .iter()
                .filter(|t| ESCALATE_TAGS.contains(&t.as_str()))
                .map(String::as_str)
                .collect();
            let decision = GuardDecision::Escalate {
                reason: format!("danger_tags require escalation: {}", escalating.join(", ")),
                danger_tags: tags.clone(),
            };
            self.emit(&decision, &actor, query);
            return decision;
        }

        match action.approval.as_deref() {
            Some("required") | Some("quorum") => {
                let approval = action.approval.clone().unwrap();
                let decision = GuardDecision::ApprovalRequired {
                    approval,
                    reason: format!("action \"{}\" requires approval", query.action),
                    danger_tags: tags.clone(),
                };
                self.emit(&decision, &actor, query);
                decision
            }
            _ => {
                let decision = GuardDecision::Allow { danger_tags: tags };
                self.emit(&decision, &actor, query);
                decision
            }
        }
    }

    fn match_target(&self, pattern: &str, value: &str) -> bool {
        if let Some(rest) = pattern.strip_prefix('@') {
            let Some(set) = self.target_sets.get(rest) else {
                return false;
            };
            return set.iter().any(|p| glob_match(p, value));
        }
        glob_match(pattern, value)
    }

    fn emit(&self, decision: &GuardDecision, actor: &str, query: &GuardQuery) {
        let Some(f) = &self.on_event else { return };
        f(&GuardEventStub {
            kind: "guard.check".to_string(),
            actor: actor.to_string(),
            action: query.action.clone(),
            target: query.target.clone(),
            decision: decision.kind().to_string(),
            danger_tags: decision.danger_tags().to_vec(),
        });
    }
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
