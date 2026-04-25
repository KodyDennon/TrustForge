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
    LogOnly {
        reason: String,
        danger_tags: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnforcementLevel {
    E0,
    E1,
    E2,
    E3,
    E4,
    E5,
}

impl Default for EnforcementLevel {
    fn default() -> Self {
        EnforcementLevel::E4
    }
}

impl EnforcementLevel {
    pub fn parse(s: &str) -> Option<EnforcementLevel> {
        match s {
            "E0" => Some(Self::E0),
            "E1" => Some(Self::E1),
            "E2" => Some(Self::E2),
            "E3" => Some(Self::E3),
            "E4" => Some(Self::E4),
            "E5" => Some(Self::E5),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::E0 => "E0",
            Self::E1 => "E1",
            Self::E2 => "E2",
            Self::E3 => "E3",
            Self::E4 => "E4",
            Self::E5 => "E5",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NegativeCapability {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub overrides: Option<Vec<String>>,
}

impl GuardDecision {
    pub fn kind(&self) -> &'static str {
        match self {
            GuardDecision::Allow { .. } => "allow",
            GuardDecision::ApprovalRequired { .. } => "approval-required",
            GuardDecision::Escalate { .. } => "escalate",
            GuardDecision::Deny { .. } => "deny",
            GuardDecision::LogOnly { .. } => "log-only",
        }
    }

    pub fn danger_tags(&self) -> &[String] {
        match self {
            GuardDecision::Allow { danger_tags }
            | GuardDecision::ApprovalRequired { danger_tags, .. }
            | GuardDecision::Escalate { danger_tags, .. }
            | GuardDecision::Deny { danger_tags, .. }
            | GuardDecision::LogOnly { danger_tags, .. } => danger_tags,
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            GuardDecision::Allow { .. } => None,
            GuardDecision::ApprovalRequired { reason, .. }
            | GuardDecision::Escalate { reason, .. }
            | GuardDecision::Deny { reason, .. }
            | GuardDecision::LogOnly { reason, .. } => Some(reason),
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
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub enforcement_level: Option<String>,
}

#[derive(Clone, Debug)]
pub struct IndexedAction {
    pub name: String,
    pub approval: Option<String>,
    pub danger_tags: Vec<String>,
    pub allow_targets: Vec<String>,
    pub deny_targets: Vec<String>,
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
    enforcement_level: EnforcementLevel,
    negative_capabilities: Vec<NegativeCapability>,
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
            enforcement_level: EnforcementLevel::default(),
            negative_capabilities: Vec::new(),
        }
    }

    /// Replace the negative capability list (e.g. on policy reload).
    pub fn set_negative_capabilities(&mut self, caps: Vec<NegativeCapability>) {
        self.negative_capabilities = caps;
    }

    /// Replace the enforcement level (e.g. when shadow-mode toggles).
    pub fn set_enforcement_level(&mut self, level: EnforcementLevel) {
        self.enforcement_level = level;
    }

    pub fn enforcement_level(&self) -> EnforcementLevel {
        self.enforcement_level
    }

    pub fn set_event_listener<F>(&mut self, f: F)
    where
        F: Fn(&GuardEventStub) + Send + Sync + 'static,
    {
        self.on_event = Some(Box::new(f));
    }

    /// Every action declared in the bound contract, keyed by action name.
    /// Callers use this to present contract contents in UIs or to enumerate
    /// which actions exist before invoking the guard.
    pub fn actions(&self) -> impl Iterator<Item = &IndexedAction> {
        self.action_by_name.values()
    }

    pub fn action_by_name(&self, name: &str) -> Option<&IndexedAction> {
        self.action_by_name.get(name)
    }

    pub fn forbidden_actions(&self) -> impl Iterator<Item = (&String, &String)> {
        self.forbidden_by_name.iter()
    }

    pub fn target_sets(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.target_sets.iter()
    }

    pub fn check(&self, query: &GuardQuery) -> GuardDecision {
        let raw = self.check_raw(query);
        let adjusted = apply_enforcement_level(raw, self.enforcement_level);
        let actor = query
            .actor
            .clone()
            .unwrap_or_else(|| "tf:actor:process:local/unknown".to_string());
        self.emit(&adjusted, &actor, query);
        adjusted
    }

    /// Run the rule logic without applying the EnforcementLevel filter.
    pub fn check_raw(&self, query: &GuardQuery) -> GuardDecision {
        // 1. Negative capabilities take absolute precedence.
        for neg in &self.negative_capabilities {
            if negative_matches(neg, query) {
                let reason = neg.reason.clone().unwrap_or_else(|| {
                    format!("action {} is denied by negative_capability", query.action)
                });
                return GuardDecision::Deny {
                    reason,
                    danger_tags: vec!["explicit-denial".to_string()],
                };
            }
        }

        if let Some(reason) = self.forbidden_by_name.get(&query.action) {
            return GuardDecision::Deny {
                reason: if reason.is_empty() {
                    "action listed in forbidden".to_string()
                } else {
                    reason.clone()
                },
                danger_tags: Vec::new(),
            };
        }

        let Some(action) = self.action_by_name.get(&query.action) else {
            return GuardDecision::Deny {
                reason: format!("action \"{}\" is not declared", query.action),
                danger_tags: Vec::new(),
            };
        };

        let tags = action.danger_tags.clone();

        if let Some(target) = &query.target {
            for pattern in &action.deny_targets {
                if self.match_target(pattern, target) {
                    return GuardDecision::Deny {
                        reason: format!("target {} is in deny_targets ({})", target, pattern),
                        danger_tags: tags.clone(),
                    };
                }
            }
            if !action.allow_targets.is_empty() {
                let allowed = action
                    .allow_targets
                    .iter()
                    .any(|p| self.match_target(p, target));
                if !allowed {
                    return GuardDecision::Deny {
                        reason: format!("target {} is not in allow_targets", target),
                        danger_tags: tags.clone(),
                    };
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
            return GuardDecision::Escalate {
                reason: format!("danger_tags require escalation: {}", escalating.join(", ")),
                danger_tags: tags.clone(),
            };
        }

        match action.approval.as_deref() {
            Some("required") | Some("quorum") => {
                let approval = action.approval.clone().unwrap();
                GuardDecision::ApprovalRequired {
                    approval,
                    reason: format!("action \"{}\" requires approval", query.action),
                    danger_tags: tags,
                }
            }
            _ => GuardDecision::Allow { danger_tags: tags },
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
            enforcement_level: Some(self.enforcement_level.as_str().to_string()),
        });
    }
}

/// Apply the EnforcementLevel filter described in DECISIONS.md
/// "Progressive enforcement levels are core". Maps the raw rule
/// decision to the actual decision the caller will execute against.
pub fn apply_enforcement_level(raw: GuardDecision, level: EnforcementLevel) -> GuardDecision {
    match level {
        EnforcementLevel::E0 => match raw {
            GuardDecision::Deny { reason, mut danger_tags }
            | GuardDecision::Escalate { reason, mut danger_tags }
            | GuardDecision::ApprovalRequired { reason, mut danger_tags, .. } => {
                danger_tags.push("shadow".to_string());
                GuardDecision::LogOnly {
                    reason: format!("[shadow] would have decided: {}", reason),
                    danger_tags,
                }
            }
            other => other,
        },
        EnforcementLevel::E1 => match raw {
            GuardDecision::Deny { reason, mut danger_tags } => {
                danger_tags.push("warn".to_string());
                danger_tags.push(format!("would-deny:{}", reason));
                GuardDecision::Allow { danger_tags }
            }
            GuardDecision::Escalate { reason, mut danger_tags } => {
                danger_tags.push("warn".to_string());
                GuardDecision::LogOnly {
                    reason: format!("[warn] {}", reason),
                    danger_tags,
                }
            }
            other => other,
        },
        EnforcementLevel::E2 => tag_decision(raw, "proof-log-required"),
        EnforcementLevel::E3 => match raw {
            GuardDecision::Allow { danger_tags } if !danger_tags.is_empty() => {
                GuardDecision::Escalate {
                    reason: format!(
                        "E3 escalates allow with danger tags: {}",
                        danger_tags.join(", ")
                    ),
                    danger_tags,
                }
            }
            other => other,
        },
        EnforcementLevel::E4 => raw,
        EnforcementLevel::E5 => match raw {
            GuardDecision::Escalate { reason, danger_tags }
            | GuardDecision::ApprovalRequired { reason, danger_tags, .. } => GuardDecision::Deny {
                reason: format!("E5 fail-closed: {}", reason),
                danger_tags,
            },
            GuardDecision::Allow { danger_tags } if !danger_tags.is_empty() => GuardDecision::Deny {
                reason: format!(
                    "E5 fail-closed: allow with danger tags {} blocked",
                    danger_tags.join(", ")
                ),
                danger_tags,
            },
            other => other,
        },
    }
}

fn tag_decision(d: GuardDecision, tag: &str) -> GuardDecision {
    match d {
        GuardDecision::Allow { mut danger_tags } => {
            danger_tags.push(tag.to_string());
            GuardDecision::Allow { danger_tags }
        }
        GuardDecision::ApprovalRequired { approval, reason, mut danger_tags } => {
            danger_tags.push(tag.to_string());
            GuardDecision::ApprovalRequired { approval, reason, danger_tags }
        }
        GuardDecision::Escalate { reason, mut danger_tags } => {
            danger_tags.push(tag.to_string());
            GuardDecision::Escalate { reason, danger_tags }
        }
        GuardDecision::Deny { reason, mut danger_tags } => {
            danger_tags.push(tag.to_string());
            GuardDecision::Deny { reason, danger_tags }
        }
        GuardDecision::LogOnly { reason, mut danger_tags } => {
            danger_tags.push(tag.to_string());
            GuardDecision::LogOnly { reason, danger_tags }
        }
    }
}

fn negative_matches(neg: &NegativeCapability, q: &GuardQuery) -> bool {
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
