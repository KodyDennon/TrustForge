#![allow(clippy::field_reassign_with_default)]
//! `.tf/` manifest loader — Rust mirror of
//! `tools/tf-types-ts/src/core/tf-manifests.ts`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default)]
pub struct TfManifestPaths {
    pub root_dir: PathBuf,
    pub agent_contract: Option<PathBuf>,
    pub threat_model: Option<PathBuf>,
    pub policy: Option<PathBuf>,
    pub actions: Option<PathBuf>,
    pub proof_profile: Option<PathBuf>,
    pub codegen: Option<PathBuf>,
    pub conformance: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TfManifests {
    pub agent_contract: Option<Value>,
    pub threat_model: Option<Value>,
    pub policy: Option<Value>,
    pub actions: Option<Value>,
    pub proof_profile: Option<Value>,
    pub codegen: Option<HashMap<String, String>>,
    pub conformance: Option<Value>,
    pub diagnostics: Vec<TfDiagnostic>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TfDiagnostic {
    pub file: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct TfFeatureGate {
    pub policy: Option<Value>,
    pub claimed_profiles: Vec<String>,
    pub default_proof_level: Option<String>,
    pub anchors: Vec<Value>,
    pub forbidden_actions: Vec<String>,
    pub per_action_proof_level: HashMap<String, String>,
}

impl TfFeatureGate {
    pub fn proof_level_for_action(&self, action: &str) -> Option<&str> {
        self.per_action_proof_level.get(action).map(String::as_str)
    }
}

const REL_AGENT_CONTRACT: &str = ".tf/agent-contract.yaml";
const REL_THREAT_MODEL: &str = ".tf/threat-model.yaml";
const REL_POLICY: &str = ".tf/policy.yaml";
const REL_ACTIONS: &str = ".tf/actions.yaml";
const REL_PROOF_PROFILE: &str = ".tf/proof-profile.yaml";
const REL_CODEGEN: &str = ".tf/codegen.toml";
const REL_CONFORMANCE: &str = ".tf/conformance.json";

pub fn load_tf_manifests(paths: &TfManifestPaths) -> TfManifests {
    let mut out = TfManifests::default();
    let try_yaml = |path: &Path, target: &mut Option<Value>, diags: &mut Vec<TfDiagnostic>| {
        if !path.exists() {
            return;
        }
        match fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|raw| crate::yaml::parse(&raw).map_err(|e| e.to_string()))
        {
            Ok(v) => *target = Some(v),
            Err(reason) => diags.push(TfDiagnostic {
                file: path.display().to_string(),
                reason,
            }),
        }
    };
    let try_json = |path: &Path, target: &mut Option<Value>, diags: &mut Vec<TfDiagnostic>| {
        if !path.exists() {
            return;
        }
        match fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|raw| serde_json::from_str::<Value>(&raw).map_err(|e| e.to_string()))
        {
            Ok(v) => *target = Some(v),
            Err(reason) => diags.push(TfDiagnostic {
                file: path.display().to_string(),
                reason,
            }),
        }
    };

    let agent = paths
        .agent_contract
        .clone()
        .unwrap_or_else(|| paths.root_dir.join(REL_AGENT_CONTRACT));
    try_yaml(&agent, &mut out.agent_contract, &mut out.diagnostics);
    let tm = paths
        .threat_model
        .clone()
        .unwrap_or_else(|| paths.root_dir.join(REL_THREAT_MODEL));
    try_yaml(&tm, &mut out.threat_model, &mut out.diagnostics);
    let policy = paths
        .policy
        .clone()
        .unwrap_or_else(|| paths.root_dir.join(REL_POLICY));
    try_yaml(&policy, &mut out.policy, &mut out.diagnostics);
    let actions = paths
        .actions
        .clone()
        .unwrap_or_else(|| paths.root_dir.join(REL_ACTIONS));
    try_yaml(&actions, &mut out.actions, &mut out.diagnostics);
    let pp = paths
        .proof_profile
        .clone()
        .unwrap_or_else(|| paths.root_dir.join(REL_PROOF_PROFILE));
    try_yaml(&pp, &mut out.proof_profile, &mut out.diagnostics);
    let cf = paths
        .conformance
        .clone()
        .unwrap_or_else(|| paths.root_dir.join(REL_CONFORMANCE));
    try_json(&cf, &mut out.conformance, &mut out.diagnostics);

    let cg = paths
        .codegen
        .clone()
        .unwrap_or_else(|| paths.root_dir.join(REL_CODEGEN));
    if cg.exists() {
        match fs::read_to_string(&cg) {
            Ok(raw) => out.codegen = Some(parse_tiny_toml(&raw)),
            Err(e) => out.diagnostics.push(TfDiagnostic {
                file: cg.display().to_string(),
                reason: e.to_string(),
            }),
        }
    }
    out
}

pub fn build_feature_gate(manifests: &TfManifests) -> TfFeatureGate {
    let mut gate = TfFeatureGate::default();
    gate.policy = manifests.policy.clone();
    if let Some(conf) = manifests.conformance.as_ref() {
        if let Some(arr) = conf.get("claimed_profiles").and_then(|v| v.as_array()) {
            gate.claimed_profiles = arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
        }
    }
    if let Some(pp) = manifests.proof_profile.as_ref() {
        gate.default_proof_level = pp
            .get("default_proof_level")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                pp.get("default_level")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            });
        if let Some(actions) = pp.get("actions").and_then(|v| v.as_array()) {
            for a in actions {
                if let (Some(name), Some(level)) = (
                    a.get("name").and_then(|v| v.as_str()),
                    a.get("level").and_then(|v| v.as_str()),
                ) {
                    gate.per_action_proof_level
                        .insert(name.to_string(), level.to_string());
                }
            }
        }
        if let Some(anchors) = pp.get("anchors").and_then(|v| v.as_array()) {
            gate.anchors = anchors.clone();
        }
    }
    if let Some(ac) = manifests.agent_contract.as_ref() {
        if let Some(forbidden) = ac.get("forbidden").and_then(|v| v.as_array()) {
            for f in forbidden {
                if let Some(name) = f.get("action").and_then(|v| v.as_str()) {
                    gate.forbidden_actions.push(name.to_string());
                }
            }
        }
    }
    gate
}

fn parse_tiny_toml(raw: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in raw.lines() {
        let stripped = line.split('#').next().unwrap_or(line).trim();
        if stripped.is_empty() {
            continue;
        }
        if let Some((k, v)) = stripped.split_once('=') {
            let key = k.trim();
            let mut value = v.trim();
            if (value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))
            {
                value = &value[1..value.len() - 1];
            }
            out.insert(key.to_string(), value.to_string());
        }
    }
    out
}
