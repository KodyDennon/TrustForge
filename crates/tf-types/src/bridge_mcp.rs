//! MCP bridge — Rust mirror of `tools/tf-types-ts/src/core/bridge-mcp.ts`.
//!
//! Translates between an MCP tool list and a partial agent-contract
//! action array. The bridge does not speak MCP JSON-RPC itself; it only
//! shapes the data so the AgentGuard sees the same actions whether the
//! AI agent discovered them via `.tf/agent-contract.yaml` or via an MCP
//! `tools/list` response.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::bridges::{Bridge, BridgeError, BridgeKind};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct McpTool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    #[serde(
        rename = "inputSchema",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub input_schema: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct McpToolList {
    pub tools: Vec<McpTool>,
}

#[derive(Clone, Debug, Default)]
pub struct McpImportOptions {
    pub default_risk: Option<String>,
    pub default_approval: Option<String>,
    pub default_proof: Option<String>,
    pub danger_tag_map: HashMap<String, Vec<String>>,
    pub name_prefix: Option<String>,
}

/// One projected action; the shape mirrors the TS `Action` so contracts
/// can be merged back into a YAML agent-contract.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct McpAction {
    pub name: String,
    pub risk: String,
    pub approval: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parameters: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub danger_tags: Option<Vec<String>>,
}

/// Valid action names are two or more dot-separated segments, each
/// `[a-z][a-z0-9_]*` (formerly the pattern
/// `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`).
fn is_valid_action_name(name: &str) -> bool {
    let mut segments = 0usize;
    for segment in name.split('.') {
        let bytes = segment.as_bytes();
        let Some((&first, rest)) = bytes.split_first() else {
            return false; // empty segment (leading/trailing/double dot)
        };
        if !first.is_ascii_lowercase() {
            return false;
        }
        if !rest
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return false;
        }
        segments += 1;
    }
    segments >= 2
}

fn normalize_tool_name(name: &str, prefix: Option<&str>) -> String {
    let mut scrubbed = String::with_capacity(name.len());
    let mut prev_underscore = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            scrubbed.push(ch.to_ascii_lowercase());
            prev_underscore = false;
        } else if !prev_underscore {
            scrubbed.push('_');
            prev_underscore = true;
        }
    }
    let trimmed = scrubbed.trim_matches('_').to_string();
    let with_prefix = match prefix {
        Some(p) if !p.is_empty() => format!("{}.{}", p, trimmed),
        _ => trimmed,
    };
    if with_prefix.contains('.') {
        with_prefix
    } else {
        format!("mcp.{}", with_prefix)
    }
}

pub fn mcp_to_contract_actions(
    tool_list: &McpToolList,
    opts: &McpImportOptions,
) -> Result<Vec<McpAction>, BridgeError> {
    let default_risk = opts
        .default_risk
        .clone()
        .unwrap_or_else(|| "R2".to_string());
    let default_approval = opts
        .default_approval
        .clone()
        .unwrap_or_else(|| "conditional".to_string());
    let mut out = Vec::with_capacity(tool_list.tools.len());
    for tool in &tool_list.tools {
        if tool.name.is_empty() {
            return Err(BridgeError::InvalidInput("MCP tool missing a name".into()));
        }
        let action_name = normalize_tool_name(&tool.name, opts.name_prefix.as_deref());
        if !is_valid_action_name(&action_name) {
            return Err(BridgeError::InvalidInput(format!(
                "MCP tool {} produced invalid action name {}",
                tool.name, action_name
            )));
        }
        let danger_tags = opts.danger_tag_map.get(&tool.name).cloned();
        let action = McpAction {
            name: action_name,
            risk: default_risk.clone(),
            approval: default_approval.clone(),
            proof: opts.default_proof.clone(),
            description: tool.description.clone(),
            parameters: tool.input_schema.clone(),
            danger_tags: danger_tags.filter(|t| !t.is_empty()),
        };
        out.push(action);
    }
    Ok(out)
}

pub fn contract_to_mcp_tools(actions: &[McpAction]) -> McpToolList {
    let tools = actions
        .iter()
        .map(|action| {
            let warning = match action.danger_tags.as_ref() {
                Some(tags) if !tags.is_empty() => format!("⚠️ {}. ", tags.join(", ")),
                _ => String::new(),
            };
            let description = format!(
                "{}{}",
                warning,
                action.description.clone().unwrap_or_default()
            )
            .trim()
            .to_string();
            McpTool {
                name: action.name.clone(),
                description: if description.is_empty() {
                    None
                } else {
                    Some(description)
                },
                input_schema: action.parameters.clone(),
            }
        })
        .collect();
    McpToolList { tools }
}

#[derive(Clone, Debug, Default)]
pub struct McpBridgeConfig {
    pub bridge_id: String,
    pub trust_domain: String,
    pub import: McpImportOptions,
}

pub struct McpBridge {
    cfg: McpBridgeConfig,
}

impl McpBridge {
    pub fn new(cfg: McpBridgeConfig) -> Self {
        McpBridge { cfg }
    }

    pub fn import_tools(&self, tool_list: &McpToolList) -> Result<Vec<McpAction>, BridgeError> {
        mcp_to_contract_actions(tool_list, &self.cfg.import)
    }

    pub fn export_tools(&self, actions: &[McpAction]) -> McpToolList {
        contract_to_mcp_tools(actions)
    }

    /// Normalize a tool name the same way the bridge does at import time.
    pub fn normalize(&self, tool_name: &str) -> String {
        normalize_tool_name(tool_name, self.cfg.import.name_prefix.as_deref())
    }
}

impl Bridge for McpBridge {
    fn bridge_id(&self) -> &str {
        &self.cfg.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::Mcp
    }
    fn trust_domain(&self) -> &str {
        &self.cfg.trust_domain
    }
}
