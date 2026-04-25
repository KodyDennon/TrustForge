//! Rust MCP bridge tests, including parity with the TS MCP normalize
//! function over `conformance/bridge-vectors.yaml`.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::json;

use tf_types::bridge_mcp::{
    contract_to_mcp_tools, mcp_to_contract_actions, McpBridge, McpBridgeConfig, McpImportOptions,
    McpTool, McpToolList,
};
use tf_types::bridges::{Bridge, BridgeKind};

#[derive(Deserialize)]
struct Vectors {
    mcp_normalize: Vec<NormVector>,
    webauthn: Vec<serde_yaml::Value>, // not used here, only to load file
}

#[derive(Deserialize)]
struct NormVector {
    name: String,
    tool: String,
    prefix: String,
    action: String,
}

fn load_vectors() -> Vectors {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("bridge-vectors.yaml");
    let raw = fs::read_to_string(&path).unwrap();
    serde_yaml::from_str(&raw).expect("parse bridge-vectors.yaml")
}

#[test]
fn normalize_tool_name_matches_parity_vectors() {
    let vectors = load_vectors();
    for v in &vectors.mcp_normalize {
        let cfg = McpBridgeConfig {
            bridge_id: "tf-mcp-bridge".into(),
            trust_domain: "example.com".into(),
            import: McpImportOptions {
                name_prefix: if v.prefix.is_empty() {
                    None
                } else {
                    Some(v.prefix.clone())
                },
                ..Default::default()
            },
        };
        let bridge = McpBridge::new(cfg);
        assert_eq!(bridge.normalize(&v.tool), v.action, "vector {}", v.name);
    }
    let _ = vectors.webauthn; // keep load symmetric
}

#[test]
fn imports_a_tool_list_into_actions() {
    let list = McpToolList {
        tools: vec![
            McpTool {
                name: "filesystem.read".into(),
                description: Some("Read a file".into()),
                input_schema: Some(json!({ "type": "object" })),
            },
            McpTool {
                name: "filesystem.delete".into(),
                description: Some("Delete a file".into()),
                input_schema: None,
            },
        ],
    };
    let mut tag_map = std::collections::HashMap::new();
    tag_map.insert(
        "filesystem.delete".to_string(),
        vec!["destructive".to_string(), "irreversible".to_string()],
    );
    let _ = &tag_map; // silence intermittent warning
    let opts = McpImportOptions {
        default_risk: Some("R3".into()),
        default_approval: Some("required".into()),
        danger_tag_map: tag_map,
        ..Default::default()
    };
    let actions = mcp_to_contract_actions(&list, &opts).expect("convert");
    assert_eq!(actions.len(), 2);
    // TS normalize converts `.` and other non-alphanumeric chars to `_` and
    // prepends `mcp.` if the result has no dot.
    assert_eq!(actions[0].name, "mcp.filesystem_read");
    assert_eq!(actions[0].risk, "R3");
    assert_eq!(actions[0].approval, "required");
    assert_eq!(actions[0].description.as_deref(), Some("Read a file"));
    let delete = &actions[1];
    assert_eq!(delete.name, "mcp.filesystem_delete");
    let tags = delete.danger_tags.as_ref().expect("danger tags");
    assert!(tags.contains(&"destructive".to_string()));
    assert!(tags.contains(&"irreversible".to_string()));
}

#[test]
fn rejects_a_tool_with_no_name() {
    let list = McpToolList {
        tools: vec![McpTool {
            name: String::new(),
            description: None,
            input_schema: None,
        }],
    };
    let result = mcp_to_contract_actions(&list, &McpImportOptions::default());
    assert!(result.is_err());
}

#[test]
fn round_trip_actions_to_tools_preserves_name_and_description() {
    let list = McpToolList {
        tools: vec![McpTool {
            name: "tools.echo".into(),
            description: Some("Echoes the input".into()),
            input_schema: None,
        }],
    };
    let actions = mcp_to_contract_actions(&list, &McpImportOptions::default()).unwrap();
    // After normalization the action name is `mcp.tools_echo`; back-conversion
    // keeps the action's own name.
    let back = contract_to_mcp_tools(&actions);
    assert_eq!(back.tools[0].name, "mcp.tools_echo");
    assert!(back.tools[0]
        .description
        .as_deref()
        .unwrap_or_default()
        .contains("Echoes the input"));
}

#[test]
fn bridge_implements_bridge_trait() {
    let cfg = McpBridgeConfig {
        bridge_id: "tf-mcp".into(),
        trust_domain: "example.com".into(),
        import: McpImportOptions::default(),
    };
    let bridge = McpBridge::new(cfg);
    assert_eq!(bridge.bridge_id(), "tf-mcp");
    assert_eq!(bridge.trust_domain(), "example.com");
    assert!(matches!(bridge.kind(), BridgeKind::Mcp));
}

#[test]
fn warning_prefix_appears_when_action_has_danger_tags() {
    let list = McpToolList {
        tools: vec![McpTool {
            name: "fs.delete".into(),
            description: Some("Delete a file".into()),
            input_schema: None,
        }],
    };
    let mut tag_map = std::collections::HashMap::new();
    tag_map.insert(
        "fs.delete".to_string(),
        vec!["destructive".to_string()],
    );
    let actions = mcp_to_contract_actions(
        &list,
        &McpImportOptions {
            danger_tag_map: tag_map,
            ..Default::default()
        },
    )
    .unwrap();
    let back = contract_to_mcp_tools(&actions);
    let desc = back.tools[0]
        .description
        .as_deref()
        .unwrap_or_default();
    assert!(desc.contains("⚠️"));
    assert!(desc.contains("destructive"));
}
