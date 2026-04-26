//! Rust .tf manifest loader tests — mirror of TS suite.

use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;
use tf_types::tf_manifests::{build_feature_gate, load_tf_manifests, TfManifestPaths};

fn write(path: &PathBuf, content: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

#[test]
fn loads_present_manifests_and_skips_absent() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write(
        &root.join(".tf/agent-contract.yaml"),
        "contract_version: \"1\"\nspec_version: TF-0006-draft\nproject: x\ntrust_domain: example.com\nactions: []\n",
    );
    write(
        &root.join(".tf/policy.yaml"),
        "policy_version: \"1\"\ntrust_domain: example.com\nrules:\n  - id: allow.read\n    effect: allow\n    action: file.read\n",
    );
    write(
        &root.join(".tf/conformance.json"),
        "{\"conformance_version\":\"1\",\"subject\":\"tf-svc-1\",\"claimed_profiles\":[\"tf-core-compatible\"],\"evidence\":[{\"kind\":\"test\",\"id\":\"t1\"}]}",
    );
    write(
        &root.join(".tf/codegen.toml"),
        "ts_target = \"src/generated\"\n",
    );
    let m = load_tf_manifests(&TfManifestPaths {
        root_dir: root,
        ..Default::default()
    });
    assert!(m.diagnostics.is_empty());
    assert!(m.agent_contract.is_some());
    assert!(m.policy.is_some());
    assert!(m.conformance.is_some());
    assert!(m.threat_model.is_none());
    assert_eq!(
        m.codegen.as_ref().and_then(|c| c.get("ts_target")),
        Some(&"src/generated".to_string())
    );
}

#[test]
fn build_feature_gate_composes_runtime_view() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write(
        &root.join(".tf/agent-contract.yaml"),
        "contract_version: \"1\"\nspec_version: TF-0006-draft\nproject: x\ntrust_domain: example.com\nactions: []\nforbidden:\n  - action: shell.exec\n    reason: never\n",
    );
    write(
        &root.join(".tf/proof-profile.yaml"),
        "proof_profile_version: \"1\"\ntrust_domain: example.com\ndefault_proof_level: L1\nactions:\n  - name: payment.charge\n    level: L4\n    anchor: rfc6962\n",
    );
    write(
        &root.join(".tf/conformance.json"),
        "{\"conformance_version\":\"1\",\"subject\":\"tf-svc-1\",\"claimed_profiles\":[\"tf-core-compatible\",\"tf-bridge-compatible\"],\"evidence\":[{\"kind\":\"test\",\"id\":\"t1\"}]}",
    );
    let manifests = load_tf_manifests(&TfManifestPaths {
        root_dir: root,
        ..Default::default()
    });
    let gate = build_feature_gate(&manifests);
    assert!(gate
        .claimed_profiles
        .iter()
        .any(|p| p == "tf-core-compatible"));
    assert_eq!(gate.proof_level_for_action("payment.charge"), Some("L4"));
    assert_eq!(gate.default_proof_level.as_deref(), Some("L1"));
    assert!(gate.forbidden_actions.iter().any(|a| a == "shell.exec"));
}

#[test]
fn parse_failure_emits_diagnostic() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    write(&root.join(".tf/conformance.json"), "this is not json {");
    let m = load_tf_manifests(&TfManifestPaths {
        root_dir: root,
        ..Default::default()
    });
    assert!(m
        .diagnostics
        .iter()
        .any(|d| d.file.ends_with("conformance.json")));
}
