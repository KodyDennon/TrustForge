//! Coverage for `BridgesRegistry::load` / `from_str` /
//! `resolve_by_issuer`. Mirrors the TS `bridges-registry.test.ts`.

use std::fs;

use tf_types::bridges_registry::{
    BridgeEntry, BridgesRegistry, BridgesRegistryError, BridgesRegistryKind,
};

fn sample_doc() -> &'static str {
    r#"
registry_version: "1"
default_profile: tf-home-compatible
bridges:
  - kind: oauth
    issuer_match: "https://accounts.google.com"
    trust_level: T2
    capability_map:
      openid: "auth.openid"
      email: "user.email.read"
  - kind: clerk
    iss_pattern: clerk.dev
    trust_level: T2
  - kind: spiffe
    issuer_match: "spiffe://example.com"
    trust_level: T3
"#
}

#[test]
fn loads_valid_registry() {
    let registry = BridgesRegistry::from_str(sample_doc()).expect("parse");
    assert_eq!(registry.registry_version, "1");
    assert_eq!(registry.default_profile.as_deref(), Some("tf-home-compatible"));
    assert_eq!(registry.bridges.len(), 3);
    assert_eq!(registry.bridges[0].kind, BridgesRegistryKind::Oauth);
    assert_eq!(
        registry.bridges[0].issuer_match.as_deref(),
        Some("https://accounts.google.com"),
    );
    let cap = registry.bridges[0]
        .capability_map
        .as_ref()
        .expect("capability_map");
    assert_eq!(cap.get("openid"), Some(&"auth.openid".to_string()));
}

#[test]
fn resolves_by_issuer_exact_match_wins() {
    let registry = BridgesRegistry::from_str(sample_doc()).expect("parse");
    let hit = registry
        .resolve_by_issuer("https://accounts.google.com")
        .expect("hit");
    assert_eq!(hit.kind, BridgesRegistryKind::Oauth);
}

#[test]
fn resolves_by_issuer_substring_pattern() {
    let registry = BridgesRegistry::from_str(sample_doc()).expect("parse");
    let hit = registry
        .resolve_by_issuer("https://api.clerk.dev/v1/sessions/abc")
        .expect("hit");
    assert_eq!(hit.kind, BridgesRegistryKind::Clerk);
}

#[test]
fn resolves_by_issuer_unknown_returns_none() {
    let registry = BridgesRegistry::from_str(sample_doc()).expect("parse");
    assert!(registry.resolve_by_issuer("https://unknown.example/").is_none());
    assert!(registry.resolve_by_issuer("").is_none());
}

#[test]
fn override_wins_over_default_for_same_issuer() {
    // Custom registry mapping `clerk.dev` to `oauth` (not the built-in
    // clerk handler) — the registry's mapping takes precedence over
    // whatever default the resolver would otherwise apply.
    let custom = r#"
registry_version: "1"
bridges:
  - kind: oauth
    issuer_match: clerk.dev
    trust_level: T1
"#;
    let registry = BridgesRegistry::from_str(custom).expect("parse");
    let hit = registry.resolve_by_issuer("clerk.dev").expect("hit");
    assert_eq!(hit.kind, BridgesRegistryKind::Oauth);
    assert_eq!(hit.trust_level.as_deref(), Some("T1"));
}

#[test]
fn rejects_missing_registry_version() {
    let bad = r#"
bridges: []
"#;
    let err = BridgesRegistry::from_str(bad).expect_err("must reject");
    match err {
        BridgesRegistryError::Invalid(_) => {}
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn rejects_unknown_kind() {
    let bad = r#"
registry_version: "1"
bridges:
  - kind: futurebridge
"#;
    let err = BridgesRegistry::from_str(bad).expect_err("must reject");
    assert!(matches!(err, BridgesRegistryError::Invalid(_)));
}

#[test]
fn rejects_bad_capability_map_target() {
    let bad = r#"
registry_version: "1"
bridges:
  - kind: oauth
    issuer_match: x
    capability_map:
      email: "NOT a valid action"
"#;
    let err = BridgesRegistry::from_str(bad).expect_err("must reject");
    assert!(matches!(err, BridgesRegistryError::Invalid(_)));
}

#[test]
fn rejects_unknown_top_level_key() {
    let bad = r#"
registry_version: "1"
bridges: []
extra: 1
"#;
    let err = BridgesRegistry::from_str(bad).expect_err("must reject");
    assert!(matches!(err, BridgesRegistryError::Invalid(_)));
}

#[test]
fn rejects_bad_profile_pattern() {
    let bad = r#"
registry_version: "1"
default_profile: not-a-tf-profile
bridges: []
"#;
    let err = BridgesRegistry::from_str(bad).expect_err("must reject");
    assert!(matches!(err, BridgesRegistryError::Invalid(_)));
}

#[test]
fn missing_file_resolves_to_empty_registry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bridges.yaml");
    let registry = BridgesRegistry::load(&path).expect("missing file -> empty");
    assert_eq!(registry.bridges.len(), 0);
}

#[test]
fn load_from_file_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bridges.yaml");
    fs::write(&path, sample_doc()).expect("write");
    let registry = BridgesRegistry::load(&path).expect("load");
    assert_eq!(registry.bridges.len(), 3);
    let hit = registry
        .resolve_by_kind(&BridgesRegistryKind::Spiffe)
        .expect("hit");
    let entry: &BridgeEntry = hit;
    assert_eq!(entry.trust_level.as_deref(), Some("T3"));
}
