//! Rust side of the AgentGuard parity suite.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;
use tf_types::guard::{AgentGuard, GuardQuery};

#[derive(Deserialize)]
struct VectorsFile {
    contract: Value,
    cases: Vec<VectorCase>,
}

#[derive(Deserialize)]
struct VectorCase {
    name: String,
    query: QueryBody,
    expect: Expect,
}

#[derive(Deserialize)]
struct QueryBody {
    action: String,
    target: Option<String>,
}

#[derive(Deserialize)]
struct Expect {
    kind: String,
    danger_tags: Option<Vec<String>>,
}

fn load_vectors() -> VectorsFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("guard-vectors.yaml");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    tf_types::yaml::from_str(&raw).expect("parse guard-vectors.yaml")
}

#[test]
fn guard_vectors_match_ts() {
    let vectors = load_vectors();
    let guard = AgentGuard::from_contract(&vectors.contract);
    for c in &vectors.cases {
        let query = GuardQuery {
            actor: Some("tf:actor:agent:example.com/test".into()),
            actor_claim: None,
            action: c.query.action.clone(),
            target: c.query.target.clone(),
        };
        let decision = guard.check(&query);
        assert_eq!(
            decision.kind(),
            c.expect.kind,
            "{}: got {:?}",
            c.name,
            decision
        );
        if let Some(expected_tags) = &c.expect.danger_tags {
            let mut got: Vec<String> = decision.danger_tags().to_vec();
            let mut want: Vec<String> = expected_tags.clone();
            got.sort();
            want.sort();
            assert_eq!(got, want, "{} danger_tags mismatch", c.name);
        }
    }
}
