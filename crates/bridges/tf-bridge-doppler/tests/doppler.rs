//! Tests for the Doppler bridge — uses `wiremock` to mock the Doppler
//! `/v3/me` endpoint, then exercises actor projection + secret-mapping.

use serde_json::json;
use tf_bridge_doppler::{
    doppler_secret_to_capability, doppler_service_token_to_actor, doppler_token_to_actor,
    DopplerBridgeError, DopplerTokenInfo, DopplerTokenType, DopplerVerifier,
};
use tf_types::generated::{ActorType, Constraint, RiskClass};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn me_body() -> serde_json::Value {
    json!({
        "slug": "ci-runner",
        "name": "CI Runner",
        "type": "service",
        "project": "trustforge",
        "config": "prod",
        "workplace": {
            "id": "wp_123",
            "name": "Acme Corp",
            "slug": "acme",
        }
    })
}

#[tokio::test]
async fn doppler_introspect_round_trip_service_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v3/me"))
        .and(header("authorization", "Bearer dp.st.prod.aaaaaaaa"))
        .respond_with(ResponseTemplate::new(200).set_body_json(me_body()))
        .mount(&server)
        .await;
    let verifier = DopplerVerifier::new(server.uri());
    let info = verifier.introspect("dp.st.prod.aaaaaaaa").await.unwrap();
    assert_eq!(info.slug, "ci-runner");
    assert_eq!(info.workplace_id, "wp_123");
    assert_eq!(info.project.as_deref(), Some("trustforge"));
    assert_eq!(info.config.as_deref(), Some("prod"));
    assert_eq!(info.token_type, DopplerTokenType::Service);
}

#[tokio::test]
async fn doppler_introspect_translates_to_actor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v3/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(me_body()))
        .mount(&server)
        .await;
    let verifier = DopplerVerifier::new(server.uri());
    let (actor, info) = doppler_service_token_to_actor(&verifier, "dp.st.prod.aaaa")
        .await
        .unwrap();
    assert_eq!(
        actor.actor_id,
        "tf:actor:service:doppler.com/wp_123/trustforge/prod/ci-runner"
    );
    assert_eq!(actor.actor_type, ActorType::Service);
    assert_eq!(info.workplace_name, "Acme Corp");
}

#[tokio::test]
async fn doppler_introspect_rejects_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v3/me"))
        .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
        .mount(&server)
        .await;
    let verifier = DopplerVerifier::new(server.uri());
    let err = verifier.introspect("dp.st.prod.bbb").await.unwrap_err();
    assert!(matches!(err, DopplerBridgeError::Rejected(_)));
}

#[tokio::test]
async fn doppler_introspect_rejects_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v3/me"))
        .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
        .mount(&server)
        .await;
    let verifier = DopplerVerifier::new(server.uri());
    let err = verifier.introspect("dp.st.prod.bbb").await.unwrap_err();
    assert!(matches!(err, DopplerBridgeError::Rejected(_)));
}

#[tokio::test]
async fn doppler_introspect_propagates_500_as_network_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v3/me"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let verifier = DopplerVerifier::new(server.uri());
    let err = verifier.introspect("dp.st.prod.bbb").await.unwrap_err();
    assert!(matches!(err, DopplerBridgeError::Network(_)));
}

#[tokio::test]
async fn doppler_introspect_rejects_empty_token() {
    let verifier = DopplerVerifier::doppler();
    let err = verifier.introspect("").await.unwrap_err();
    assert!(matches!(err, DopplerBridgeError::InvalidInput(_)));
}

#[test]
fn doppler_token_info_with_no_project_uses_any() {
    let info = DopplerTokenInfo {
        slug: "x".into(),
        name: "x".into(),
        workplace_id: "wp_123".into(),
        workplace_name: "Acme".into(),
        project: None,
        config: None,
        token_type: DopplerTokenType::ServiceAccount,
    };
    let actor = doppler_token_to_actor(&info).unwrap();
    assert_eq!(
        actor.actor_id,
        "tf:actor:service:doppler.com/wp_123/any/any/x"
    );
}

#[test]
fn doppler_secret_to_capability_uses_doppler_uri() {
    let cap = doppler_secret_to_capability("trustforge", "prod", "DATABASE_URL");
    assert_eq!(cap.name, "doppler.kv.read");
    assert_eq!(cap.risk, RiskClass::R2);
    let cs = cap.constraints.unwrap();
    match &cs[0] {
        Constraint::Target { patterns } => {
            assert_eq!(patterns[0], "doppler://trustforge/prod/DATABASE_URL");
        }
        _ => unreachable!(),
    }
}
