//! Tests for the GCP ID-token bridge — uses `wiremock` to host a JWKS,
//! signs tokens with a freshly generated RSA key, and verifies they round
//! trip through the bridge.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use sha2::Sha256;
use tf_bridge_gcp::{
    gcp_iam_role_to_capabilities, service_account_to_actor, verify_gcp_id_token, GcpBridgeError,
    GcpIdTokenVerifier, GcpServiceAccountInfo,
};
use tf_types::generated::{ActorType, RiskClass, TrustLevel};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISSUER: &str = "https://accounts.google.com";

struct SignedJwt {
    jwt: String,
    jwks: serde_json::Value,
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn make_signed_jwt(audience: &str, sub: &str, email: Option<&str>, kid: &str) -> SignedJwt {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let public_key = RsaPublicKey::from(&private_key);

    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();
    let n_b64 = b64url(&n_bytes);
    let e_b64 = b64url(&e_bytes);

    let header = json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": kid,
    });
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims = json!({
        "iss": ISSUER,
        "sub": sub,
        "aud": audience,
        "exp": now + 3600,
        "iat": now,
    });
    if let Some(e) = email {
        claims["email"] = json!(e);
        claims["email_verified"] = json!(true);
    }
    let header_b64 = b64url(serde_json::to_string(&header).unwrap().as_bytes());
    let claims_b64 = b64url(serde_json::to_string(&claims).unwrap().as_bytes());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign_with_rng(&mut rng, signing_input.as_bytes());
    let sig_b64 = b64url(&signature.to_bytes());
    let jwt = format!("{signing_input}.{sig_b64}");

    let jwks = json!({
        "keys": [
            {
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": n_b64,
                "e": e_b64,
            }
        ]
    });
    SignedJwt { jwt, jwks }
}

#[tokio::test]
async fn verify_gcp_id_token_round_trip() {
    let aud = "1234567890.apps.googleusercontent.com";
    let signed = make_signed_jwt(aud, "112233", Some("alice@example.com"), "test-kid");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/v3/certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(signed.jwks.clone()))
        .mount(&server)
        .await;

    let jwks_url = format!("{}/oauth2/v3/certs", server.uri());
    let verifier = GcpIdTokenVerifier::new(jwks_url, ISSUER, vec![aud.to_string()]);
    let identity = verify_gcp_id_token(&verifier, &signed.jwt).await.unwrap();
    assert_eq!(identity.iss, ISSUER);
    assert_eq!(identity.sub, "112233");
    assert_eq!(identity.aud, aud);
    assert_eq!(identity.email.as_deref(), Some("alice@example.com"));
    assert!(identity.email_verified);
}

#[tokio::test]
async fn verify_gcp_id_token_rejects_wrong_audience() {
    let aud = "1234567890.apps.googleusercontent.com";
    let signed = make_signed_jwt(aud, "112233", None, "test-kid-2");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/v3/certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(signed.jwks.clone()))
        .mount(&server)
        .await;
    let jwks_url = format!("{}/oauth2/v3/certs", server.uri());
    let verifier = GcpIdTokenVerifier::new(jwks_url, ISSUER, vec!["other-audience".to_string()]);
    let err = verify_gcp_id_token(&verifier, &signed.jwt)
        .await
        .unwrap_err();
    assert!(matches!(err, GcpBridgeError::Rejected(_)));
}

#[tokio::test]
async fn verify_gcp_id_token_rejects_missing_kid() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/v3/certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys": []})))
        .mount(&server)
        .await;
    let jwks_url = format!("{}/oauth2/v3/certs", server.uri());
    let verifier = GcpIdTokenVerifier::new(jwks_url, ISSUER, vec!["aud".to_string()]);
    // A header without kid:
    let bogus = format!(
        "{}.{}.AAAA",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(r#"{"iss":"x","sub":"y","exp":0,"iat":0,"aud":"z"}"#)
    );
    let err = verify_gcp_id_token(&verifier, &bogus).await.unwrap_err();
    assert!(matches!(err, GcpBridgeError::Rejected(_)));
}

#[tokio::test]
async fn verify_gcp_id_token_rejects_empty_token() {
    let verifier = GcpIdTokenVerifier::google(vec!["aud".into()]);
    let err = verify_gcp_id_token(&verifier, "").await.unwrap_err();
    assert!(matches!(err, GcpBridgeError::InvalidInput(_)));
}

#[test]
fn service_account_to_actor_with_explicit_project() {
    let sa = GcpServiceAccountInfo {
        email: "build@my-team.iam.gserviceaccount.com".into(),
        project_id: Some("my-team".into()),
        unique_id: None,
    };
    let actor = service_account_to_actor(&sa).unwrap();
    assert_eq!(
        actor.actor_id,
        "tf:actor:service:gcp.googleapis.com/my-team/sa/build"
    );
    assert_eq!(actor.actor_type, ActorType::Service);
    assert_eq!(actor.trust_levels, vec![TrustLevel::T3]);
    assert_eq!(actor.authority_roots[0].id, "projects/my-team");
}

#[test]
fn service_account_inference_fails_for_compute_default() {
    let sa = GcpServiceAccountInfo {
        email: "1234-compute@developer.gserviceaccount.com".into(),
        project_id: None,
        unique_id: None,
    };
    let err = service_account_to_actor(&sa).unwrap_err();
    assert!(matches!(err, GcpBridgeError::InvalidInput(_)));
}

#[test]
fn role_translation_storage_admin_is_wildcard_r3() {
    let caps = gcp_iam_role_to_capabilities("roles/storage.admin");
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].name, "gcp.storage.*");
    assert_eq!(caps[0].risk, RiskClass::R3);
}

#[test]
fn role_translation_secret_accessor_is_r2() {
    let caps = gcp_iam_role_to_capabilities("roles/secretmanager.secretAccessor");
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].name, "gcp.secretmanager.access_secret");
    assert_eq!(caps[0].risk, RiskClass::R2);
}

#[test]
fn role_translation_iam_token_creator_is_high_risk() {
    let caps = gcp_iam_role_to_capabilities("roles/iam.serviceAccountTokenCreator");
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].risk, RiskClass::R3);
}
