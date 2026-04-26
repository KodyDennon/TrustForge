//! Rust GNAP/DPoP bridge tests. Mints real ES256 access tokens against
//! a known JWKS, has a client present a DPoP proof signed by the same
//! private key the access token's `cnf.jkt` was bound to, and verifies
//! end-to-end through the bridge.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::LineEnding as P256LineEnding;
use p256::SecretKey;
use rand::rngs::OsRng;
use serde::Serialize;

use tf_types::bridge_gnap::{
    jwk_thumbprint, GnapAccessRight, GnapAccessTokenRequest, GnapBridge, GnapBridgeConfig,
    GnapClient, GnapGrantRequest, GnapKeyDescriptor,
};
use tf_types::bridge_oauth::{Jwk, Jwks};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn b64u(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

struct AsKey {
    pem: Vec<u8>,
    jwk: Jwk,
}

fn make_as_key() -> AsKey {
    let secret = SecretKey::random(&mut OsRng);
    let pem = secret
        .to_pkcs8_pem(P256LineEnding::LF)
        .unwrap()
        .as_bytes()
        .to_vec();
    let public = secret.public_key();
    let encoded = public.to_encoded_point(false);
    let x = encoded.x().expect("x");
    let y = encoded.y().expect("y");
    let jwk = Jwk {
        kty: "EC".into(),
        alg: Some("ES256".into()),
        kid: Some("as-key-1".into()),
        crv: Some("P-256".into()),
        x: Some(b64u(x.as_slice())),
        y: Some(b64u(y.as_slice())),
        n: None,
        e: None,
    };
    AsKey { pem, jwk }
}

struct ClientKey {
    sign_pem: Vec<u8>,
    jwk: Jwk,
    jkt: String,
}

fn make_client_key() -> ClientKey {
    let secret = SecretKey::random(&mut OsRng);
    let pem = secret
        .to_pkcs8_pem(P256LineEnding::LF)
        .unwrap()
        .as_bytes()
        .to_vec();
    let public = secret.public_key();
    let encoded = public.to_encoded_point(false);
    let x = encoded.x().unwrap();
    let y = encoded.y().unwrap();
    let jwk = Jwk {
        kty: "EC".into(),
        alg: Some("ES256".into()),
        kid: None,
        crv: Some("P-256".into()),
        x: Some(b64u(x.as_slice())),
        y: Some(b64u(y.as_slice())),
        n: None,
        e: None,
    };
    let jkt = jwk_thumbprint(&jwk).unwrap();
    ClientKey {
        sign_pem: pem,
        jwk,
        jkt,
    }
}

#[derive(Serialize)]
struct AccessClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    iat: u64,
    exp: u64,
    cnf: serde_json::Value,
    tf_actor_type: &'a str,
}

fn mint_access_token(as_key: &AsKey, sub: &str, jkt: &str) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("as-key-1".into());
    let claims = AccessClaims {
        iss: "https://as.example.com",
        sub,
        iat: now(),
        exp: now() + 300,
        cnf: serde_json::json!({ "jkt": jkt }),
        tf_actor_type: "agent",
    };
    let signing_key = EncodingKey::from_ec_pem(&as_key.pem).unwrap();
    encode(&header, &claims, &signing_key).unwrap()
}

#[derive(Serialize)]
struct DpopClaims<'a> {
    htm: &'a str,
    htu: &'a str,
    iat: u64,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<&'a str>,
}

fn mint_dpop_proof(client: &ClientKey, htm: &str, htu: &str, ath: Option<&str>) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".into());
    header.jwk = Some(serde_json::from_value(serde_json::to_value(&client.jwk).unwrap()).unwrap());
    let claims = DpopClaims {
        htm,
        htu,
        iat: now(),
        jti: format!("jti-{}", now()),
        ath,
    };
    let signing_key = EncodingKey::from_ec_pem(&client.sign_pem).unwrap();
    encode(&header, &claims, &signing_key).unwrap()
}

fn make_bridge(as_key: &AsKey) -> GnapBridge {
    GnapBridge::new(GnapBridgeConfig {
        bridge_id: "tf-gnap".into(),
        trust_domain: "example.com".into(),
        issuer: "https://as.example.com".into(),
        allowed_algorithms: vec!["ES256".into()],
        jwks: Jwks {
            keys: vec![as_key.jwk.clone()],
        },
    })
}

fn make_grant_request(client: &ClientKey, actions: &[&str]) -> GnapGrantRequest {
    GnapGrantRequest {
        client: GnapClient {
            id: None,
            key: GnapKeyDescriptor {
                proof: "dpop".into(),
                jwk: client.jwk.clone(),
            },
        },
        access_token: GnapAccessTokenRequest {
            access: vec![GnapAccessRight::Object {
                actions: Some(actions.iter().map(|s| s.to_string()).collect()),
                locations: None,
                kind: None,
            }],
        },
    }
}

#[test]
fn build_grant_response_returns_a_stub() {
    let as_key = make_as_key();
    let client = make_client_key();
    let bridge = make_bridge(&as_key);
    let req = make_grant_request(&client, &["files.read"]);
    let resp = bridge
        .build_grant_response(
            &req,
            "stub-token",
            Some("https://as.example.com/continue/abc"),
        )
        .expect("build");
    assert_eq!(resp.access_token.value, "stub-token");
    assert_eq!(
        resp.continue_uri.as_deref(),
        Some("https://as.example.com/continue/abc")
    );
}

#[test]
fn rejects_grant_with_no_access() {
    let as_key = make_as_key();
    let client = make_client_key();
    let bridge = make_bridge(&as_key);
    let req = GnapGrantRequest {
        client: GnapClient {
            id: None,
            key: GnapKeyDescriptor {
                proof: "dpop".into(),
                jwk: client.jwk.clone(),
            },
        },
        access_token: GnapAccessTokenRequest { access: vec![] },
    };
    assert!(bridge.build_grant_response(&req, "x", None).is_err());
}

#[test]
fn verify_access_token_projects_bound_identity() {
    let as_key = make_as_key();
    let client = make_client_key();
    let bridge = make_bridge(&as_key);
    let token = mint_access_token(&as_key, "agent-007", &client.jkt);
    let req = make_grant_request(&client, &["files.read", "files.write"]);
    let grant = bridge.verify_access_token(&token, &req).expect("verify");
    assert_eq!(
        grant.identity.actor_id,
        "tf:actor:agent:example.com/agent-007"
    );
    assert_eq!(grant.client_key_thumbprint, client.jkt);
    assert_eq!(grant.capabilities.len(), 2);
    assert!(grant.identity.public_keys[0].public_key != "AA==");
}

#[test]
fn verify_rejects_token_with_wrong_jkt() {
    let as_key = make_as_key();
    let client = make_client_key();
    let bridge = make_bridge(&as_key);
    let wrong = "abc-not-the-real-jkt";
    let token = mint_access_token(&as_key, "agent-007", wrong);
    let req = make_grant_request(&client, &["files.read"]);
    assert!(bridge.verify_access_token(&token, &req).is_err());
}

#[test]
fn verify_dpop_proof_accepts_fresh_proof() {
    let as_key = make_as_key();
    let client = make_client_key();
    let bridge = make_bridge(&as_key);
    let proof = mint_dpop_proof(&client, "POST", "https://api.example.com/files", None);
    let result = bridge.verify_dpop_proof(
        &proof,
        "POST",
        "https://api.example.com/files",
        None,
        &client.jkt,
    );
    assert!(result.ok, "expected ok, got {:?}", result.reason);
}

#[test]
fn verify_dpop_rejects_jkt_mismatch() {
    let as_key = make_as_key();
    let client = make_client_key();
    let bridge = make_bridge(&as_key);
    let proof = mint_dpop_proof(&client, "GET", "https://api.example.com/x", None);
    let result = bridge.verify_dpop_proof(
        &proof,
        "GET",
        "https://api.example.com/x",
        None,
        "wrong-thumbprint",
    );
    assert!(!result.ok);
}

#[test]
fn verify_dpop_rejects_htm_or_htu_mismatch() {
    let as_key = make_as_key();
    let client = make_client_key();
    let bridge = make_bridge(&as_key);
    let proof = mint_dpop_proof(&client, "POST", "https://api.example.com/files", None);
    let wrong_method = bridge.verify_dpop_proof(
        &proof,
        "GET",
        "https://api.example.com/files",
        None,
        &client.jkt,
    );
    assert!(!wrong_method.ok);
    let wrong_url = bridge.verify_dpop_proof(
        &proof,
        "POST",
        "https://api.example.com/somewhere-else",
        None,
        &client.jkt,
    );
    assert!(!wrong_url.ok);
}

#[test]
fn verify_dpop_rejects_typ_other_than_dpop_jwt() {
    let as_key = make_as_key();
    let client = make_client_key();
    let bridge = make_bridge(&as_key);
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("JWT".into());
    header.jwk = Some(serde_json::from_value(serde_json::to_value(&client.jwk).unwrap()).unwrap());
    let claims = DpopClaims {
        htm: "GET",
        htu: "https://api.example.com",
        iat: now(),
        jti: "x".into(),
        ath: None,
    };
    let signing_key = EncodingKey::from_ec_pem(&client.sign_pem).unwrap();
    let proof = encode(&header, &claims, &signing_key).unwrap();
    let result =
        bridge.verify_dpop_proof(&proof, "GET", "https://api.example.com", None, &client.jkt);
    assert!(!result.ok);
    // suppress unused-import warnings for ed25519_dalek pieces.
    let _ = (
        Ed25519SigningKey::generate(&mut OsRng).to_pkcs8_pem(LineEnding::LF),
        P256SigningKey::random(&mut OsRng),
    );
}
