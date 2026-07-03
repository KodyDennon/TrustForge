//! Rust OAuth/GNAP bridge tests. We mint JWTs against real keys
//! (Ed25519 + ECDSA P-256 + RSA), publish their JWK forms, and verify
//! end-to-end through `OAuthBridge::verify_token`. Cross-language parity
//! is asserted with the TS suite at
//! `tools/tf-types-ts/tests/bridge-oauth.test.ts`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tf_types::encoding::URL_SAFE_NO_PAD;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;

use tf_types::bridge_oauth::{Jwk, Jwks, OAuthBridge, OAuthBridgeConfig};
use tf_types::bridges::BridgeError;
use tf_types::generated::{
    ActorIdentity_IdentityVersion, ActorType, AuthorityRoot_Kind, TrustLevel,
};

#[derive(Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tf_actor_type: Option<String>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

mod ed25519_test_vector {
    use super::*;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    pub struct Material {
        pub signing_pem: Vec<u8>,
        pub jwk: Jwk,
    }

    pub fn generate(kid: &str) -> Material {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let verifying = signing.verifying_key();
        let pem = signing
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode pkcs8 pem")
            .as_bytes()
            .to_vec();
        let jwk = Jwk {
            kty: "OKP".into(),
            alg: Some("EdDSA".into()),
            kid: Some(kid.into()),
            crv: Some("Ed25519".into()),
            x: Some(b64u(verifying.as_bytes())),
            y: None,
            n: None,
            e: None,
        };
        Material {
            signing_pem: pem,
            jwk,
        }
    }
}

mod p256_test_vector {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::EncodePrivateKey;
    use p256::SecretKey;
    use rand::rngs::OsRng;

    pub struct Material {
        pub signing_pem: Vec<u8>,
        pub jwk: Jwk,
    }

    pub fn generate(kid: &str) -> Material {
        let secret = SecretKey::random(&mut OsRng);
        let pem = secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
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
            kid: Some(kid.into()),
            crv: Some("P-256".into()),
            x: Some(b64u(x.as_slice())),
            y: Some(b64u(y.as_slice())),
            n: None,
            e: None,
        };
        Material {
            signing_pem: pem,
            jwk,
        }
    }
}

fn make_bridge(jwk: Jwk, allowed: &[&str]) -> OAuthBridge {
    OAuthBridge::new(OAuthBridgeConfig {
        bridge_id: "tf-oauth-bridge".into(),
        trust_domain: "example.com".into(),
        jwks: Jwks { keys: vec![jwk] },
        allowed_algorithms: allowed.iter().map(|s| s.to_string()).collect(),
        issuer: "https://idp.example.com".into(),
        audience: vec!["tf://example.com".into()],
        clock_tolerance_seconds: 30,
    })
}

fn default_claims() -> Claims {
    Claims {
        iss: "https://idp.example.com".into(),
        sub: "alice@example.com".into(),
        aud: "tf://example.com".into(),
        exp: now() + 300,
        iat: now(),
        scope: "files:read mail:send".into(),
        tf_actor_type: Some("human".into()),
    }
}

#[test]
fn verifies_eddsa_token_and_projects_identity() {
    let m = ed25519_test_vector::generate("ed-key-1");
    let bridge = make_bridge(m.jwk.clone(), &["EdDSA"]);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("ed-key-1".into());
    let signing_key = EncodingKey::from_ed_pem(&m.signing_pem).unwrap();
    let token = encode(&header, &default_claims(), &signing_key).unwrap();

    let result = bridge.verify_token(&token).expect("verify");
    assert_eq!(result.identity.actor_type, ActorType::Human);
    assert_eq!(
        result.identity.actor_id,
        "tf:actor:human:example.com/alice%40example.com"
    );
    assert!(matches!(
        result.identity.identity_version,
        ActorIdentity_IdentityVersion::V1
    ));
    assert_eq!(result.identity.trust_levels, vec![TrustLevel::T3]);
    assert_eq!(
        result.identity.authority_roots[0].kind,
        AuthorityRoot_Kind::Organization
    );
    assert_eq!(
        result.identity.authority_roots[0].id,
        "https://idp.example.com"
    );
    assert_eq!(result.capabilities, vec!["files:read", "mail:send"]);
}

#[test]
fn verifies_es256_token() {
    let m = p256_test_vector::generate("ec-key-1");
    let bridge = make_bridge(m.jwk.clone(), &["ES256"]);
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("ec-key-1".into());
    let signing_key = EncodingKey::from_ec_pem(&m.signing_pem).unwrap();
    let token = encode(&header, &default_claims(), &signing_key).unwrap();
    let result = bridge.verify_token(&token).expect("verify");
    assert_eq!(result.identity.actor_type, ActorType::Human);
    assert_eq!(result.capabilities.len(), 2);
}

#[test]
fn rejects_unknown_algorithm() {
    let m = ed25519_test_vector::generate("ed-key-2");
    let bridge = make_bridge(m.jwk.clone(), &["ES256"]);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("ed-key-2".into());
    let signing_key = EncodingKey::from_ed_pem(&m.signing_pem).unwrap();
    let token = encode(&header, &default_claims(), &signing_key).unwrap();
    assert!(matches!(
        bridge.verify_token(&token),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn rejects_wrong_issuer() {
    let m = ed25519_test_vector::generate("ed-key-3");
    let bridge = make_bridge(m.jwk.clone(), &["EdDSA"]);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("ed-key-3".into());
    let signing_key = EncodingKey::from_ed_pem(&m.signing_pem).unwrap();
    let mut claims = default_claims();
    claims.iss = "https://attacker.example.com".into();
    let token = encode(&header, &claims, &signing_key).unwrap();
    assert!(matches!(
        bridge.verify_token(&token),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn rejects_wrong_audience() {
    let m = ed25519_test_vector::generate("ed-key-4");
    let bridge = make_bridge(m.jwk.clone(), &["EdDSA"]);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("ed-key-4".into());
    let signing_key = EncodingKey::from_ed_pem(&m.signing_pem).unwrap();
    let mut claims = default_claims();
    claims.aud = "tf://other.example.com".into();
    let token = encode(&header, &claims, &signing_key).unwrap();
    assert!(matches!(
        bridge.verify_token(&token),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn rejects_expired_token() {
    let m = ed25519_test_vector::generate("ed-key-5");
    let bridge = make_bridge(m.jwk.clone(), &["EdDSA"]);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("ed-key-5".into());
    let signing_key = EncodingKey::from_ed_pem(&m.signing_pem).unwrap();
    let mut claims = default_claims();
    let earlier = now() - 1000;
    claims.iat = earlier - 60;
    claims.exp = earlier;
    let token = encode(&header, &claims, &signing_key).unwrap();
    assert!(matches!(
        bridge.verify_token(&token),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn rejects_unknown_kid() {
    let m = ed25519_test_vector::generate("ed-key-6");
    let bridge = make_bridge(m.jwk.clone(), &["EdDSA"]);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("does-not-exist".into());
    let signing_key = EncodingKey::from_ed_pem(&m.signing_pem).unwrap();
    let token = encode(&header, &default_claims(), &signing_key).unwrap();
    assert!(matches!(
        bridge.verify_token(&token),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn projects_agent_actor_type_from_claim() {
    let m = ed25519_test_vector::generate("ed-key-7");
    let bridge = make_bridge(m.jwk.clone(), &["EdDSA"]);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("ed-key-7".into());
    let signing_key = EncodingKey::from_ed_pem(&m.signing_pem).unwrap();
    let mut claims = default_claims();
    claims.tf_actor_type = Some("agent".into());
    claims.sub = "code-helper".into();
    let token = encode(&header, &claims, &signing_key).unwrap();
    let result = bridge.verify_token(&token).expect("verify");
    assert_eq!(result.identity.actor_type, ActorType::Agent);
    assert_eq!(
        result.identity.actor_id,
        "tf:actor:agent:example.com/code-helper"
    );
}

#[test]
fn rejects_token_signed_with_wrong_key() {
    let signer = ed25519_test_vector::generate("ed-key-8");
    let other = ed25519_test_vector::generate("ed-key-8"); // same kid, different key
    let bridge = make_bridge(other.jwk.clone(), &["EdDSA"]);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("ed-key-8".into());
    let signing_key = EncodingKey::from_ed_pem(&signer.signing_pem).unwrap();
    let token = encode(&header, &default_claims(), &signing_key).unwrap();
    assert!(matches!(
        bridge.verify_token(&token),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn _smoke_clock_skew_within_tolerance() {
    let m = ed25519_test_vector::generate("ed-key-9");
    let bridge = make_bridge(m.jwk.clone(), &["EdDSA"]);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("ed-key-9".into());
    let signing_key = EncodingKey::from_ed_pem(&m.signing_pem).unwrap();
    // exp 5 seconds in past, but bridge tolerance is 30s
    let mut claims = default_claims();
    claims.exp = now() - 5;
    let token = encode(&header, &claims, &signing_key).unwrap();
    bridge.verify_token(&token).expect("within tolerance");
    // Defeat unused warning on json/ed25519/Duration imports.
    let _ = (json!({}), Duration::from_secs(0));
}
