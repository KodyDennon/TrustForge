//! Tests for the Azure JWT bridge — uses `wiremock` for the JWKS,
//! signs Azure-shaped tokens with a freshly generated RSA key, and
//! verifies them through the bridge.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use sha2::Sha256;
use tf_bridge_azure::{
    azure_role_assignment_to_capabilities, managed_identity_to_actor, verify_azure_jwt,
    AzureBridgeError, AzureIdentity, AzureJwtVerifier,
};
use tf_types::generated::{ActorType, RiskClass, TrustLevel};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sign_token(
    issuer: &str,
    audience: &str,
    tid: &str,
    oid: &str,
    appid: Option<&str>,
    upn: Option<&str>,
    idtyp: Option<&str>,
    kid: &str,
) -> (String, serde_json::Value) {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let public_key = RsaPublicKey::from(&private_key);
    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();
    let n_b64 = b64url(&n_bytes);
    let e_b64 = b64url(&e_bytes);

    let header = json!({"alg":"RS256","typ":"JWT","kid":kid});
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims = json!({
        "iss": issuer,
        "sub": format!("sub-{oid}"),
        "oid": oid,
        "tid": tid,
        "aud": audience,
        "exp": now + 3600,
        "iat": now,
    });
    if let Some(a) = appid {
        claims["appid"] = json!(a);
    }
    if let Some(u) = upn {
        claims["upn"] = json!(u);
    }
    if let Some(t) = idtyp {
        claims["idtyp"] = json!(t);
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
    (jwt, jwks)
}

#[tokio::test]
async fn verify_azure_jwt_managed_identity_success() {
    let tenant_id = "11111111-2222-3333-4444-555555555555";
    let issuer = format!("https://login.microsoftonline.com/{}/v2.0", tenant_id);
    let audience = "api://my-app";
    let (jwt, jwks) = sign_token(
        &issuer,
        audience,
        tenant_id,
        "managed-identity-oid",
        Some("app-id-1"),
        None,
        Some("app"),
        "k1",
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{tenant_id}/discovery/v2.0/keys")))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks.clone()))
        .mount(&server)
        .await;

    let jwks_url = format!("{}/{}/discovery/v2.0/keys", server.uri(), tenant_id);
    let verifier = AzureJwtVerifier::new(jwks_url, &issuer, vec![audience.to_string()]);
    let identity = verify_azure_jwt(&verifier, &jwt).await.unwrap();
    assert_eq!(identity.tid.as_deref(), Some(tenant_id));
    assert_eq!(identity.oid.as_deref(), Some("managed-identity-oid"));
    assert_eq!(identity.appid.as_deref(), Some("app-id-1"));
    assert_eq!(identity.idtyp.as_deref(), Some("app"));
}

#[tokio::test]
async fn verify_azure_jwt_rejects_wrong_issuer() {
    let tenant_id = "abc";
    let issuer = format!("https://login.microsoftonline.com/{}/v2.0", tenant_id);
    let audience = "api://x";
    let (jwt, jwks) = sign_token(
        &issuer, audience, tenant_id, "oid-1", None, None, None, "k1",
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{tenant_id}/discovery/v2.0/keys")))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .mount(&server)
        .await;

    let jwks_url = format!("{}/{}/discovery/v2.0/keys", server.uri(), tenant_id);
    let verifier = AzureJwtVerifier::new(
        jwks_url,
        "https://login.microsoftonline.com/different-tenant/v2.0",
        vec![audience.to_string()],
    );
    let err = verify_azure_jwt(&verifier, &jwt).await.unwrap_err();
    assert!(matches!(err, AzureBridgeError::Rejected(_)));
}

#[tokio::test]
async fn verify_azure_jwt_rejects_jwks_404() {
    let tenant_id = "abc";
    let issuer = format!("https://login.microsoftonline.com/{}/v2.0", tenant_id);
    let audience = "api://x";
    let (jwt, _jwks) = sign_token(
        &issuer, audience, tenant_id, "oid-1", None, None, None, "k1",
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{tenant_id}/discovery/v2.0/keys")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let jwks_url = format!("{}/{}/discovery/v2.0/keys", server.uri(), tenant_id);
    let verifier = AzureJwtVerifier::new(jwks_url, &issuer, vec![audience.to_string()]);
    let err = verify_azure_jwt(&verifier, &jwt).await.unwrap_err();
    assert!(matches!(err, AzureBridgeError::Jwks(_)));
}

#[tokio::test]
async fn verify_azure_jwt_rejects_empty_token() {
    let verifier = AzureJwtVerifier::for_tenant("common", vec!["api://x".to_string()]);
    let err = verify_azure_jwt(&verifier, "").await.unwrap_err();
    assert!(matches!(err, AzureBridgeError::InvalidInput(_)));
}

#[test]
fn managed_identity_to_actor_uses_oid_and_tenant() {
    let claims = AzureIdentity {
        iss: "https://login.microsoftonline.com/tid-1/v2.0".into(),
        sub: "sub-1".into(),
        oid: Some("oid-1".into()),
        tid: Some("tid-1".into()),
        aud: "api://x".into(),
        appid: Some("app-1".into()),
        upn: None,
        email: None,
        roles: Vec::new(),
        idtyp: Some("app".into()),
        exp: 9999999999,
        iat: 0,
        raw: serde_json::Value::Null,
    };
    let actor = managed_identity_to_actor(&claims).unwrap();
    assert_eq!(
        actor.actor_id,
        "tf:actor:service:login.microsoftonline.com/tid-1/oid-1"
    );
    assert_eq!(actor.actor_type, ActorType::Service);
    assert_eq!(actor.trust_levels, vec![TrustLevel::T3]);
    assert_eq!(actor.authority_roots[0].id, "azure-tenant:tid-1");
}

#[test]
fn managed_identity_to_actor_rejects_missing_tid() {
    let claims = AzureIdentity {
        iss: "x".into(),
        sub: "s".into(),
        oid: Some("o".into()),
        tid: None,
        aud: "x".into(),
        appid: None,
        upn: None,
        email: None,
        roles: Vec::new(),
        idtyp: None,
        exp: 0,
        iat: 0,
        raw: serde_json::Value::Null,
    };
    let err = managed_identity_to_actor(&claims).unwrap_err();
    assert!(matches!(err, AzureBridgeError::InvalidInput(_)));
}

#[test]
fn role_translation_blob_data_contributor_has_writes() {
    let caps = azure_role_assignment_to_capabilities("Storage Blob Data Contributor");
    assert_eq!(caps.len(), 4);
    let names: Vec<_> = caps.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"azure.storage.write_blob"));
    assert!(names.contains(&"azure.storage.delete_blob"));
}

#[test]
fn role_translation_keyvault_admin_is_max_risk() {
    let caps = azure_role_assignment_to_capabilities("Key Vault Administrator");
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].risk, RiskClass::R5);
}
