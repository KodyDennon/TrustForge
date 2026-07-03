#![allow(unused_imports)]
//! Rust WebAuthn full-attestation tests. We mint synthetic attestations
//! (CBOR-encoded attestationObject + clientDataJSON) signed with real
//! noble-equivalent primitives (p256 / ed25519-dalek) and round-trip them
//! through `verify_attestation`. Cross-language parity is asserted with
//! `tools/tf-types-ts/tests/webauthn-attestation.test.ts`.

use tf_types::encoding::URL_SAFE_NO_PAD;
use tf_types::cbor::Value;
use ed25519_dalek::Signer as _;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::signature::Signer as P256Signer;
use p256::ecdsa::Signature as P256Signature;
use p256::ecdsa::SigningKey as P256SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use tf_types::bridges::BridgeError;
use tf_types::webauthn_attestation::{
    decode_attestation_object, parse_authenticator_data, parse_client_data, parse_cose_public_key,
    verify_attestation, AttestationFormat, CoseAlgorithm, VerifyAttestationOptions,
};

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

fn b64u(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn challenge() -> String {
    b64u(&[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10])
}

fn cbor_encode(v: &Value) -> Vec<u8> {
    tf_types::cbor::encode(v).unwrap()
}

fn build_client_data(challenge: &str, origin: &str) -> Vec<u8> {
    serde_json::json!({
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": origin,
    })
    .to_string()
    .into_bytes()
}

fn cose_p256(x: &[u8], y: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())), // kty=EC2
        (Value::Integer(3.into()), Value::Integer((-7).into())), // alg=ES256
        (Value::Integer((-1).into()), Value::Integer(1.into())), // crv=P-256
        (Value::Integer((-2).into()), Value::Bytes(x.to_vec())),
        (Value::Integer((-3).into()), Value::Bytes(y.to_vec())),
    ])
}

fn cose_ed25519(x: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(1.into())), // kty=OKP
        (Value::Integer(3.into()), Value::Integer((-8).into())), // alg=EdDSA
        (Value::Integer((-1).into()), Value::Integer(6.into())), // crv=Ed25519
        (Value::Integer((-2).into()), Value::Bytes(x.to_vec())),
    ])
}

fn build_auth_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    aaguid: &[u8; 16],
    cred_id: &[u8],
    cose: &Value,
) -> Vec<u8> {
    let rp_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    let mut out = Vec::new();
    out.extend_from_slice(&rp_hash);
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    out.extend_from_slice(aaguid);
    out.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    out.extend_from_slice(cred_id);
    out.extend_from_slice(&cbor_encode(cose));
    out
}

fn build_attestation_object(fmt: &str, att_stmt: Value, auth_data: &[u8]) -> Vec<u8> {
    let v = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text(fmt.into())),
        (Value::Text("attStmt".into()), att_stmt),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    cbor_encode(&v)
}

fn p256_keypair() -> (P256SigningKey, [u8; 32], [u8; 32]) {
    let signing = P256SigningKey::random(&mut OsRng);
    let pubk = signing.verifying_key().to_encoded_point(false);
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(pubk.x().unwrap());
    y.copy_from_slice(pubk.y().unwrap());
    (signing, x, y)
}

fn ed25519_keypair() -> (Ed25519SigningKey, [u8; 32]) {
    let signing = Ed25519SigningKey::generate(&mut OsRng);
    let public = signing.verifying_key().to_bytes();
    (signing, public)
}

#[test]
fn parses_authenticator_data_with_credential() {
    let (_, x, y) = p256_keypair();
    let cose = cose_p256(&x, &y);
    let aaguid = [0xab; 16];
    let cred_id = [10, 20, 30, 40, 50, 60, 70, 80];
    let auth = build_auth_data(RP_ID, 0x41, 7, &aaguid, &cred_id, &cose);
    let parsed = parse_authenticator_data(&auth).expect("parse");
    assert_eq!(parsed.flags, 0x41);
    assert_eq!(parsed.sign_count, 7);
    assert_eq!(parsed.aaguid.as_deref(), Some(&aaguid[..]));
    assert_eq!(parsed.credential_id.as_deref(), Some(&cred_id[..]));
    let cose = parsed.credential_public_key.unwrap();
    assert_eq!(cose.kty, 2);
    assert_eq!(cose.alg, Some(CoseAlgorithm::Es256));
}

#[test]
fn parses_ed25519_cose() {
    let (_, x) = ed25519_keypair();
    let cose = cose_ed25519(&x);
    let bytes = cbor_encode(&cose);
    let key = parse_cose_public_key(&bytes).expect("cose");
    assert_eq!(key.alg, Some(CoseAlgorithm::EdDsa));
    assert_eq!(key.kty, 1);
}

#[test]
fn decode_attestation_splits_fields() {
    let (_, x, y) = p256_keypair();
    let cose = cose_p256(&x, &y);
    let auth = build_auth_data(RP_ID, 0x41, 0, &[0xab; 16], &[1, 2, 3], &cose);
    let att = build_attestation_object("none", Value::Map(vec![]), &auth);
    let decoded = decode_attestation_object(&att).expect("decode");
    assert!(matches!(decoded.fmt, AttestationFormat::None_));
    assert_eq!(decoded.auth_data, auth);
}

#[test]
fn parse_client_data_requires_fields() {
    let cd = build_client_data(&challenge(), ORIGIN);
    let parsed = parse_client_data(&cd).expect("parse");
    assert_eq!(parsed.r#type, "webauthn.create");
}

#[test]
fn verifies_fmt_none_attestation() {
    let (_, x, y) = p256_keypair();
    let cose = cose_p256(&x, &y);
    let auth = build_auth_data(RP_ID, 0x41, 0, &[0xab; 16], &[10, 20, 30], &cose);
    let att = build_attestation_object("none", Value::Map(vec![]), &auth);
    let cd = build_client_data(&challenge(), ORIGIN);
    let opts = VerifyAttestationOptions {
        rp_id: RP_ID.into(),
        expected_origin: ORIGIN.into(),
        expected_challenge: challenge(),
        allowed_algorithms: None,
        require_attestation_signature: false,
    };
    let result = verify_attestation(&att, &cd, &opts).expect("verify");
    assert_eq!(result.algorithm, CoseAlgorithm::Es256);
    assert!(matches!(result.format, AttestationFormat::None_));
}

#[test]
fn verifies_packed_self_attestation_es256() {
    let (signing, x, y) = p256_keypair();
    let cose = cose_p256(&x, &y);
    let auth = build_auth_data(RP_ID, 0x41, 1, &[0xab; 16], &[10, 20, 30], &cose);
    let cd = build_client_data(&challenge(), ORIGIN);
    let cd_hash: [u8; 32] = Sha256::digest(&cd).into();
    let mut signed = auth.clone();
    signed.extend_from_slice(&cd_hash);
    let sig: P256Signature = signing.sign(&signed);
    let sig_bytes = sig.to_der().as_bytes().to_vec();
    let att_stmt = Value::Map(vec![
        (Value::Text("alg".into()), Value::Integer((-7).into())),
        (Value::Text("sig".into()), Value::Bytes(sig_bytes)),
    ]);
    let att = build_attestation_object("packed", att_stmt, &auth);
    let opts = VerifyAttestationOptions {
        rp_id: RP_ID.into(),
        expected_origin: ORIGIN.into(),
        expected_challenge: challenge(),
        allowed_algorithms: None,
        require_attestation_signature: false,
    };
    let result = verify_attestation(&att, &cd, &opts).expect("verify");
    assert!(matches!(result.format, AttestationFormat::Packed));
}

#[test]
fn verifies_packed_self_attestation_ed25519() {
    let (signing, x) = ed25519_keypair();
    let cose = cose_ed25519(&x);
    let auth = build_auth_data(RP_ID, 0x41, 1, &[0xab; 16], &[10, 20, 30], &cose);
    let cd = build_client_data(&challenge(), ORIGIN);
    let cd_hash: [u8; 32] = Sha256::digest(&cd).into();
    let mut signed = auth.clone();
    signed.extend_from_slice(&cd_hash);
    let sig = signing.sign(&signed).to_bytes().to_vec();
    let att_stmt = Value::Map(vec![
        (Value::Text("alg".into()), Value::Integer((-8).into())),
        (Value::Text("sig".into()), Value::Bytes(sig)),
    ]);
    let att = build_attestation_object("packed", att_stmt, &auth);
    let opts = VerifyAttestationOptions {
        rp_id: RP_ID.into(),
        expected_origin: ORIGIN.into(),
        expected_challenge: challenge(),
        allowed_algorithms: None,
        require_attestation_signature: false,
    };
    let result = verify_attestation(&att, &cd, &opts).expect("verify");
    assert_eq!(result.algorithm, CoseAlgorithm::EdDsa);
}

#[test]
fn rejects_bad_challenge() {
    let (_, x, y) = p256_keypair();
    let cose = cose_p256(&x, &y);
    let auth = build_auth_data(RP_ID, 0x41, 0, &[0xab; 16], &[10, 20, 30], &cose);
    let att = build_attestation_object("none", Value::Map(vec![]), &auth);
    let cd = build_client_data("DIFFERENT", ORIGIN);
    let opts = VerifyAttestationOptions {
        rp_id: RP_ID.into(),
        expected_origin: ORIGIN.into(),
        expected_challenge: challenge(),
        allowed_algorithms: None,
        require_attestation_signature: false,
    };
    assert!(matches!(
        verify_attestation(&att, &cd, &opts),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn rejects_mismatched_rp_id_hash() {
    let (_, x, y) = p256_keypair();
    let cose = cose_p256(&x, &y);
    let auth = build_auth_data(
        "other.example.com",
        0x41,
        0,
        &[0xab; 16],
        &[10, 20, 30],
        &cose,
    );
    let att = build_attestation_object("none", Value::Map(vec![]), &auth);
    let cd = build_client_data(&challenge(), ORIGIN);
    let opts = VerifyAttestationOptions {
        rp_id: RP_ID.into(),
        expected_origin: ORIGIN.into(),
        expected_challenge: challenge(),
        allowed_algorithms: None,
        require_attestation_signature: false,
    };
    assert!(matches!(
        verify_attestation(&att, &cd, &opts),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn rejects_forged_packed_signature() {
    let (signing_real, x, y) = p256_keypair();
    let (signing_other, _, _) = p256_keypair();
    let _ = signing_real; // we sign with the imposter
    let cose = cose_p256(&x, &y);
    let auth = build_auth_data(RP_ID, 0x41, 0, &[0xab; 16], &[10, 20, 30], &cose);
    let cd = build_client_data(&challenge(), ORIGIN);
    let cd_hash: [u8; 32] = Sha256::digest(&cd).into();
    let mut signed = auth.clone();
    signed.extend_from_slice(&cd_hash);
    let sig: P256Signature = signing_other.sign(&signed);
    let att_stmt = Value::Map(vec![
        (Value::Text("alg".into()), Value::Integer((-7).into())),
        (
            Value::Text("sig".into()),
            Value::Bytes(sig.to_der().as_bytes().to_vec()),
        ),
    ]);
    let att = build_attestation_object("packed", att_stmt, &auth);
    let opts = VerifyAttestationOptions {
        rp_id: RP_ID.into(),
        expected_origin: ORIGIN.into(),
        expected_challenge: challenge(),
        allowed_algorithms: None,
        require_attestation_signature: false,
    };
    assert!(matches!(
        verify_attestation(&att, &cd, &opts),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn rejects_missing_user_present_flag() {
    let (_, x, y) = p256_keypair();
    let cose = cose_p256(&x, &y);
    let auth = build_auth_data(RP_ID, 0x40, 0, &[0xab; 16], &[10, 20, 30], &cose);
    let att = build_attestation_object("none", Value::Map(vec![]), &auth);
    let cd = build_client_data(&challenge(), ORIGIN);
    let opts = VerifyAttestationOptions {
        rp_id: RP_ID.into(),
        expected_origin: ORIGIN.into(),
        expected_challenge: challenge(),
        allowed_algorithms: None,
        require_attestation_signature: false,
    };
    assert!(matches!(
        verify_attestation(&att, &cd, &opts),
        Err(BridgeError::Rejected(_))
    ));
}
