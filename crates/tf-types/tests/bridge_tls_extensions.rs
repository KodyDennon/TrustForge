//! Tests for the TLS bridge extensions:
//!   - OCSP query (good / revoked / unknown) via a fixture-backed `OcspFetcher`,
//!   - CRL parsing + lookup with a 100-entry list,
//!   - RFC-5705-style exporter binding against a hand-computed reference vector,
//!   - post-handshake re-auth Ed25519 challenge / response.
//!
//! No network IO and no platform-trust-store dependencies — every fixture is
//! constructed in this file or pulled from `conformance/tls-exporter-vectors.yaml`.

use std::collections::HashMap;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
};
use time::{Duration, OffsetDateTime};

use tf_types::bridge_tls::{
    CrlCheck, ExporterBinding, OcspCheck, OcspFetcher, OcspStatus, PostHandshakeReauth, X509Cert,
};
use tf_types::bridges::BridgeError;
use tf_types::crypto::Ed25519Signer;

// ---------------------------------------------------------------------------
// Helpers — make a self-signed CA leaf pair and synthesise OCSP DER blobs.
// ---------------------------------------------------------------------------

struct CaMaterial {
    cert: rcgen::Certificate,
    key_pair: KeyPair,
}

fn make_ca() -> CaMaterial {
    let mut params = CertificateParams::new(vec!["TF Test Root CA".into()]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "TF Test Root CA");
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
    params.not_after = OffsetDateTime::now_utc() + Duration::hours(1);
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    CaMaterial { cert, key_pair }
}

fn make_leaf(parent: &CaMaterial, cn: &str, serial: u64) -> X509Cert {
    let mut params = CertificateParams::new(vec![cn.into()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.distinguished_name.push(DnType::CommonName, cn);
    params.serial_number = Some(SerialNumber::from(serial));
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::hours(1);
    let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params
        .signed_by(&kp, &parent.cert, &parent.key_pair)
        .unwrap();
    X509Cert::from_der(cert.der()).unwrap()
}

fn ca_as_x509cert(ca: &CaMaterial) -> X509Cert {
    X509Cert::from_der(ca.cert.der()).unwrap()
}

// ---------------------------------------------------------------------------
// Minimal OCSP DER builder. Only emits the shape `OcspCheck::parse_response`
// actually walks: `OCSPResponse(responseStatus=0, responseBytes(BasicOCSPResponse(
// tbsResponseData(producedAt, responses=[SingleResponse(certID, certStatus,
// thisUpdate, nextUpdate?)]), AlgorithmIdentifier, BIT STRING)))`.
// We use only DER primitive encoders; signatures are stubbed since the bridge
// (mirroring the TS counterpart) does not enforce responder-signature trust at
// this layer — that is left to a higher-level resolver.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum SyntheticStatus {
    Good,
    Revoked,
    Unknown,
}

fn build_ocsp_der(
    status: SyntheticStatus,
    this_update: OffsetDateTime,
    next_update: Option<OffsetDateTime>,
) -> Vec<u8> {
    let mut single_response = Vec::new();
    // certID SEQUENCE { hashAlg AlgorithmIdentifier, issuerNameHash OCTET, issuerKeyHash OCTET, serial INTEGER }
    let cert_id = der_sequence(&[
        // AlgorithmIdentifier with OID 1.3.14.3.2.26 (sha-1)
        der_sequence(&[der_oid(&[1, 3, 14, 3, 2, 26]), der_null()]),
        // issuerNameHash: 20 zero bytes
        der_octet_string(&[0u8; 20]),
        // issuerKeyHash: 20 zero bytes
        der_octet_string(&[0u8; 20]),
        // serialNumber: positive INTEGER 1
        der_integer(&[0x01]),
    ]);
    single_response.extend_from_slice(&cert_id);

    // certStatus CHOICE
    let cs = match status {
        SyntheticStatus::Good => {
            // [0] IMPLICIT NULL: tag 0x80, length 0
            vec![0x80, 0x00]
        }
        SyntheticStatus::Revoked => {
            // [1] IMPLICIT RevokedInfo SEQUENCE { revocationTime GeneralizedTime, ... }
            let rev_time = der_generalized_time(this_update);
            // RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime }
            // With IMPLICIT [1] we replace SEQUENCE tag (0x30) with [1] constructed (0xa1).
            let body_inner = rev_time;
            let mut body = Vec::new();
            der_write_tlv(&mut body, 0xa1, &body_inner);
            body
        }
        SyntheticStatus::Unknown => {
            // [2] IMPLICIT NULL: tag 0x82, length 0
            vec![0x82, 0x00]
        }
    };
    single_response.extend_from_slice(&cs);

    // thisUpdate GeneralizedTime
    single_response.extend_from_slice(&der_generalized_time(this_update));
    // nextUpdate optional [0] EXPLICIT GeneralizedTime
    if let Some(next) = next_update {
        let inner = der_generalized_time(next);
        let mut explicit = Vec::new();
        der_write_tlv(&mut explicit, 0xa0, &inner);
        single_response.extend_from_slice(&explicit);
    }

    let single_response_seq = der_sequence(&[single_response]);
    let responses_seq = der_sequence(&[single_response_seq]);

    // tbsResponseData SEQUENCE
    let tbs_response_data = der_sequence(&[
        // responderID [1] EXPLICIT Name — we use a minimal empty Name (SEQUENCE {})
        {
            let name = der_sequence(&[]);
            let mut out = Vec::new();
            der_write_tlv(&mut out, 0xa1, &name);
            out
        },
        // producedAt GeneralizedTime
        der_generalized_time(this_update),
        // responses
        responses_seq,
    ]);

    // signatureAlgorithm AlgorithmIdentifier
    let sig_alg = der_sequence(&[der_oid(&[1, 2, 840, 10045, 4, 3, 2]), der_null()]);

    // signature BIT STRING (zero-length, unused — bridge currently does not
    // verify responder signature; mirrors the TS surface)
    let signature = vec![0x03, 0x01, 0x00];

    // BasicOCSPResponse SEQUENCE
    let basic_ocsp_response = der_sequence(&[tbs_response_data, sig_alg, signature]);

    // ResponseBytes SEQUENCE { responseType OID, response OCTET STRING }
    let response_bytes_inner = der_sequence(&[
        der_oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1]), // id-pkix-ocsp-basic
        der_octet_string(&basic_ocsp_response),
    ]);
    // [0] EXPLICIT ResponseBytes
    let mut explicit_response_bytes = Vec::new();
    der_write_tlv(&mut explicit_response_bytes, 0xa0, &response_bytes_inner);

    // OCSPResponse SEQUENCE { responseStatus ENUMERATED, responseBytes [0] OPTIONAL }
    let response_status = vec![0x0a, 0x01, 0x00]; // ENUMERATED 0 (successful)

    der_sequence(&[response_status, explicit_response_bytes])
}

// ---- DER primitive helpers -------------------------------------------------

fn der_write_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

fn der_write_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    der_write_length(out, content.len());
    out.extend_from_slice(content);
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    for p in parts {
        content.extend_from_slice(p);
    }
    let mut out = Vec::new();
    der_write_tlv(&mut out, 0x30, &content);
    out
}

fn der_oid(arcs: &[u32]) -> Vec<u8> {
    assert!(arcs.len() >= 2);
    let mut content = Vec::new();
    content.push((arcs[0] * 40 + arcs[1]) as u8);
    for &arc in &arcs[2..] {
        encode_base128(&mut content, arc);
    }
    let mut out = Vec::new();
    der_write_tlv(&mut out, 0x06, &content);
    out
}

fn encode_base128(out: &mut Vec<u8>, mut v: u32) {
    let mut bytes = Vec::new();
    bytes.push((v & 0x7f) as u8);
    v >>= 7;
    while v > 0 {
        bytes.push(((v & 0x7f) as u8) | 0x80);
        v >>= 7;
    }
    bytes.reverse();
    out.extend_from_slice(&bytes);
}

fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    der_write_tlv(&mut out, 0x04, bytes);
    out
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    der_write_tlv(&mut out, 0x02, bytes);
    out
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn der_generalized_time(t: OffsetDateTime) -> Vec<u8> {
    // Format YYYYMMDDHHMMSSZ
    let s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    let mut out = Vec::new();
    der_write_tlv(&mut out, 0x18, s.as_bytes());
    out
}

// ---- Test fetcher ----------------------------------------------------------

struct FixtureFetcher {
    by_url: HashMap<String, Vec<u8>>,
}

impl OcspFetcher for FixtureFetcher {
    fn fetch(
        &self,
        _cert: &X509Cert,
        _issuer: &X509Cert,
        ocsp_url: &str,
    ) -> Result<Vec<u8>, BridgeError> {
        self.by_url
            .get(ocsp_url)
            .cloned()
            .ok_or_else(|| BridgeError::Internal(format!("no OCSP fixture for {}", ocsp_url)))
    }
}

// ---------------------------------------------------------------------------
// OCSP tests
// ---------------------------------------------------------------------------

#[test]
fn ocsp_good_response_yields_good() {
    let ca = make_ca();
    let leaf = make_leaf(&ca, "tf-leaf", 1);
    let issuer = ca_as_x509cert(&ca);

    let now = OffsetDateTime::now_utc();
    let der = build_ocsp_der(
        SyntheticStatus::Good,
        now - Duration::minutes(1),
        Some(now + Duration::hours(1)),
    );
    let mut by_url = HashMap::new();
    by_url.insert("http://ocsp.example/".into(), der);
    let fetcher = FixtureFetcher { by_url };

    let status = OcspCheck::query(
        &leaf,
        &issuer,
        &fetcher,
        "http://ocsp.example/",
        now.unix_timestamp(),
    )
    .expect("OCSP query");
    assert_eq!(status, OcspStatus::Good);
}

#[test]
fn ocsp_revoked_response_yields_revoked() {
    let ca = make_ca();
    let leaf = make_leaf(&ca, "tf-leaf-revoked", 2);
    let issuer = ca_as_x509cert(&ca);

    let now = OffsetDateTime::now_utc();
    let der = build_ocsp_der(
        SyntheticStatus::Revoked,
        now - Duration::minutes(1),
        Some(now + Duration::hours(1)),
    );
    let mut by_url = HashMap::new();
    by_url.insert("http://ocsp.example/".into(), der);
    let fetcher = FixtureFetcher { by_url };

    let status = OcspCheck::query(
        &leaf,
        &issuer,
        &fetcher,
        "http://ocsp.example/",
        now.unix_timestamp(),
    )
    .expect("OCSP query");
    assert_eq!(status, OcspStatus::Revoked);
}

#[test]
fn ocsp_unknown_response_yields_unknown() {
    let ca = make_ca();
    let leaf = make_leaf(&ca, "tf-leaf-unknown", 3);
    let issuer = ca_as_x509cert(&ca);

    let now = OffsetDateTime::now_utc();
    let der = build_ocsp_der(
        SyntheticStatus::Unknown,
        now - Duration::minutes(1),
        Some(now + Duration::hours(1)),
    );
    let mut by_url = HashMap::new();
    by_url.insert("http://ocsp.example/".into(), der);
    let fetcher = FixtureFetcher { by_url };

    let status = OcspCheck::query(
        &leaf,
        &issuer,
        &fetcher,
        "http://ocsp.example/",
        now.unix_timestamp(),
    )
    .expect("OCSP query");
    assert_eq!(status, OcspStatus::Unknown);
}

#[test]
fn ocsp_stale_response_is_rejected() {
    let ca = make_ca();
    let leaf = make_leaf(&ca, "tf-leaf-stale", 4);
    let issuer = ca_as_x509cert(&ca);

    let past = OffsetDateTime::now_utc() - Duration::days(30);
    let der = build_ocsp_der(
        SyntheticStatus::Good,
        past - Duration::minutes(1),
        Some(past + Duration::hours(1)),
    );
    let mut by_url = HashMap::new();
    by_url.insert("http://ocsp.example/".into(), der);
    let fetcher = FixtureFetcher { by_url };

    // Now is way after nextUpdate → must be rejected.
    let res = OcspCheck::query(
        &leaf,
        &issuer,
        &fetcher,
        "http://ocsp.example/",
        OffsetDateTime::now_utc().unix_timestamp(),
    );
    assert!(
        matches!(res, Err(BridgeError::Rejected(_))),
        "got {:?}",
        res
    );
}

// ---------------------------------------------------------------------------
// CRL tests
// ---------------------------------------------------------------------------

#[test]
fn crl_with_100_entries_supports_lookup() {
    let ca = make_ca();
    let mut revoked_certs = Vec::new();
    for i in 1..=100u64 {
        revoked_certs.push(RevokedCertParams {
            serial_number: SerialNumber::from(i),
            revocation_time: OffsetDateTime::now_utc() - Duration::minutes(5),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        });
    }
    let crl_params = CertificateRevocationListParams {
        this_update: OffsetDateTime::now_utc() - Duration::minutes(1),
        next_update: OffsetDateTime::now_utc() + Duration::hours(1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl = crl_params
        .signed_by(&ca.cert, &ca.key_pair)
        .expect("sign CRL");
    let crl_bytes: &[u8] = crl.der().as_ref();

    let index = CrlCheck::load(crl_bytes).expect("load CRL");
    assert_eq!(index.len(), 100);

    // Hit and miss lookups using the canonical big-endian serial form.
    for i in 1..=100u64 {
        let mut serial_be = i.to_be_bytes().to_vec();
        while serial_be.len() > 1 && serial_be[0] == 0x00 {
            serial_be.remove(0);
        }
        let entry = index
            .is_revoked(&serial_be)
            .unwrap_or_else(|| panic!("serial {} should be revoked", i));
        assert_eq!(entry.reason_code, Some(1)); // 1 = keyCompromise
    }
    // Serial 0xDEADBEEF is not on the list.
    let missing = index.is_revoked(&[0xde, 0xad, 0xbe, 0xef]);
    assert!(missing.is_none());
}

// ---------------------------------------------------------------------------
// Exporter binding
// ---------------------------------------------------------------------------

#[test]
fn exporter_binding_matches_reference_vector() {
    // Vector recorded in conformance/tls-exporter-vectors.yaml — generated
    // using the same algorithm as the TS bridge's `deriveExporterKey`.
    let ikm: Vec<u8> = (0..32u8).collect();
    let label = "tf-session-binding";
    let context: &[u8] = &[];
    let length = 32;
    let expected_hex = "97c45446f2dafe3a8283909cd3938650c0deaa5f94d9061b198272e4c1f8e4f8";

    let okm = ExporterBinding::derive(&ikm, label, context, length);
    assert_eq!(hex_encode(&okm), expected_hex);

    // Second vector with non-empty context and 64-byte output.
    let ikm2 = parse_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let okm2 = ExporterBinding::derive(&ikm2, "tf-quic-binding", b"session-id:abc123", 64);
    let expected2 = "d6800e1130079e7e04c88c44323210dd7fa85dd950bffa84b229ab2546b50628a3df53841f30924cef7b58335cba9430ae7ed54f946044ab0bf40094cab0d681";
    assert_eq!(hex_encode(&okm2), expected2);
}

#[test]
fn exporter_binding_yaml_fixture_loads() {
    // Confirm the conformance YAML is well-formed and contains the same
    // vector this test asserts on. This guards against accidental drift.
    let yaml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/tls-exporter-vectors.yaml");
    let text = std::fs::read_to_string(&yaml_path).expect("read tls-exporter-vectors.yaml");
    let parsed: serde_yaml::Value = serde_yaml::from_str(&text).expect("parse yaml");
    let vectors = parsed
        .get("vectors")
        .and_then(|v| v.as_sequence())
        .expect("vectors[]");
    assert!(!vectors.is_empty());
    let first = &vectors[0];
    assert_eq!(
        first.get("label").and_then(|v| v.as_str()),
        Some("tf-session-binding")
    );
    assert_eq!(
        first.get("expected_hex").and_then(|v| v.as_str()),
        Some("97c45446f2dafe3a8283909cd3938650c0deaa5f94d9061b198272e4c1f8e4f8")
    );
}

// ---------------------------------------------------------------------------
// Post-handshake reauth
// ---------------------------------------------------------------------------

#[test]
fn post_handshake_reauth_accepts_valid_signature() {
    use rand::rngs::OsRng;
    let signer = Ed25519Signer::generate(&mut OsRng);
    let pk = signer.public_key_bytes();
    let challenge = PostHandshakeReauth::challenge();
    assert_eq!(challenge.len(), 32);
    let sig = signer.sign(&challenge);
    assert!(PostHandshakeReauth::verify_response(&challenge, &pk, &sig));
}

#[test]
fn post_handshake_reauth_rejects_tampered_signature() {
    use rand::rngs::OsRng;
    let signer = Ed25519Signer::generate(&mut OsRng);
    let pk = signer.public_key_bytes();
    let challenge = PostHandshakeReauth::challenge();
    let mut sig = signer.sign(&challenge);
    sig[0] ^= 0x01; // flip a single bit anywhere in the signature
    assert!(!PostHandshakeReauth::verify_response(&challenge, &pk, &sig));

    // Also: altering the challenge must reject a valid signature.
    let good_sig = signer.sign(&challenge);
    let mut tampered_challenge = challenge.clone();
    tampered_challenge[5] ^= 0x80;
    assert!(!PostHandshakeReauth::verify_response(
        &tampered_challenge,
        &pk,
        &good_sig
    ));
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn parse_hex(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = from_hex_nibble(bytes[i]);
        let lo = from_hex_nibble(bytes[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn from_hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("non-hex char"),
    }
}
