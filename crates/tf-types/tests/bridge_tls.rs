//! Rust TLS / mTLS bridge tests. We use `rcgen` to mint real certificate
//! chains (root → intermediate → leaf) signed with ECDSA P-256, then drive
//! them through `TlsBridge::verify_chain`. Cross-language parity is
//! asserted with `tools/tf-types-ts/tests/bridge-tls.test.ts`.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use time::{Duration, OffsetDateTime};

use tf_types::bridge_tls::{TlsBridge, TlsBridgeConfig};
use tf_types::bridges::BridgeError;
use tf_types::generated::ActorType;

#[allow(dead_code)]
struct Material {
    pem: String,
    key_pair: KeyPair,
    cert: rcgen::Certificate,
}

fn make_root() -> Material {
    let mut params = CertificateParams::new(vec!["TrustForge Root CA".into()]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "TrustForge Root CA");
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::hours(1);
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    Material {
        pem: cert.pem(),
        key_pair,
        cert,
    }
}

fn make_intermediate(parent: &Material, cn: &str) -> Material {
    let mut params = CertificateParams::new(vec![cn.into()]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.distinguished_name.push(DnType::CommonName, cn);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::hours(1);
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params
        .signed_by(&key_pair, &parent.cert, &parent.key_pair)
        .unwrap();
    Material {
        pem: cert.pem(),
        key_pair,
        cert,
    }
}

struct LeafOpts<'a> {
    cn: &'a str,
    ekus: Vec<ExtendedKeyUsagePurpose>,
    san_uris: Vec<String>,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

fn make_leaf(parent: &Material, opts: LeafOpts) -> Material {
    let mut params = CertificateParams::new(vec![opts.cn.into()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.distinguished_name.push(DnType::CommonName, opts.cn);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = opts.ekus;
    params.subject_alt_names = opts
        .san_uris
        .into_iter()
        .map(|u| SanType::URI(u.parse().expect("URI")))
        .collect();
    params.not_before = opts.not_before;
    params.not_after = opts.not_after;
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params
        .signed_by(&key_pair, &parent.cert, &parent.key_pair)
        .unwrap();
    Material {
        pem: cert.pem(),
        key_pair,
        cert,
    }
}

fn default_leaf<'a>(cn: &'a str, ekus: Vec<ExtendedKeyUsagePurpose>) -> LeafOpts<'a> {
    LeafOpts {
        cn,
        ekus,
        san_uris: vec![],
        not_before: OffsetDateTime::now_utc() - Duration::minutes(1),
        not_after: OffsetDateTime::now_utc() + Duration::hours(1),
    }
}

#[test]
fn verifies_full_chain_and_projects_service_actor() {
    let root = make_root();
    let inter = make_intermediate(&root, "TrustForge Intermediate");
    let mut opts = default_leaf(
        "tf-service-leaf",
        vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ],
    );
    opts.san_uris = vec!["spiffe://example.com/services/code-helper".into()];
    let leaf = make_leaf(&inter, opts);

    let bridge = TlsBridge::new(TlsBridgeConfig {
        bridge_id: "tf-tls-bridge".into(),
        trust_domain: "example.com".into(),
        root_certificates_pem: vec![root.pem.clone()],
        max_chain_length: None,
        required_san_uri: None,
        now_unix_seconds: None,
    })
    .expect("bridge");

    let result = bridge
        .verify_chain(&[leaf.pem.clone(), inter.pem.clone()])
        .expect("verify");
    assert_eq!(result.identity.actor_type, ActorType::Service);
    assert!(result
        .identity
        .actor_id
        .starts_with("tf:actor:service:example.com/spiffe%3A//example.com/services/code-helper"));
    assert!(result.capabilities.contains(&"tls.client-auth".to_string()));
    assert!(result.capabilities.contains(&"tls.server-auth".to_string()));
    assert_eq!(result.chain_subjects.len(), 3);
    let _ = leaf.cert; // suppress dead-field warnings
    let _ = root.cert;
    let _ = inter.cert;
}

#[test]
fn rejects_chain_signed_by_unknown_root() {
    let real_root = make_root();
    let imposter_root = make_root();
    let leaf = make_leaf(
        &imposter_root,
        default_leaf("leaf", vec![ExtendedKeyUsagePurpose::ClientAuth]),
    );

    let bridge = TlsBridge::new(TlsBridgeConfig {
        bridge_id: "tf-tls-bridge".into(),
        trust_domain: "example.com".into(),
        root_certificates_pem: vec![real_root.pem.clone()],
        max_chain_length: None,
        required_san_uri: None,
        now_unix_seconds: None,
    })
    .unwrap();
    assert!(matches!(
        bridge.verify_chain(&[leaf.pem.clone()]),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn rejects_expired_leaf() {
    let root = make_root();
    let now = OffsetDateTime::now_utc();
    let opts = LeafOpts {
        cn: "expired",
        ekus: vec![ExtendedKeyUsagePurpose::ClientAuth],
        san_uris: vec![],
        not_before: now - Duration::hours(2),
        not_after: now - Duration::minutes(1),
    };
    let leaf = make_leaf(&root, opts);
    let bridge = TlsBridge::new(TlsBridgeConfig {
        bridge_id: "tf-tls-bridge".into(),
        trust_domain: "example.com".into(),
        root_certificates_pem: vec![root.pem.clone()],
        max_chain_length: None,
        required_san_uri: None,
        now_unix_seconds: None,
    })
    .unwrap();
    assert!(matches!(
        bridge.verify_chain(&[leaf.pem.clone()]),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn enforces_required_san_uri() {
    let root = make_root();
    let mut opts = default_leaf("svc", vec![ExtendedKeyUsagePurpose::ClientAuth]);
    opts.san_uris = vec!["spiffe://example.com/different".into()];
    let leaf = make_leaf(&root, opts);
    let bridge = TlsBridge::new(TlsBridgeConfig {
        bridge_id: "tf-tls-bridge".into(),
        trust_domain: "example.com".into(),
        root_certificates_pem: vec![root.pem.clone()],
        max_chain_length: None,
        required_san_uri: Some("spiffe://example.com/expected".into()),
        now_unix_seconds: None,
    })
    .unwrap();
    assert!(matches!(
        bridge.verify_chain(&[leaf.pem.clone()]),
        Err(BridgeError::Rejected(_))
    ));
}

#[test]
fn projects_device_actor_when_no_spiffe_san() {
    let root = make_root();
    let leaf = make_leaf(
        &root,
        default_leaf("device-001", vec![ExtendedKeyUsagePurpose::ClientAuth]),
    );
    let bridge = TlsBridge::new(TlsBridgeConfig {
        bridge_id: "tf-tls-bridge".into(),
        trust_domain: "example.com".into(),
        root_certificates_pem: vec![root.pem.clone()],
        max_chain_length: None,
        required_san_uri: None,
        now_unix_seconds: None,
    })
    .unwrap();
    let result = bridge.verify_chain(&[leaf.pem.clone()]).expect("verify");
    assert_eq!(result.identity.actor_type, ActorType::Device);
    assert_eq!(
        result.identity.actor_id,
        "tf:actor:device:example.com/device-001"
    );
}

#[test]
fn empty_chain_rejected() {
    let root = make_root();
    let bridge = TlsBridge::new(TlsBridgeConfig {
        bridge_id: "tf-tls-bridge".into(),
        trust_domain: "example.com".into(),
        root_certificates_pem: vec![root.pem.clone()],
        max_chain_length: None,
        required_san_uri: None,
        now_unix_seconds: None,
    })
    .unwrap();
    assert!(matches!(
        bridge.verify_chain(&[]),
        Err(BridgeError::InvalidInput(_))
    ));
}
