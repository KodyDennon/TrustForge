//! Real-parser fixtures for the service-mesh bridge.
//!
//! Twelve total: four each for Envoy XFCC, Istio AuthN, and Linkerd
//! `l5d-client-id`. Together they exercise the happy path plus three
//! kinds of failure (malformed, missing-required-field, wrong shape).

use tf_types::encoding::{STANDARD, URL_SAFE_NO_PAD};

use tf_types::bridge_service_mesh::{
    envoy_accepted_event, istio_accepted_event, linkerd_accepted_event, parse_istio_attributes,
    parse_linkerd_client_id, parse_xfcc, IstioPrincipal, LinkerdClient,
};

// ---------------------------------------------------------------------------
// Envoy XFCC
// ---------------------------------------------------------------------------

#[test]
fn envoy_minimal_single_entry() {
    let header = "URI=spiffe://example.com/ns/foo/sa/bar";
    let entries = parse_xfcc(header).expect("minimal entry parses");
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.uri.as_deref(), Some("spiffe://example.com/ns/foo/sa/bar"));
    assert!(e.hash.is_none());
    assert!(e.by.is_none());
    assert!(e.subject.is_none());

    // Proof-event stub is shaped correctly.
    let stub = envoy_accepted_event(e);
    assert_eq!(stub.event_type, "bridge.service_mesh.envoy.accepted");
    assert_eq!(
        stub.payload.get("uri").and_then(|v| v.as_str()),
        Some("spiffe://example.com/ns/foo/sa/bar")
    );
}

#[test]
fn envoy_multi_entry_with_quoted_subject() {
    // Two hops; the leaf entry has a quoted Subject containing a
    // comma (which would break a naïve splitter), plus DNS / Hash / By.
    let header = concat!(
        "By=spiffe://issuer.example.com/ca;",
        "Hash=abcd1234;",
        "Subject=\"CN=workload,OU=team,O=acme\";",
        "URI=spiffe://example.com/ns/foo/sa/bar;",
        "DNS=foo.example.com",
        ",",
        "By=spiffe://outer.example.com/ca;",
        "Hash=ffff;",
        "URI=spiffe://outer.example.com/ns/edge/sa/proxy"
    );
    let entries = parse_xfcc(header).expect("multi-entry parses");
    assert_eq!(entries.len(), 2);

    let leaf = &entries[0];
    assert_eq!(
        leaf.uri.as_deref(),
        Some("spiffe://example.com/ns/foo/sa/bar")
    );
    assert_eq!(leaf.hash.as_deref(), Some("abcd1234"));
    assert_eq!(leaf.by.as_deref(), Some("spiffe://issuer.example.com/ca"));
    // Explicit Subject= takes precedence over DNS=, so DNS is not
    // folded in here.
    assert_eq!(leaf.subject.as_deref(), Some("CN=workload,OU=team,O=acme"));

    let outer = &entries[1];
    assert_eq!(
        outer.uri.as_deref(),
        Some("spiffe://outer.example.com/ns/edge/sa/proxy")
    );
    assert_eq!(outer.hash.as_deref(), Some("ffff"));
}

#[test]
fn envoy_mismatched_quotes_is_rejected() {
    // Subject is opened with a quote but never closed — must error.
    let header = "URI=spiffe://example.com/ns/foo/sa/bar;Subject=\"CN=open";
    let err = parse_xfcc(header).expect_err("mismatched quotes must fail");
    let msg = format!("{}", err);
    assert!(
        msg.contains("mismatched quotes") || msg.contains("dangling"),
        "unexpected error message: {}",
        msg
    );
}

#[test]
fn envoy_missing_required_fields_is_rejected() {
    // No URI, no Subject, no By, no DNS — Envoy never emits this but a
    // tampered upstream could. We must reject so the daemon never
    // signs an "accepted" event for a content-free entry.
    let header = "Hash=ffaa";
    let err = parse_xfcc(header).expect_err("content-free entry must fail");
    let msg = format!("{}", err);
    assert!(
        msg.contains("no URI/By/Subject/DNS"),
        "unexpected error message: {}",
        msg
    );

    // Entry with DNS only is accepted — DNS folds into the subject
    // fallback so the entry is no longer content-free.
    let dns_only = "DNS=svc.example.com;DNS=alt.example.com;Hash=ff";
    let entries = parse_xfcc(dns_only).expect("dns-only entry parses");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].subject.as_deref(),
        Some("dns:svc.example.com,alt.example.com")
    );
}

// ---------------------------------------------------------------------------
// Istio AuthN
// ---------------------------------------------------------------------------

/// Build a valid Istio `x-istio-attributes` byte string by encoding
/// `principal` as a single length-delimited protobuf string field
/// (field 1, wire type 2).
fn istio_attribute_proto(principal: &str) -> String {
    let bytes = principal.as_bytes();
    let mut buf = Vec::with_capacity(2 + bytes.len());
    buf.push(0x0a); // tag: field=1, wire=2
    encode_varint(&mut buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
    STANDARD.encode(&buf)
}

fn encode_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Build a minimal JWT with `iss` and `sub` claims. Signature is a
/// dummy `sig` segment — the parser explicitly does not verify
/// signatures here.
fn fake_jwt(iss: &str, sub: &str) -> String {
    let header = serde_json::json!({"alg": "RS256", "typ": "JWT"}).to_string();
    let payload = serde_json::json!({"iss": iss, "sub": sub}).to_string();
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header.as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.as_bytes()),
        URL_SAFE_NO_PAD.encode(b"sig"),
    )
}

#[test]
fn istio_protobuf_principal() {
    let header = istio_attribute_proto("spiffe://cluster.local/ns/foo/sa/bar");
    let p: IstioPrincipal = parse_istio_attributes(&header).expect("protobuf principal");
    assert_eq!(p.spiffe_id, "spiffe://cluster.local/ns/foo/sa/bar");
    assert_eq!(p.namespace, "foo");

    let stub = istio_accepted_event(&p);
    assert_eq!(stub.event_type, "bridge.service_mesh.istio.accepted");
    assert_eq!(
        stub.payload.get("namespace").and_then(|v| v.as_str()),
        Some("foo")
    );
}

#[test]
fn istio_jwt_principal() {
    let jwt = fake_jwt(
        "https://kubernetes.default.svc.cluster.local",
        "spiffe://cluster.local/ns/payments/sa/charger",
    );
    let p = parse_istio_attributes(&jwt).expect("jwt principal");
    assert_eq!(p.spiffe_id, "spiffe://cluster.local/ns/payments/sa/charger");
    assert_eq!(p.namespace, "payments");
}

#[test]
fn istio_missing_namespace_is_rejected() {
    // SPIFFE id has no `/ns/<ns>/sa/<sa>` — Istio always emits that
    // shape, so anything else is suspect.
    let header = istio_attribute_proto("spiffe://cluster.local/some/random/path");
    let err = parse_istio_attributes(&header).expect_err("namespace required");
    let msg = format!("{}", err);
    assert!(msg.contains("/ns/"), "unexpected error message: {}", msg);
}

#[test]
fn istio_wrong_issuer_is_rejected() {
    let jwt = fake_jwt(
        "https://attacker.example.com/",
        "spiffe://cluster.local/ns/foo/sa/bar",
    );
    let err = parse_istio_attributes(&jwt).expect_err("non-istio issuer must fail");
    let msg = format!("{}", err);
    assert!(
        msg.contains("non-Istio issuer"),
        "unexpected error message: {}",
        msg
    );
}

// ---------------------------------------------------------------------------
// Linkerd l5d-client-id
// ---------------------------------------------------------------------------

#[test]
fn linkerd_valid_spiffe() {
    let header = "spiffe://cluster.local/ns/web/sa/api";
    let c: LinkerdClient = parse_linkerd_client_id(header).expect("spiffe");
    assert_eq!(c.spiffe_id, "spiffe://cluster.local/ns/web/sa/api");

    let stub = linkerd_accepted_event(&c);
    assert_eq!(stub.event_type, "bridge.service_mesh.linkerd.accepted");
    assert_eq!(
        stub.payload.get("spiffe_id").and_then(|v| v.as_str()),
        Some("spiffe://cluster.local/ns/web/sa/api")
    );
}

#[test]
fn linkerd_missing_trust_domain_is_rejected() {
    // `spiffe://` with no trust domain at all.
    let header = "spiffe:///ns/web/sa/api";
    let err = parse_linkerd_client_id(header).expect_err("missing trust domain must fail");
    let msg = format!("{}", err);
    assert!(
        msg.contains("trust domain"),
        "unexpected error message: {}",
        msg
    );
}

#[test]
fn linkerd_wrong_scheme_is_rejected() {
    let header = "http://web.cluster.local/api";
    let err = parse_linkerd_client_id(header).expect_err("wrong scheme must fail");
    let msg = format!("{}", err);
    assert!(
        msg.contains("non-spiffe scheme"),
        "unexpected error message: {}",
        msg
    );
}

#[test]
fn linkerd_empty_header_is_rejected() {
    let err = parse_linkerd_client_id("").expect_err("empty must fail");
    let msg = format!("{}", err);
    assert!(msg.contains("empty"), "unexpected error message: {}", msg);
}
