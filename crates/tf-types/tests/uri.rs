//! URI parser smoke tests for the hand-written core modules.

use tf_types::actor_id::{actor_id_equals, format_actor_id, parse_actor_id, ActorIdParseError};
use tf_types::generated::common::ActorType;
use tf_types::instance_id::{format_instance_id, parse_instance_id, to_actor_id};
use tf_types::trust_domain::{parse_trust_domain, trust_domain_equals, TrustDomainKind};

#[test]
fn actor_id_round_trip() {
    let p = parse_actor_id("tf:actor:agent:example.com/code-helper").unwrap();
    assert_eq!(p.actor_type, ActorType::Agent);
    assert_eq!(p.path, "example.com/code-helper");
    let s = format_actor_id(&p.actor_type, &p.path).unwrap();
    assert_eq!(s, "tf:actor:agent:example.com/code-helper");
}

#[test]
fn actor_id_rejects_unknown_type() {
    let err = parse_actor_id("tf:actor:robot:example").unwrap_err();
    assert!(matches!(err, ActorIdParseError::UnknownType(_)));
}

#[test]
fn actor_id_equals_ignores_raw_string() {
    assert!(actor_id_equals(
        "tf:actor:agent:example.com/a",
        "tf:actor:agent:example.com/a"
    ));
    assert!(!actor_id_equals(
        "tf:actor:agent:example.com/a",
        "tf:actor:agent:example.com/b"
    ));
}

#[test]
fn instance_id_round_trip() {
    let p =
        parse_instance_id("tf:instance:agent:example.com/code-helper/macbook/session-42").unwrap();
    assert_eq!(p.actor_type, ActorType::Agent);
    assert_eq!(p.actor_path, "example.com/code-helper/macbook");
    assert_eq!(p.instance_path, "session-42");
    let s = format_instance_id(&p.actor_type, &p.actor_path, &p.instance_path).unwrap();
    assert_eq!(
        s,
        "tf:instance:agent:example.com/code-helper/macbook/session-42"
    );
}

#[test]
fn to_actor_id_strips_instance() {
    let a = to_actor_id("tf:instance:agent:example.com/code-helper/macbook/session-42").unwrap();
    assert_eq!(a, "tf:actor:agent:example.com/code-helper/macbook");
}

#[test]
fn trust_domain_dns_and_local() {
    let dns = parse_trust_domain("Example.COM").unwrap();
    assert_eq!(dns.kind, TrustDomainKind::Dns);
    assert_eq!(dns.value, "example.com");

    let local = parse_trust_domain("local/home").unwrap();
    assert_eq!(local.kind, TrustDomainKind::Local);
    assert_eq!(local.value, "home");

    assert!(trust_domain_equals("EXAMPLE.com", "example.COM"));
    assert!(!trust_domain_equals("local/Home", "local/home"));
}
