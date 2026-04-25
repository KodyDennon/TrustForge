// SPDX-License-Identifier: Apache-2.0
//
// Host-side unit tests for tf-envoy-filter pure helpers.
//
// We can't drive `proxy-wasm`'s `HttpContext::on_http_request_headers`
// from a host-side test without a wasm runtime; the closest off-the-shelf
// option `proxy-wasm-test = "0.2"` does not exist on crates.io as of
// 2026-04-25. Instead we test the deterministic helpers
// (`build_decide_request`, `to_json`, `parse_decide_response`) which
// encode 100% of the protocol-shaping logic. The remaining shim
// (header reads, dispatch_http_call) is untestable without a real Envoy
// and is exercised by the conformance suite.

use tf_envoy_filter::{build_decide_request, parse_decide_response, DecideRequest};

#[test]
fn builds_request_from_typical_headers() {
    let req = build_decide_request(
        "api.example.com",
        "GET",
        "/v1/widgets/42",
        Some("Bearer abc.def.ghi"),
        None,
    );
    assert_eq!(
        req,
        DecideRequest {
            actor: "Bearer abc.def.ghi".into(),
            action: "http.get.v1".into(),
            target: "api.example.com/v1/widgets/42".into(),
        }
    );
}

#[test]
fn falls_back_to_cookie_when_no_authorization() {
    let req = build_decide_request(
        "api.example.com",
        "POST",
        "/login",
        None,
        Some("session=xyz"),
    );
    assert_eq!(req.actor, "session=xyz");
    assert_eq!(req.action, "http.post.login");
}

#[test]
fn anonymous_when_neither_header_present() {
    let req = build_decide_request("api.example.com", "GET", "/", None, None);
    assert_eq!(req.actor, "");
    assert_eq!(req.action, "http.get._root");
    assert_eq!(req.target, "api.example.com/");
}

#[test]
fn json_serialisation_is_well_formed() {
    let req = DecideRequest {
        actor: "alice".into(),
        action: "http.get.v1".into(),
        target: "api.example.com/v1".into(),
    };
    let s = req.to_json();
    let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
    assert_eq!(v["actor"], "alice");
    assert_eq!(v["action"], "http.get.v1");
    assert_eq!(v["target"], "api.example.com/v1");
}

#[test]
fn json_serialisation_escapes_quotes_and_backslashes() {
    let req = DecideRequest {
        actor: r#"weird"\name"#.into(),
        action: "x".into(),
        target: "y".into(),
    };
    let s = req.to_json();
    let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON despite quirky input");
    assert_eq!(v["actor"], r#"weird"\name"#);
}

#[test]
fn parses_allow_response() {
    let resp = parse_decide_response(br#"{"decision":"allow"}"#);
    assert_eq!(resp.decision, "allow");
    assert_eq!(resp.reason, "");
}

#[test]
fn parses_deny_response_with_reason() {
    let resp = parse_decide_response(br#"{"decision":"deny","reason":"policy: missing scope"}"#);
    assert_eq!(resp.decision, "deny");
    assert_eq!(resp.reason, "policy: missing scope");
}

#[test]
fn parses_deny_response_with_extra_fields() {
    let body = br#"{"trace":"abc","decision":"deny","reason":"nope","ttl":30}"#;
    let resp = parse_decide_response(body);
    assert_eq!(resp.decision, "deny");
    assert_eq!(resp.reason, "nope");
}

#[test]
fn malformed_body_is_treated_as_deny() {
    // No `decision` field present — caller should not interpret this as allow.
    let resp = parse_decide_response(b"<html>nope</html>");
    assert!(resp.decision != "allow");
}
