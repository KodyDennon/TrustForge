//! Cross-component tests for the AWS bridge.
//!
//! Uses `wiremock` to mock STS GetCallerIdentity, exercises the
//! AssumeRole-to-actor translator, and pins the IAM-policy translation
//! against a representative real-world policy document.

use std::collections::BTreeMap;

use tf_bridge_aws::{
    assume_role_token_to_actor, iam_policy_to_capabilities, verify_aws_sigv4_request,
    AwsAssumedRoleToken, AwsBridgeError, AwsSigV4Request,
};
use tf_types::generated::{ActorType, RiskClass, TrustLevel};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SUCCESS_RESPONSE_BODY: &str = r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <UserId>AROAEXAMPLE:session-1</UserId>
    <Account>123456789012</Account>
    <Arn>arn:aws:sts::123456789012:assumed-role/MyRole/session-1</Arn>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>00000000-0000-0000-0000-000000000000</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>"#;

fn signed_request(host: &str) -> AwsSigV4Request {
    let mut headers = BTreeMap::new();
    headers.insert(
        "Authorization".to_string(),
        "AWS4-HMAC-SHA256 Credential=AKIA.../20260101/us-east-1/sts/aws4_request, \
         SignedHeaders=host;x-amz-date, \
         Signature=deadbeef"
            .to_string(),
    );
    headers.insert("Host".to_string(), host.to_string());
    headers.insert("X-Amz-Date".to_string(), "20260101T000000Z".to_string());
    headers.insert(
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    );
    AwsSigV4Request {
        method: "POST".into(),
        uri: format!("http://{host}/"),
        headers,
        body: b"Action=GetCallerIdentity&Version=2011-06-15".to_vec(),
    }
}

#[tokio::test]
async fn verify_aws_sigv4_request_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SUCCESS_RESPONSE_BODY))
        .mount(&server)
        .await;
    let endpoint = server.uri();
    let host = endpoint
        .strip_prefix("http://")
        .unwrap_or(&endpoint)
        .to_string();
    let req = signed_request(&host);
    let identity = verify_aws_sigv4_request(&endpoint, &req).await.unwrap();
    assert_eq!(identity.account, "123456789012");
    assert_eq!(identity.user_id, "AROAEXAMPLE:session-1");
    assert_eq!(
        identity.arn,
        "arn:aws:sts::123456789012:assumed-role/MyRole/session-1"
    );
    assert_eq!(identity.actor_type, ActorType::Service);
}

#[tokio::test]
async fn verify_aws_sigv4_request_rejects_non_post() {
    let server = MockServer::start().await;
    let endpoint = server.uri();
    let host = endpoint
        .strip_prefix("http://")
        .unwrap_or(&endpoint)
        .to_string();
    let mut req = signed_request(&host);
    req.method = "GET".into();
    let err = verify_aws_sigv4_request(&endpoint, &req).await.unwrap_err();
    assert!(matches!(err, AwsBridgeError::InvalidInput(_)));
}

#[tokio::test]
async fn verify_aws_sigv4_request_rejects_wrong_action() {
    let server = MockServer::start().await;
    let endpoint = server.uri();
    let host = endpoint
        .strip_prefix("http://")
        .unwrap_or(&endpoint)
        .to_string();
    let mut req = signed_request(&host);
    req.body = b"Action=AssumeRole&Version=2011-06-15".to_vec();
    let err = verify_aws_sigv4_request(&endpoint, &req).await.unwrap_err();
    assert!(matches!(err, AwsBridgeError::InvalidInput(_)));
}

#[tokio::test]
async fn verify_aws_sigv4_request_rejects_missing_authorization() {
    let server = MockServer::start().await;
    let endpoint = server.uri();
    let host = endpoint
        .strip_prefix("http://")
        .unwrap_or(&endpoint)
        .to_string();
    let mut req = signed_request(&host);
    req.headers.remove("Authorization");
    let err = verify_aws_sigv4_request(&endpoint, &req).await.unwrap_err();
    assert!(matches!(err, AwsBridgeError::InvalidInput(_)));
}

#[tokio::test]
async fn verify_aws_sigv4_request_propagates_sts_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(403).set_body_string(
            "<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>",
        ))
        .mount(&server)
        .await;
    let endpoint = server.uri();
    let host = endpoint
        .strip_prefix("http://")
        .unwrap_or(&endpoint)
        .to_string();
    let req = signed_request(&host);
    let err = verify_aws_sigv4_request(&endpoint, &req).await.unwrap_err();
    assert!(matches!(err, AwsBridgeError::StsRejected(_)));
}

#[test]
fn assume_role_translation_pins_actor_uri_and_authority_root() {
    let token = AwsAssumedRoleToken {
        assumed_role_arn: "arn:aws:sts::987654321098:assumed-role/PowerUser/jane@example.com"
            .into(),
        assumed_role_id: "AROAJANEEXAMPLE:jane@example.com".into(),
        access_key_id: "ASIA...".into(),
        expiration: Some("2026-12-31T23:59:59Z".into()),
    };
    let actor = assume_role_token_to_actor(&token).unwrap();
    assert_eq!(
        actor.actor_id,
        "tf:actor:service:aws.amazon.com/987654321098/role/PowerUser/jane@example.com"
    );
    assert_eq!(actor.actor_type, ActorType::Service);
    assert_eq!(actor.trust_levels, vec![TrustLevel::T3]);
    assert_eq!(actor.authority_roots.len(), 1);
    assert_eq!(
        actor.authority_roots[0].id,
        "arn:aws:iam::987654321098:root"
    );
    assert_eq!(actor.valid_until.as_deref(), Some("2026-12-31T23:59:59Z"));
}

#[test]
fn assume_role_translation_rejects_non_sts_arn() {
    let token = AwsAssumedRoleToken {
        assumed_role_arn: "arn:aws:iam::123:user/foo".into(),
        assumed_role_id: "AID:foo".into(),
        access_key_id: "ASIA...".into(),
        expiration: None,
    };
    let err = assume_role_token_to_actor(&token).unwrap_err();
    assert!(matches!(err, AwsBridgeError::InvalidInput(_)));
}

#[test]
fn iam_policy_translation_handles_real_world_policy() {
    let policy = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadObjects",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    "arn:aws:s3:::example/*",
                    "arn:aws:s3:::example"
                ]
            },
            {
                "Sid": "WriteFew",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::example/uploads/*"
            },
            {
                "Sid": "NoDeletes",
                "Effect": "Deny",
                "Action": ["s3:DeleteObject", "s3:DeleteBucket"],
                "Resource": "*"
            }
        ]
    }"#;
    let (allow, deny) = iam_policy_to_capabilities(policy).unwrap();
    assert_eq!(allow.len(), 3);
    let names: Vec<_> = allow.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"aws.s3.get_object"));
    assert!(names.contains(&"aws.s3.list_bucket"));
    assert!(names.contains(&"aws.s3.put_object"));

    let put = allow
        .iter()
        .find(|c| c.name == "aws.s3.put_object")
        .unwrap();
    assert_eq!(put.risk, RiskClass::R3);
    assert!(put.constraints.is_some());

    let get = allow
        .iter()
        .find(|c| c.name == "aws.s3.get_object")
        .unwrap();
    assert_eq!(get.risk, RiskClass::R1);

    assert_eq!(deny.len(), 2);
    let deny_names: Vec<_> = deny.iter().map(|d| d.name.as_str()).collect();
    assert!(deny_names.contains(&"aws.s3.delete_object"));
    assert!(deny_names.contains(&"aws.s3.delete_bucket"));
}

#[test]
fn iam_policy_translation_rejects_invalid_json() {
    let err = iam_policy_to_capabilities("{not json").unwrap_err();
    assert!(matches!(err, AwsBridgeError::Policy(_)));
}

#[test]
fn iam_policy_translation_rejects_missing_statement() {
    let err = iam_policy_to_capabilities(r#"{"Version":"2012-10-17"}"#).unwrap_err();
    assert!(matches!(err, AwsBridgeError::Policy(_)));
}

#[test]
fn iam_policy_translation_handles_wildcard_action() {
    let policy = r#"{
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    }"#;
    let (allow, deny) = iam_policy_to_capabilities(policy).unwrap();
    assert_eq!(allow.len(), 1);
    assert_eq!(allow[0].name, "aws.*");
    assert_eq!(allow[0].risk, RiskClass::R3);
    assert!(allow[0].constraints.is_none());
    assert!(deny.is_empty());
}
