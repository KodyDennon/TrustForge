//! ApprovalQueue tests mirroring the TS suite.

use std::time::Duration;

use tf_types::approval::{ApprovalDecision, ApprovalError, ApprovalQueue};
use tf_types::generated::approval_request::{ApprovalRequest, ApprovalRequest_RequestVersion};

fn req(id: &str) -> ApprovalRequest {
    ApprovalRequest {
        request_version: ApprovalRequest_RequestVersion::V1,
        id: id.to_string(),
        actor: "tf:actor:agent:example.com/a".to_string(),
        action: "shell.exec".to_string(),
        target: None,
        danger_tags: None,
        reason: "just because".to_string(),
        created_at: "2026-04-24T13:00:00Z".to_string(),
        expires_at: None,
    }
}

#[tokio::test]
async fn approve_resolves_pending() {
    let queue = std::sync::Arc::new(ApprovalQueue::new(32, Duration::from_secs(30)));
    let queue_clone = queue.clone();
    let handle = tokio::spawn(async move { queue_clone.push(req("r1")).await });
    // Give push a chance to register the pending record.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(queue.respond("r1", ApprovalDecision::Approve, Some("OK".into())));
    let result = handle.await.unwrap().unwrap();
    assert_eq!(result.decision, ApprovalDecision::Approve);
    assert_eq!(result.note, Some("OK".to_string()));
    assert_eq!(queue.size(), 0);
}

#[tokio::test]
async fn deny_resolves_with_deny() {
    let queue = std::sync::Arc::new(ApprovalQueue::new(32, Duration::from_secs(30)));
    let queue_clone = queue.clone();
    let handle = tokio::spawn(async move { queue_clone.push(req("r2")).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(queue.respond("r2", ApprovalDecision::Deny, None));
    let result = handle.await.unwrap().unwrap();
    assert_eq!(result.decision, ApprovalDecision::Deny);
}

#[tokio::test]
async fn timeout_defaults_to_deny() {
    let queue = ApprovalQueue::new(32, Duration::from_millis(30));
    let result = queue.push(req("r3")).await.unwrap();
    assert_eq!(result.decision, ApprovalDecision::Deny);
    assert_eq!(result.note, Some("timeout".to_string()));
}

#[tokio::test]
async fn max_pending_rejects_when_full() {
    let queue = std::sync::Arc::new(ApprovalQueue::new(1, Duration::from_secs(30)));
    let queue_clone = queue.clone();
    let _handle = tokio::spawn(async move { queue_clone.push(req("a")).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let err = queue.push(req("b")).await.unwrap_err();
    assert!(matches!(err, ApprovalError::QueueFull(_)));
}

#[tokio::test]
async fn drain_deny_resolves_outstanding() {
    let queue = std::sync::Arc::new(ApprovalQueue::new(32, Duration::from_secs(30)));
    let a_q = queue.clone();
    let b_q = queue.clone();
    let a = tokio::spawn(async move { a_q.push(req("a")).await });
    let b = tokio::spawn(async move { b_q.push(req("b")).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    queue.drain_deny("shutdown");
    assert_eq!(a.await.unwrap().unwrap().decision, ApprovalDecision::Deny);
    assert_eq!(b.await.unwrap().unwrap().decision, ApprovalDecision::Deny);
    assert_eq!(queue.size(), 0);
}
