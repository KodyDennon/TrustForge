//! ApprovalQueue — Rust mirror of
//! `tools/tf-types-ts/src/core/approval.ts`.
//!
//! A FIFO of pending ApprovalRequests where the daemon side awaits a
//! resolution. Uses tokio oneshot channels for the awaited responses and a
//! tokio timer for default-deny timeouts.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::generated::approval_request::ApprovalRequest;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("approval queue full ({0} pending)")]
    QueueFull(usize),
    #[error("approval result channel closed")]
    ChannelClosed,
}

#[derive(Clone, Debug)]
pub struct ApprovalResult {
    pub decision: ApprovalDecision,
    pub note: Option<String>,
}

struct PendingRecord {
    request: ApprovalRequest,
    responder: Option<oneshot::Sender<ApprovalResult>>,
    timer: Option<JoinHandle<()>>,
}

pub struct ApprovalQueue {
    pending: Arc<Mutex<HashMap<String, PendingRecord>>>,
    max_pending: usize,
    default_timeout: Duration,
    on_push: Option<Arc<dyn Fn(&ApprovalRequest) + Send + Sync>>,
    on_resolve: Option<Arc<dyn Fn(&ApprovalRequest, &ApprovalResult) + Send + Sync>>,
}

impl ApprovalQueue {
    pub fn new(max_pending: usize, default_timeout: Duration) -> Self {
        ApprovalQueue {
            pending: Arc::new(Mutex::new(HashMap::new())),
            max_pending,
            default_timeout,
            on_push: None,
            on_resolve: None,
        }
    }

    pub fn on_push<F>(mut self, f: F) -> Self
    where
        F: Fn(&ApprovalRequest) + Send + Sync + 'static,
    {
        self.on_push = Some(Arc::new(f));
        self
    }

    pub fn on_resolve<F>(mut self, f: F) -> Self
    where
        F: Fn(&ApprovalRequest, &ApprovalResult) + Send + Sync + 'static,
    {
        self.on_resolve = Some(Arc::new(f));
        self
    }

    pub fn size(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    pub fn list(&self) -> Vec<ApprovalRequest> {
        self.pending
            .lock()
            .unwrap()
            .values()
            .map(|r| r.request.clone())
            .collect()
    }

    /// Enqueue a request and await a decision. Resolves with Deny if the
    /// default timeout elapses first.
    pub async fn push(&self, request: ApprovalRequest) -> Result<ApprovalResult, ApprovalError> {
        let (tx, rx) = oneshot::channel::<ApprovalResult>();
        {
            let mut map = self.pending.lock().unwrap();
            if map.len() >= self.max_pending {
                return Err(ApprovalError::QueueFull(map.len()));
            }
            let id = request.id.clone();
            let pending = self.pending.clone();
            let timeout_id = id.clone();
            let default_timeout = self.default_timeout;
            let on_resolve = self.on_resolve.clone();
            let request_for_timer = request.clone();
            let timer = tokio::spawn(async move {
                tokio::time::sleep(default_timeout).await;
                let sender = {
                    let mut map = pending.lock().unwrap();
                    map.remove(&timeout_id).and_then(|r| r.responder)
                };
                if let Some(tx) = sender {
                    let result = ApprovalResult {
                        decision: ApprovalDecision::Deny,
                        note: Some("timeout".to_string()),
                    };
                    if let Some(cb) = &on_resolve {
                        cb(&request_for_timer, &result);
                    }
                    let _ = tx.send(result);
                }
            });
            map.insert(
                id,
                PendingRecord {
                    request: request.clone(),
                    responder: Some(tx),
                    timer: Some(timer),
                },
            );
        }
        if let Some(cb) = &self.on_push {
            cb(&request);
        }
        rx.await.map_err(|_| ApprovalError::ChannelClosed)
    }

    /// Resolve a pending request. Returns true if a matching request was
    /// found and resolved.
    pub fn respond(
        &self,
        request_id: &str,
        decision: ApprovalDecision,
        note: Option<String>,
    ) -> bool {
        let (responder, request, timer) = {
            let mut map = self.pending.lock().unwrap();
            match map.remove(request_id) {
                Some(r) => (r.responder, r.request, r.timer),
                None => return false,
            }
        };
        if let Some(handle) = timer {
            handle.abort();
        }
        let result = ApprovalResult { decision, note };
        if let Some(cb) = &self.on_resolve {
            cb(&request, &result);
        }
        if let Some(tx) = responder {
            let _ = tx.send(result);
        }
        true
    }

    /// Cancel every outstanding approval with Deny + `reason`.
    pub fn drain_deny(&self, reason: &str) {
        let items: Vec<_> = {
            let mut map = self.pending.lock().unwrap();
            map.drain().map(|(_, r)| r).collect()
        };
        for record in items {
            if let Some(handle) = record.timer {
                handle.abort();
            }
            let result = ApprovalResult {
                decision: ApprovalDecision::Deny,
                note: Some(reason.to_string()),
            };
            if let Some(cb) = &self.on_resolve {
                cb(&record.request, &result);
            }
            if let Some(tx) = record.responder {
                let _ = tx.send(result);
            }
        }
    }
}
