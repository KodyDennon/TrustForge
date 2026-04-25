//! Quorum approval collector — Rust mirror of
//! `tools/tf-types-ts/src/core/quorum.ts`.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumConfig {
    pub min_approvers: u32,
    pub of: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumOutcome {
    pub decision: String,
    pub approvers: Vec<String>,
    pub deniers: Vec<String>,
    pub ceremony: QuorumCeremony,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumCeremony {
    pub ceremony_version: String,
    pub ceremony_id: String,
    pub kind: String,
    pub request_id: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub min_approvers: u32,
    pub of: Vec<String>,
    pub approvers: Vec<String>,
    pub signatures: Vec<QuorumSignature>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumSignature {
    pub algorithm: String,
    pub signer: String,
    pub signature: String,
}

#[derive(Debug)]
pub struct QuorumApprovalCollector {
    cfg: QuorumConfig,
}

#[derive(Debug)]
pub struct QuorumHandle {
    cfg: QuorumConfig,
    request_id: String,
    started_at: String,
    state: Arc<Mutex<QuorumState>>,
}

#[derive(Debug, Default)]
struct QuorumState {
    approvers: Vec<String>,
    deniers: Vec<String>,
    signatures: Vec<QuorumSignature>,
    outcome: Option<QuorumOutcome>,
}

impl QuorumApprovalCollector {
    pub fn new(cfg: QuorumConfig) -> Result<Self, String> {
        if cfg.min_approvers < 1 {
            return Err("quorum.min_approvers must be ≥ 1".into());
        }
        if (cfg.of.len() as u32) < cfg.min_approvers {
            return Err(format!(
                "quorum.of ({}) must contain at least min_approvers ({}) actors",
                cfg.of.len(),
                cfg.min_approvers
            ));
        }
        Ok(QuorumApprovalCollector { cfg })
    }

    pub fn push(&self, request_id: &str, started_at: &str) -> QuorumHandle {
        QuorumHandle {
            cfg: self.cfg.clone(),
            request_id: request_id.into(),
            started_at: started_at.into(),
            state: Arc::new(Mutex::new(QuorumState::default())),
        }
    }
}

impl QuorumHandle {
    /// Record one approver's vote. Returns true when the vote was accepted
    /// (approver is in the eligible set and hasn't already voted), false
    /// otherwise.
    pub fn respond_as(
        &self,
        approver: &str,
        decision: &str,
        signature: QuorumSignature,
    ) -> bool {
        if !self.cfg.of.iter().any(|a| a == approver) {
            return false;
        }
        let mut state = self.state.lock().unwrap();
        if state.approvers.iter().any(|a| a == approver)
            || state.deniers.iter().any(|a| a == approver)
        {
            return false;
        }
        if decision == "approve" {
            state.approvers.push(approver.to_string());
            state.signatures.push(signature);
        } else {
            state.deniers.push(approver.to_string());
        }
        if state.approvers.len() as u32 >= self.cfg.min_approvers
            && state.outcome.is_none()
        {
            state.outcome = Some(self.materialise(&state, "approve"));
        } else if state.approvers.len() + state.deniers.len() >= self.cfg.of.len()
            && state.outcome.is_none()
        {
            state.outcome = Some(self.materialise(&state, "deny"));
        }
        true
    }

    pub fn outcome(&self) -> Option<QuorumOutcome> {
        self.state.lock().unwrap().outcome.clone()
    }

    fn materialise(&self, state: &QuorumState, decision: &str) -> QuorumOutcome {
        QuorumOutcome {
            decision: decision.into(),
            approvers: state.approvers.clone(),
            deniers: state.deniers.clone(),
            ceremony: QuorumCeremony {
                ceremony_version: "1".into(),
                ceremony_id: format!("cer-{}-quorum", self.request_id),
                kind: "quorum".into(),
                request_id: self.request_id.clone(),
                started_at: self.started_at.clone(),
                completed_at: Some(now_iso8601()),
                min_approvers: self.cfg.min_approvers,
                of: self.cfg.of.clone(),
                approvers: state.approvers.clone(),
                signatures: state.signatures.clone(),
            },
        }
    }
}

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (year, month, day, hour, minute, second) = secs_to_ymdhms(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn secs_to_ymdhms(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let time = secs.rem_euclid(86_400);
    let hour = (time / 3600) as u32;
    let minute = ((time % 3600) / 60) as u32;
    let second = (time % 60) as u32;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d, hour, minute, second)
}
