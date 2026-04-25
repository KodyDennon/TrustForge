//! Delegation chain walker — mirrors
//! `tools/tf-types-ts/src/core/delegation.ts`.

use crate::capability::intersect_constraints;
use crate::generated::common::{Constraint, DelegationLink};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalkResult {
    pub valid: bool,
    pub effective: Vec<Constraint>,
    pub expired_at: Option<String>,
    pub broken_step: Option<usize>,
    pub reason: Option<String>,
}

pub fn walk_chain(chain: &[DelegationLink], now: &str) -> WalkResult {
    let mut effective: Vec<Constraint> = Vec::new();
    let mut allow_redelegation = true;
    let mut max_depth_remaining: i64 = i64::MAX;

    for (i, step) in chain.iter().enumerate() {
        if i > 0 {
            if !allow_redelegation {
                return WalkResult {
                    valid: false,
                    effective,
                    expired_at: None,
                    broken_step: Some(i),
                    reason: Some(format!("step {} disallows redelegation", i - 1)),
                };
            }
            if max_depth_remaining <= 0 {
                return WalkResult {
                    valid: false,
                    effective,
                    expired_at: None,
                    broken_step: Some(i),
                    reason: Some(format!("max_depth exceeded at step {}", i)),
                };
            }
            max_depth_remaining -= 1;
        }

        if let Some(expires_at) = &step.expires_at {
            if expires_at.as_str() < now {
                return WalkResult {
                    valid: false,
                    effective,
                    expired_at: Some(expires_at.clone()),
                    broken_step: Some(i),
                    reason: Some(format!("step {} expired at {}", i, expires_at)),
                };
            }
        }

        if let Some(constraints) = &step.constraints {
            if !constraints.is_empty() {
                effective = intersect_constraints(&effective, constraints);
            }
        }

        if let Some(redelegation) = &step.redelegation {
            allow_redelegation = redelegation.allowed;
            if let Some(d) = redelegation.max_depth {
                max_depth_remaining = max_depth_remaining.min(d);
            }
        } else {
            allow_redelegation = true;
        }
    }

    WalkResult {
        valid: true,
        effective,
        expired_at: None,
        broken_step: None,
        reason: None,
    }
}
