//! Revocation index — mirrors `tools/tf-types-ts/src/core/revocation.ts`.

use std::collections::HashMap;

use crate::generated::revocation::{Revocation, Revocation_TargetKind};

pub struct RevocationIndex {
    by_kind: HashMap<Revocation_TargetKind, HashMap<String, Revocation>>,
}

impl RevocationIndex {
    pub fn from_slice(revocations: &[Revocation]) -> Self {
        let mut by_kind: HashMap<Revocation_TargetKind, HashMap<String, Revocation>> =
            HashMap::new();
        for r in revocations {
            let bucket = by_kind.entry(r.target_kind.clone()).or_default();
            match bucket.get(&r.target_id) {
                Some(existing) if existing.effective_at <= r.effective_at => {}
                _ => {
                    bucket.insert(r.target_id.clone(), r.clone());
                }
            }
        }
        RevocationIndex { by_kind }
    }

    pub fn is_revoked(&self, id: &str, kind: &Revocation_TargetKind, at: &str) -> bool {
        let Some(bucket) = self.by_kind.get(kind) else {
            return false;
        };
        let Some(rev) = bucket.get(id) else {
            return false;
        };
        rev.effective_at.as_str() <= at
    }
}

impl std::hash::Hash for Revocation_TargetKind {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
    }
}
