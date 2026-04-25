//! Service-mesh bridge — Envoy XFCC, Istio AuthN, Linkerd l5d-client-id.

use serde::{Deserialize, Serialize};

use crate::bridge_spiffe::spiffe_to_actor_id;
use crate::bridges::{Bridge, BridgeError, BridgeKind};
use crate::generated::{
    ActorIdentity, ActorIdentity_IdentityVersion, ActorType, AuthorityRoot, AuthorityRoot_Kind,
    PublicKey, PublicKey_Purpose, TrustLevel,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XfccEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ServiceMeshBridgeConfig {
    pub bridge_id: String,
    pub trust_domain: String,
}

pub struct ServiceMeshBridge {
    cfg: ServiceMeshBridgeConfig,
}

impl ServiceMeshBridge {
    pub fn new(cfg: ServiceMeshBridgeConfig) -> Self {
        ServiceMeshBridge { cfg }
    }

    pub fn accept_envoy(&self, entry: &XfccEntry) -> Result<ActorIdentity, BridgeError> {
        let uri = entry
            .uri
            .as_deref()
            .ok_or_else(|| BridgeError::InvalidInput("XFCC entry needs URI in this Rust path".into()))?;
        if !uri.starts_with("spiffe://") {
            return Err(BridgeError::Rejected(
                "Rust XFCC bridge only accepts spiffe:// URIs".into(),
            ));
        }
        let actor = spiffe_to_actor_id(uri)?;
        Ok(self.identity_from(actor, entry.by.clone()))
    }

    pub fn accept_istio(&self, spiffe_id: &str) -> Result<ActorIdentity, BridgeError> {
        if !spiffe_id.starts_with("spiffe://") {
            return Err(BridgeError::InvalidInput(
                "Istio context.spiffe_id must be a spiffe:// URI".into(),
            ));
        }
        let actor = spiffe_to_actor_id(spiffe_id)?;
        Ok(self.identity_from(actor, Some("istio".into())))
    }

    pub fn accept_linkerd(&self, client_id: &str) -> Result<ActorIdentity, BridgeError> {
        let suffix = ".serviceaccount.identity.";
        let idx = client_id
            .find(suffix)
            .ok_or_else(|| BridgeError::InvalidInput(format!("not a linkerd client_id: {}", client_id)))?;
        let pre = &client_id[..idx];
        let post = &client_id[idx + suffix.len()..];
        let cluster_local = post
            .strip_suffix(".cluster.local")
            .ok_or_else(|| BridgeError::InvalidInput(format!("not a linkerd client_id: {}", client_id)))?;
        let dot = pre.find('.').ok_or_else(|| {
            BridgeError::InvalidInput(format!("not a linkerd client_id: {}", client_id))
        })?;
        let sa = &pre[..dot];
        let ns = &pre[dot + 1..];
        let actor = format!("tf:actor:service:{}/{}/{}", cluster_local, ns, sa);
        Ok(self.identity_from(actor, Some("linkerd".into())))
    }

    fn identity_from(&self, actor: String, federation: Option<String>) -> ActorIdentity {
        ActorIdentity {
            identity_version: ActorIdentity_IdentityVersion::V1,
            actor_id: actor,
            actor_type: ActorType::Service,
            instance_id: None,
            public_keys: vec![PublicKey {
                key_id: "service-mesh".into(),
                algorithm: "ed25519".into(),
                public_key: "AA==".into(),
                purpose: PublicKey_Purpose::Signing,
                valid_from: None,
                valid_until: None,
            }],
            trust_levels: vec![TrustLevel::T3],
            authority_roots: vec![AuthorityRoot {
                kind: AuthorityRoot_Kind::Federation,
                id: federation.unwrap_or_else(|| "service-mesh".into()),
            }],
            attestations: None,
            valid_from: now_iso8601(),
            valid_until: None,
            revocation_ref: None,
            signature: None,
        }
    }
}

impl Bridge for ServiceMeshBridge {
    fn bridge_id(&self) -> &str {
        &self.cfg.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::ServiceMesh
    }
    fn trust_domain(&self) -> &str {
        &self.cfg.trust_domain
    }
}

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (y, m, d, h, mi, s) = secs_to_ymdhms(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, mi, s)
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
