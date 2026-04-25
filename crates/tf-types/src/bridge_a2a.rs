//! A2A (agent-to-agent) protocol bridge — mirror of TS bridge-a2a.ts.

use crate::bridges::{Bridge, BridgeError, BridgeKind};

#[derive(Clone, Debug)]
pub struct A2AAgentCard {
    pub agent_id: String,
    pub display_name: Option<String>,
    pub public_key_b64: Option<String>,
    pub public_key_algorithm: Option<String>,
    pub capabilities: Vec<A2ACapability>,
    pub trust_domain: String,
}

#[derive(Clone, Debug)]
pub struct A2ACapability {
    pub name: String,
    pub description: Option<String>,
    pub risk: Option<String>,
}

#[derive(Clone, Debug)]
pub struct A2ABridgeConfig {
    pub bridge_id: String,
    pub trust_domain: String,
    pub default_risk: Option<String>,
}

pub struct A2ABridge {
    cfg: A2ABridgeConfig,
}

impl Bridge for A2ABridge {
    fn bridge_id(&self) -> &str {
        &self.cfg.bridge_id
    }
    fn kind(&self) -> BridgeKind {
        BridgeKind::A2a
    }
    fn trust_domain(&self) -> &str {
        &self.cfg.trust_domain
    }
}

#[derive(Clone, Debug)]
pub struct ProjectedActor {
    pub actor_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub capabilities: Vec<(String, String)>, // (action_name, risk)
}

impl A2ABridge {
    pub fn new(cfg: A2ABridgeConfig) -> Self {
        Self { cfg }
    }

    pub fn accept_agent_card(&self, card: &A2AAgentCard) -> Result<ProjectedActor, BridgeError> {
        if card.agent_id.is_empty() || card.trust_domain.is_empty() {
            return Err(BridgeError::InvalidInput(
                "AgentCard missing agent_id or trust_domain".into(),
            ));
        }
        let actor_id = format!("tf:actor:agent:{}/{}", card.trust_domain, card.agent_id);
        let (algorithm, public_key) = match (&card.public_key_b64, &card.public_key_algorithm) {
            (Some(pk), Some(alg)) => (alg.clone(), pk.clone()),
            (Some(pk), None) => ("ed25519".to_string(), pk.clone()),
            _ => (
                "external-attestation".to_string(),
                format!("agent-card:{}", card.agent_id),
            ),
        };
        let mut caps = Vec::with_capacity(card.capabilities.len());
        for c in &card.capabilities {
            let action = a2a_normalise_capability(&c.name, None);
            if !is_valid_action_name(&action) {
                return Err(BridgeError::Rejected(format!(
                    "A2A capability {} does not normalise to a valid action name (got {})",
                    c.name, action
                )));
            }
            let risk = c
                .risk
                .clone()
                .or_else(|| self.cfg.default_risk.clone())
                .unwrap_or_else(|| "R2".to_string());
            caps.push((action, risk));
        }
        Ok(ProjectedActor {
            actor_id,
            algorithm,
            public_key,
            capabilities: caps,
        })
    }
}

/// Mirror of TS `a2aNormaliseCapability`: lowercase, non-alphanumeric
/// runs collapse to `_`, leading/trailing `_` stripped, prepend `a2a.`
/// if no dot is present.
pub fn a2a_normalise_capability(name: &str, prefix: Option<&str>) -> String {
    let mut buf = String::with_capacity(name.len());
    let mut last_underscore = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            buf.push(c.to_ascii_lowercase());
            last_underscore = false;
        } else if !last_underscore {
            buf.push('_');
            last_underscore = true;
        }
    }
    let scrubbed = buf.trim_matches('_').to_string();
    let with_prefix = match prefix {
        Some(p) => format!("{}.{}", p, scrubbed),
        None => scrubbed,
    };
    if with_prefix.contains('.') {
        with_prefix
    } else {
        format!("a2a.{}", with_prefix)
    }
}

fn is_valid_action_name(s: &str) -> bool {
    let mut segs = s.split('.');
    let first = match segs.next() {
        Some(x) => x,
        None => return false,
    };
    if !is_valid_action_segment(first) {
        return false;
    }
    let mut count = 1;
    for seg in segs {
        if !is_valid_action_segment(seg) {
            return false;
        }
        count += 1;
    }
    count >= 2
}

fn is_valid_action_segment(s: &str) -> bool {
    let mut chars = s.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_basic() {
        // dot is non-alphanumeric → collapsed to `_`, then `a2a.` prefix added.
        assert_eq!(a2a_normalise_capability("filesystem.read", None), "a2a.filesystem_read");
        assert_eq!(a2a_normalise_capability("ping", None), "a2a.ping");
        assert_eq!(a2a_normalise_capability("Read File!", None), "a2a.read_file");
        assert_eq!(a2a_normalise_capability("system-info", Some("tools")), "tools.system_info");
    }

    #[test]
    fn accept_agent_card_round_trip() {
        let bridge = A2ABridge::new(A2ABridgeConfig {
            bridge_id: "tf-a2a".into(),
            trust_domain: "example.com".into(),
            default_risk: Some("R2".into()),
        });
        let card = A2AAgentCard {
            agent_id: "code-helper".into(),
            display_name: None,
            public_key_b64: Some("AAAA".into()),
            public_key_algorithm: Some("ed25519".into()),
            capabilities: vec![A2ACapability {
                name: "fs.read".into(),
                description: None,
                risk: None,
            }],
            trust_domain: "example.com".into(),
        };
        let p = bridge.accept_agent_card(&card).expect("project");
        assert_eq!(p.actor_id, "tf:actor:agent:example.com/code-helper");
        assert_eq!(p.capabilities[0].0, "a2a.fs_read");
        assert_eq!(p.capabilities[0].1, "R2");
    }

    #[test]
    fn missing_agent_id_rejected() {
        let bridge = A2ABridge::new(A2ABridgeConfig {
            bridge_id: "tf-a2a".into(),
            trust_domain: "example.com".into(),
            default_risk: None,
        });
        let card = A2AAgentCard {
            agent_id: "".into(),
            display_name: None,
            public_key_b64: None,
            public_key_algorithm: None,
            capabilities: vec![],
            trust_domain: "example.com".into(),
        };
        assert!(bridge.accept_agent_card(&card).is_err());
    }
}
