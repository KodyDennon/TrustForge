//! Actor-URI parser and formatter mirroring `tools/tf-types-ts/src/core/actor-id.ts`.

use crate::generated::common::ActorType;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ActorIdParseError {
    #[error("expected tf:actor:<type>:<path>, got {0:?}")]
    MalformedScheme(String),
    #[error("expected scheme 'tf:actor:', got 'tf:{0}:'")]
    WrongKind(String),
    #[error("unknown actor type: {0}")]
    UnknownType(String),
    #[error("actor id path is empty")]
    EmptyPath,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedActorId {
    pub actor_type: ActorType,
    pub path: String,
    pub raw: String,
}

pub const ACTOR_TYPE_STRS: &[&str] = &[
    "human", "agent", "device", "service", "site", "organization",
    "relay", "plugin", "process", "tool", "model-provider",
    "policy-engine", "proof-anchor", "emergency-authority",
];

pub fn parse_actor_id(s: &str) -> Result<ParsedActorId, ActorIdParseError> {
    let parts = split_scheme(s).ok_or_else(|| ActorIdParseError::MalformedScheme(s.to_owned()))?;
    if parts.kind != "actor" {
        return Err(ActorIdParseError::WrongKind(parts.kind.to_owned()));
    }
    let actor_type = parse_actor_type(parts.type_segment)
        .ok_or_else(|| ActorIdParseError::UnknownType(parts.type_segment.to_owned()))?;
    if parts.path.is_empty() {
        return Err(ActorIdParseError::EmptyPath);
    }
    Ok(ParsedActorId {
        actor_type,
        path: parts.path.to_owned(),
        raw: s.to_owned(),
    })
}

pub fn format_actor_id(actor_type: &ActorType, path: &str) -> Result<String, ActorIdParseError> {
    if path.is_empty() {
        return Err(ActorIdParseError::EmptyPath);
    }
    Ok(format!("tf:actor:{}:{}", actor_type_to_str(actor_type), path))
}

pub fn actor_id_equals(a: &str, b: &str) -> bool {
    match (parse_actor_id(a), parse_actor_id(b)) {
        (Ok(pa), Ok(pb)) => pa.actor_type == pb.actor_type && pa.path == pb.path,
        _ => false,
    }
}

pub(crate) struct SchemeParts<'a> {
    pub kind: &'a str,
    pub type_segment: &'a str,
    pub path: &'a str,
}

pub(crate) fn split_scheme(s: &str) -> Option<SchemeParts<'_>> {
    let rest = s.strip_prefix("tf:")?;
    let first = rest.find(':')?;
    let kind = &rest[..first];
    let remainder = &rest[first + 1..];
    let second = remainder.find(':')?;
    let type_segment = &remainder[..second];
    let path = &remainder[second + 1..];
    Some(SchemeParts { kind, type_segment, path })
}

pub(crate) fn parse_actor_type(s: &str) -> Option<ActorType> {
    Some(match s {
        "human" => ActorType::Human,
        "agent" => ActorType::Agent,
        "device" => ActorType::Device,
        "service" => ActorType::Service,
        "site" => ActorType::Site,
        "organization" => ActorType::Organization,
        "relay" => ActorType::Relay,
        "plugin" => ActorType::Plugin,
        "process" => ActorType::Process,
        "tool" => ActorType::Tool,
        "model-provider" => ActorType::ModelProvider,
        "policy-engine" => ActorType::PolicyEngine,
        "proof-anchor" => ActorType::ProofAnchor,
        "emergency-authority" => ActorType::EmergencyAuthority,
        _ => return None,
    })
}

pub(crate) fn actor_type_to_str(t: &ActorType) -> &'static str {
    match t {
        ActorType::Human => "human",
        ActorType::Agent => "agent",
        ActorType::Device => "device",
        ActorType::Service => "service",
        ActorType::Site => "site",
        ActorType::Organization => "organization",
        ActorType::Relay => "relay",
        ActorType::Plugin => "plugin",
        ActorType::Process => "process",
        ActorType::Tool => "tool",
        ActorType::ModelProvider => "model-provider",
        ActorType::PolicyEngine => "policy-engine",
        ActorType::ProofAnchor => "proof-anchor",
        ActorType::EmergencyAuthority => "emergency-authority",
    }
}
