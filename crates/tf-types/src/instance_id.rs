//! Instance-URI parser mirroring `tools/tf-types-ts/src/core/instance-id.ts`.

use crate::actor_id::{
    actor_type_to_str, format_actor_id, parse_actor_type, split_scheme, ActorIdParseError,
};
use crate::generated::common::ActorType;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedInstanceId {
    pub actor_type: ActorType,
    pub actor_path: String,
    pub instance_path: String,
    pub raw: String,
}

pub fn parse_instance_id(s: &str) -> Result<ParsedInstanceId, ActorIdParseError> {
    let parts = split_scheme(s).ok_or_else(|| ActorIdParseError::MalformedScheme(s.to_owned()))?;
    if parts.kind != "instance" {
        return Err(ActorIdParseError::WrongKind(parts.kind.to_owned()));
    }
    let actor_type = parse_actor_type(parts.type_segment)
        .ok_or_else(|| ActorIdParseError::UnknownType(parts.type_segment.to_owned()))?;
    let split = parts.path.rfind('/').ok_or(ActorIdParseError::EmptyPath)?;
    if split == 0 {
        return Err(ActorIdParseError::EmptyPath);
    }
    let actor_path = &parts.path[..split];
    let instance_path = &parts.path[split + 1..];
    if actor_path.is_empty() || instance_path.is_empty() {
        return Err(ActorIdParseError::EmptyPath);
    }
    Ok(ParsedInstanceId {
        actor_type,
        actor_path: actor_path.to_owned(),
        instance_path: instance_path.to_owned(),
        raw: s.to_owned(),
    })
}

pub fn format_instance_id(
    actor_type: &ActorType,
    actor_path: &str,
    instance_path: &str,
) -> Result<String, ActorIdParseError> {
    if actor_path.is_empty() || instance_path.is_empty() {
        return Err(ActorIdParseError::EmptyPath);
    }
    Ok(format!(
        "tf:instance:{}:{}/{}",
        actor_type_to_str(actor_type),
        actor_path,
        instance_path
    ))
}

pub fn to_actor_id(instance_id: &str) -> Result<String, ActorIdParseError> {
    let parsed = parse_instance_id(instance_id)?;
    format_actor_id(&parsed.actor_type, &parsed.actor_path)
}
