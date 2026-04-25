//! TrustForge type bindings and semantic core.
//!
//! Generated wire types live under `generated/`; hand-written semantic
//! helpers live as sibling modules.

#![deny(unsafe_code)]

pub mod generated;

pub mod actor_id;
pub mod canonical;
pub mod instance_id;
pub mod trust_domain;

pub use actor_id::{actor_id_equals, format_actor_id, parse_actor_id, ActorIdParseError, ParsedActorId};
pub use canonical::{canonicalize, CanonicalJsonError};
pub use instance_id::{format_instance_id, parse_instance_id, to_actor_id, ParsedInstanceId};
pub use trust_domain::{parse_trust_domain, trust_domain_equals, ParsedTrustDomain, TrustDomainKind, TrustDomainParseError};
