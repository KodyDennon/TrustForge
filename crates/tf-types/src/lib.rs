//! TrustForge type bindings and semantic core.
//!
//! Generated wire types live under `generated/`; hand-written semantic
//! helpers live as sibling modules.

#![deny(unsafe_code)]

pub mod generated;

pub mod actor_id;
pub mod canonical;
pub mod capability;
pub mod delegation;
pub mod envelope;
pub mod instance_id;
pub mod revocation;
pub mod trust_domain;

pub use actor_id::{actor_id_equals, format_actor_id, parse_actor_id, ActorIdParseError, ParsedActorId};
pub use canonical::{canonicalize, CanonicalJsonError};
pub use capability::{constraints_satisfied, intersect_constraints, EvalContext};
pub use delegation::{walk_chain, WalkResult};
pub use envelope::{validate_envelope_shape, EnvelopeIssue, EnvelopeValidation};
pub use instance_id::{format_instance_id, parse_instance_id, to_actor_id, ParsedInstanceId};
pub use revocation::RevocationIndex;
pub use trust_domain::{parse_trust_domain, trust_domain_equals, ParsedTrustDomain, TrustDomainKind, TrustDomainParseError};
