//! TrustForge type bindings and semantic core.
//!
//! Generated wire types live under `generated/`; hand-written semantic
//! helpers live as sibling modules.

#![deny(unsafe_code)]

pub mod generated;

pub mod actor_id;
pub mod approval;
pub mod bridge_did;
pub mod bridge_gnap;
pub mod bridge_matrix;
pub mod bridge_mcp;
pub mod bridge_oauth;
pub mod bridge_service_mesh;
pub mod bridge_spiffe;
pub mod bridge_tls;
pub mod bridge_webauthn;
pub mod bridge_webhook;
pub mod bridges;
pub mod bundle;
pub mod webauthn_attestation;
pub mod canonical;
pub mod capability;
pub mod chain;
pub mod crypto;
pub mod delegation;
pub mod envelope;
pub mod evidence;
pub mod expiration;
pub mod federation;
pub mod format;
pub mod guard;
pub mod instance_id;
pub mod offline_approval;
pub mod packet;
pub mod permission;
pub mod plugin;
pub mod policy_engine;
pub mod profile;
pub mod quorum;
pub mod relay;
pub mod revocation;
pub mod rpc;
pub mod session;
pub mod session_migration;
pub mod tf_manifests;
pub mod trust_domain;
pub mod trust_overlay;
pub mod vault;

pub use actor_id::{actor_id_equals, format_actor_id, parse_actor_id, ActorIdParseError, ParsedActorId};
pub use canonical::{canonicalize, CanonicalJsonError};
pub use capability::{constraints_satisfied, intersect_constraints, EvalContext};
pub use delegation::{walk_chain, WalkResult};
pub use envelope::{validate_envelope_shape, EnvelopeIssue, EnvelopeValidation};
pub use instance_id::{format_instance_id, parse_instance_id, to_actor_id, ParsedInstanceId};
pub use revocation::RevocationIndex;
pub use trust_domain::{parse_trust_domain, trust_domain_equals, ParsedTrustDomain, TrustDomainKind, TrustDomainParseError};
