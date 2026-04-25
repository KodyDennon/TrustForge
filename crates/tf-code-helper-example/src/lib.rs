//! Downstream crate that compiles the RPC codegen output against the real
//! tf-types public API.
//!
//! This exists so the `tf-schema codegen --target rpc-rust` output is not
//! just a dead file in the repo: every `cargo check --workspace` compiles
//! the generated bindings, and the codegen-diff gate in CI fails if
//! regeneration would change them.

pub mod generated;

pub use generated::*;
