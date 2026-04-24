# TF-0008: Plugins and Extensions

## Status

Draft.

## Plugin scope

Plugins may implement transport adapters, identity bridges, policy engines, proof backends, approval ceremonies, crypto suites, storage layers, hardware key integrations, AI-agent integrations, device profiles, constrained network profiles, code generation, dashboard modules, and compliance export.

## Plugins as actors

Plugins are first-class actors.

Plugin actor example:

```text
tf:actor:plugin:tf-spiffe-bridge
tf:actor:plugin:tf-lora-transport
tf:actor:plugin:tf-yubikey-approval
```

## Plugin permissions

Plugins must declare what they do, what permissions they need, what data they can see, what trust level they can assert, what proof events they emit, what risks they introduce, and what conformance profile they implement.

## Sandboxing

Plugin sandboxing and least privilege are core.

## Runtimes

Supported plugin runtimes include native Rust and WASM.

WASM is preferred for portable and sandboxed plugins.

Native Rust is needed for high-performance, hardware, crypto, transport, OS-level, and embedded integrations.

## Revocation

Plugins may be revoked like other actors.
