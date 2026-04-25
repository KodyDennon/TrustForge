# TrustForge Phase 4 — ProofRPC Prototype Design

**Date:** 2026-04-24
**Status:** Draft, approved for implementation planning
**Scope:** Roadmap Phase 4 — schema format, unary request/response, server-streaming model, Rust + TypeScript codegen, capability-bound methods.

## 1. Purpose

Turn a signed, encrypted session into a typed RPC: an actor can call a method on a remote service, the server checks a declared capability before running the method, and a proof event is emitted at the configured level. Clients and servers are generated from a shared `.tfrpc.yaml` service descriptor so neither side invents the wire shape.

## 2. Non-goals

- **No full bidirectional streaming.** Phase 4 supports unary and server-streaming only. Client-streaming and bi-streaming are explicitly deferred.
- **No flow control beyond the underlying session.** The Phase 3 `SessionFrame` sequence-number window is the only ordering guarantee.
- **No alternate codecs.** Canonical JSON in the frame payload only. Protobuf / CBOR is Phase 5+.
- **No retries, deadlines, cancellation protocol.** A client that wants to cancel a stream closes the session.
- **No dynamic service discovery.** Each endpoint knows the service contract statically at build time.
- **No capability runtime**: Phase 4 accepts a capability *name* on each method and consults a caller-supplied `CapabilityEnforcer` trait / callback. Real capability tokens and delegation chains are applied in Phase 6.

## 3. Schema

New JSON Schema: `proofrpc.schema.json` (`.tfrpc.yaml` file format):

```yaml
rpc_version: "1"
service_id: <ServicePascalName>        # e.g. CodeHelper
description: <string>
methods:
  - name: <camelOrSnake>                # e.g. fetchFile
    kind: unary | server-streaming
    description: <string>
    request:  { type: "object", properties: { … }, … }   # an inline JSON Schema
    response: { type: "object", properties: { … }, … }   # ditto; for server-streaming, this is the element type
    capability: <ActionName>            # e.g. file.read
    risk: RiskClass                     # from _common.schema.json
    proof: ProofLevel                   # ditto
    approval: ApprovalRequirement       # ditto; default "none"
```

- `rpc_version` pins schema revision.
- `service_id` is the PascalCase identifier used by codegen.
- `methods[].capability` names the capability required to invoke. The server-side CapabilityEnforcer is given this name plus caller identity and method context; the enforcer returns allow / deny.
- `methods[].request` and `.response` are inline JSON Schema fragments — same draft 2020-12 as the rest of the repo — so the existing schema validator applies.

## 4. Wire protocol on top of Session

Every RPC frame is a `SessionFrame { kind: "data", payload: <RpcFrame> }` where `RpcFrame` is one of:

```ts
type RpcFrame =
  | { kind: "rpc-call";    call_id: string; method: string; request: unknown }
  | { kind: "rpc-response"; call_id: string; status: "ok" | "error"; response?: unknown; error?: RpcError }
  | { kind: "rpc-stream";   call_id: string; seq: number; more: boolean; value?: unknown; error?: RpcError }
```

- `call_id` is a random 16-byte base64 identifier generated client-side per call.
- For unary calls: client sends `rpc-call`, server replies with exactly one `rpc-response`.
- For server-streaming: client sends `rpc-call`, server sends 0..N `rpc-stream { more: true }` followed by exactly one terminal frame — either `rpc-stream { more: false }` (success) or `rpc-stream { more: false, error: ... }` (failure).
- `RpcError` is `{ code: "invalid_argument" | "unauthenticated" | "permission_denied" | "not_found" | "internal", message: string }`.

The session's AEAD + sequence numbers already protect against tamper/reorder; the RPC layer adds no additional integrity.

## 5. Codegen

Extend `tf-schema codegen --target {ts,rust}` to accept `.tfrpc.yaml` inputs alongside `.schema.json`. New targets:

```
tf-schema codegen --target rpc-ts    [--spec path/to/service.tfrpc.yaml] [--out dir]
tf-schema codegen --target rpc-rust  [--spec path/to/service.tfrpc.yaml] [--out dir]
```

Each emits:

- A request/response TS interface or Rust struct per method, generated from the inline JSON Schema via the existing codegen IR.
- A **client** class/struct with one typed async method per entry:
  - Unary: `async fetchFile(req: FetchFileRequest): Promise<FetchFileResponse>` / `async fn fetch_file(req: FetchFileRequest) -> Result<FetchFileResponse, RpcError>`.
  - Server-streaming: returns an `AsyncIterable<FetchFileResponse>` / `impl Stream<Item = Result<FetchFileResponse, RpcError>>`.
- A **server** trait/interface (Rust `trait`, TS `interface`) with the same method set. A `dispatch(frame)` helper drives incoming frames into the right handler.

Both generators reuse the Phase 0/2 hoisting pass so nested request/response objects become named types.

## 6. Runtime

Two hand-written modules, one per language, sitting on top of `SessionState`:

- `tf-types/src/rpc.ts`, `crates/tf-types/src/rpc.rs`:
  - `RpcClient` owns a SessionState + a pending-call map keyed by `call_id`. Typed wrappers on top of `call(method, request)` and `server_stream(method, request)`.
  - `RpcServer` owns a SessionState + a `CapabilityEnforcer` + a dispatch table. `process(frame)` turns an incoming `rpc-call` into a method invocation, validates the request against its schema, runs the capability check, awaits the user's handler, and writes the response frame.
  - `CapabilityEnforcer` is an interface with one method: `check(caller_actor, method_name, capability_name) -> "allow" | { deny: string }`. Phase 4 provides a default always-allow enforcer for demos and a deny-all enforcer for tests.
  - Both client and server emit a `proof-event` stub for every call: a canonical-JSON record `{ type: "rpc.call", method, call_id, caller, result: "ok"|"error" }` that would flow into a `.tflog` in Phase 5+. Phase 4 exposes the record as a callback; it does not write files.

## 7. Cross-language contract tests

A single shared `.tfrpc.yaml` — `examples/proofrpc/code-helper.tfrpc.yaml` — is used from both sides:

1. TS codegen produces TS client + server stubs.
2. Rust codegen produces Rust client + server stubs.
3. `conformance/rpc-vectors.yaml` pins:
   - canonical JSON of one unary request frame,
   - expected response frame,
   - canonical JSON of a server-stream value + terminator frame.
4. Both runtimes assert they produce these exact bytes for the example inputs.

And a live e2e: TS client over tf-session (WebSocket) calling a TS server stub. Same with Rust client → Rust server. The TS-to-Rust round trip over a WebSocket is explicitly a Phase 5 addition (requires a Rust WebSocket carrier crate).

## 8. Repository additions

```
schemas/
  proofrpc.schema.json                 # .tfrpc.yaml service descriptor
  fixtures/proofrpc/valid/basic.yaml
  fixtures/proofrpc/invalid/*.yaml     # missing method, bad risk, etc.

examples/proofrpc/
  code-helper.tfrpc.yaml

tools/tf-schema/src/codegen/
  rpc-model.ts        # walks a .tfrpc.yaml into the shared IR
  rpc-ts.ts           # emits client + server TS
  rpc-rust.ts         # emits client + server Rust

tools/tf-types-ts/src/core/
  rpc.ts              # RpcClient, RpcServer, CapabilityEnforcer

crates/tf-types/src/
  rpc.rs              # RpcClient, RpcServer, CapabilityEnforcer

conformance/
  rpc-vectors.yaml

crates/tf-types/tests/rpc.rs
tools/tf-types-ts/tests/rpc.test.ts
tools/tf-session/tests/rpc-e2e.test.ts   # live TS client ↔ TS server over WebSocket
```

## 9. Phases

1. **S1** — `proofrpc.schema.json` + fixtures; validate-all passes; docs regen.
2. **S2** — rpc runtime (`rpc.ts` + `rpc.rs`): RpcClient, RpcServer, CapabilityEnforcer, RpcFrame wire format. Unary in-memory round-trip tests on both sides.
3. **S3** — server-streaming in both runtimes with in-memory tests.
4. **S4** — RPC codegen (`rpc-ts.ts`, `rpc-rust.ts`) producing typed clients + server traits from `code-helper.tfrpc.yaml`. Generated output committed; generated TS round-trips against the hand-written runtime.
5. **S5** — conformance/rpc-vectors.yaml + parity tests on both sides.
6. **S6** — live end-to-end: TS RPC client over tf-session WebSocket calls a TS server, one unary + one server-streaming method.
7. **S7** — CI + final sweep.

## 10. Done criteria

- `bun test` and `cargo test --workspace` stay green.
- A unary RPC call + response round-trips in both runtimes, in-memory, with the canonical-JSON body matching the pinned vectors.
- A server-streaming call delivers N elements followed by a terminal frame in both runtimes.
- A TS RPC client talks to a TS RPC server over the actual tf-session WebSocket carrier end-to-end.
- The CapabilityEnforcer contract is exercised: a deny-all enforcer rejects calls with `permission_denied`.
- `tf-schema codegen --target rpc-ts --spec code-helper.tfrpc.yaml` produces deterministic output; CI's codegen-diff gate includes it.
