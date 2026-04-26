# Threat model

This page is the long-form narrative of
[`../../.tf/threat-model.yaml`](../../.tf/threat-model.yaml). The YAML
is the source of truth — schema-validated, referenced from
`.tf/agent-contract.yaml`, and consumed by the conformance runner.
This page exists so that the threat model is readable end-to-end.

A boundary-focused, diagrammatic version of the same model lives in
[`../architecture/threat-boundaries.md`](../architecture/threat-boundaries.md).
Read both: this page narrates the threats; that page anchors them on
the boundary diagram.

## Scope

TrustForge v0.1.0 reasons about:

- A repo and project under active development.
- A daemon (`tools/tf-daemon`) that holds long-term keys behind a
  vault and serves an admin HTTP endpoint.
- Plugins (`tools/native/`, WASM modules under
  `crates/tf-core-wasm`) that run with reduced capability.
- Federated peers — separate trust domains we have explicitly
  shaken hands with.
- AI agents acting under `.tf/agent-contract.yaml`.
- Live and packet sessions across actor instances.

Out of scope (residual risks the maintainers accept) are listed at
the bottom.

## Adversaries

The YAML enumerates six adversary classes, with `capability_levels`
drawn from `[opportunistic, targeted, ai-assisted, insider,
nation-state]`.

1. **External attacker** — unauthenticated network attacker probing
   public surfaces and published artefacts.
2. **Malicious dependency** — a poisoned upstream package or
   typosquat that runs inside builds, contributor machines, and CI.
3. **Rogue AI agent** — a locally-running AI coding agent under
   `.tf/agent-contract.yaml` whose prompt context has been
   manipulated, or whose model has been induced to escalate.
4. **Compromised peer** — a federated TrustForge peer whose
   long-term keys leaked or whose operator turned hostile.
5. **Insider contributor** — a contributor or maintainer with
   commit and signing access acting in bad faith or on a
   compromised workstation.
6. **Nation-state** — well-resourced adversary with hardware,
   transparency-anchor, registry-infrastructure, and side-channel
   capabilities.

## Trust boundaries (the nine assets)

Each boundary is one `assets[]` entry in the YAML. The risk class
follows TF-0004 R0–R5; see
[`../concepts/risk-classes-r0-to-r5.md`](../concepts/risk-classes-r0-to-r5.md).

| Boundary | Class | Owner / control point |
|---|---|---|
| `ci.build.pipeline` | R4 | GitHub Actions, signing keys, artefact signer. |
| `supply.chain` | R4 | Bun + Cargo lockfiles, registry mirrors, dependency review. |
| `host.filesystem` | R3 | The daemon and AI agents' file access. |
| `daemon.admin.endpoint` | R5 | UDS or loopback HTTP that grants vault unlock, policy reload, key rotation. |
| `plugin.sandbox` | R3 | OS sandbox profile in plugin manifest. |
| `vault.passphrase` | R5 | Argon2id-stretched secret unlocking long-term keys. |
| `federation.peer` | R4 | Pinned issuer key set per federated domain. |
| `transparency.anchor` | R4 | Append-only log relied on by downstream verifiers. |
| `agent.to.agent.session` | R4 | Live + packet session boundary. |

## The 24 threats, in narrative form

Threats are grouped by the boundary they cross. Each entry names the
mitigations from the YAML; a `(planned)` marker means the mitigation
is documented and scheduled but not yet implemented in 0.1.0.

### Build and supply chain

**`supply-chain-compromise`** — A poisoned upstream pushes a release
that lands in our build. Mitigated by pinning all transitive
dependencies and requiring maintainer review for new additions
(`dependency-pinning-and-review`). Schema strictness
(`schema-strict-additional-properties`) rejects bundle and tool
descriptors that smuggle extra fields.

**`dependency-typosquat`** — A typosquat package gets installed in
CI or a contributor's machine. Same mitigation
(`dependency-pinning-and-review`); the dependency surface is small
and reviewed.

### Vault

**`vault-passphrase-brute-force`** — Captured vault file decrypted
offline. Mitigated by Argon2id with embedded parameters
(`argon2id-vault-kdf`); raises offline brute-force cost beyond
commodity GPU economics.

**`vault-tamper`** — Partial-write or in-place vault modification.
Mitigated by atomic-persist (write-temp + fsync + rename) plus
integrity tag verified on load (`vault-atomic-persist`).

### Daemon admin endpoint

**`daemon-admin-token-theft`** — Bearer admin token reused from
another process or after rotation. Planned mitigation
(`daemon-admin-token-binding`) ties tokens to UDS peer-credential
or loopback origin plus a short TTL.

**`regex-dos-in-policy-engine`** — Pathological regex stalls the
daemon. Mitigated by bounded compile size, linear-time matchers
where available, and per-evaluation timeouts
(`regex-dos-prevention`).

### Plugin sandbox

**`plugin-sandbox-escape`** — Plugin code reaches host capabilities
not declared in its manifest. Planned mitigation
(`plugin-sandbox-capability-gate`) enforces the manifest's OS-level
sandbox profile and routes host capabilities through ProofRPC.

### Agent-to-agent session

**`ed25519-forgery-via-key-reuse`** — Same key signs different object
classes without domain separation. Mitigated by per-class domain
tags (`ed25519-domain-separation`).

**`replay-attack`** — Captured frame or packet replayed. Mitigated by
audience-bound capability tokens (`capability-token-aud-bind`) and
clock-skew tolerance (`clock-skew-tolerance`).

**`aead-nonce-reuse`** — XChaCha20-Poly1305 key+nonce reuse. Planned
mitigation (`aead-nonce-discipline`) enforces random nonces or
strict per-direction counters and rejects reuse at the framing
layer.

**`time-skew-clock-attack`** — Clock manipulation widens validity
windows. Mitigated by bounded skew (default 60s) and rejection of
far-future / out-of-window tokens (`clock-skew-tolerance`).

**`capability-inflation`** — Issued capability widened by a glob
trick. Mitigated by glob escape on action targets
(`glob-escape-on-action-targets`), audience binding
(`capability-token-aud-bind`), and negative-capability precedence
(`negative-capability-precedence`).

**`negative-capability-bypass-via-glob`** — Caller-controlled input
sneaks past `deny_targets`. Same mitigation as inflation.

**`webauthn-assertion-replay`** — Assertion captured at one origin
replayed at another. Planned mitigation
(`webauthn-challenge-binding`) binds assertions to a fresh
challenge, origin, and RPID.

**`relay-forwarding-authority-confusion`** — Relay's forwarding token
used as if it carried action authority. Mitigated by a separate
`relay-authority` token; action authority is checked separately at
the destination (`relay-forwarding-authority-split`).

### Federation peer

**`federated-peer-compromise`** — Peer's long-term keys leak.
Mitigated by pinned issuer key sets with explicit `kid` binding;
unknown or rotated keys are refused until the operator
acknowledges the rotation (`federation-issuer-key-verify`).

**`oauth-issuer-spoof`** — Attacker impersonates a trusted OAuth
issuer. Same mitigation.

**`spiffe-federation-poisoning`** — Bad SPIFFE bundle accepted.
Same mitigation plus SPIFFE-bridge schema strictness.

**`certificate-chain-bypass`** — TLS chain validation skipped or
weakened. Planned mitigation (`tls-and-ocsp-pinning`) requires
TLS with pinned issuer chains and stapled OCSP responses.

**`ocsp-stapling-tamper`** — Staple replaced with stale or
attacker-controlled value. Same mitigation.

**`mcp-tool-list-spoof`** — Extra fields injected in an MCP tool
list. Mitigated by `additionalProperties: false` on every schema
(`schema-strict-additional-properties`).

**`a2a-agentcard-impersonation`** — Fake A2A AgentCard accepted.
Same mitigation.

### Transparency anchor

**`transparency-anchor-takeover`** — A single anchor compromised and
used to rewrite history. Planned mitigation
(`transparency-anchor-pinning`) cross-checks inclusion proofs
against a pinned anchor set.

### AI agent

**`ai-agent-prompt-injection`** — Prompt context manipulated to make
the agent escalate. Mitigated by negative-capability precedence
(`negative-capability-precedence`); an explicit `forbidden:` entry
in the agent contract cannot be overridden by prompt content.
Combined with the AI-agent contract review process described in
[`../ai-implementation.md`](../ai-implementation.md).

## Mitigation status summary

The YAML lists 18 mitigations. As of 0.1.0:

- **Implemented**: argon2id-vault-kdf, vault-atomic-persist,
  glob-escape-on-action-targets, regex-dos-prevention,
  federation-issuer-key-verify, schema-strict-additional-properties,
  capability-token-aud-bind, negative-capability-precedence,
  ed25519-domain-separation, clock-skew-tolerance,
  dependency-pinning-and-review,
  relay-forwarding-authority-split.
- **Planned**: aead-nonce-discipline, transparency-anchor-pinning,
  plugin-sandbox-capability-gate, daemon-admin-token-binding,
  webauthn-challenge-binding, tls-and-ocsp-pinning.

Profile MUST features only count `implemented` items; `planned`
items are advisory until they ship and are tested in the
conformance suite.

## Residual risks (accepted)

These six gaps are explicitly out of scope for v0.1.0. Each has an
`accepted_by` and `accepted_at` field in the YAML
(`tf:actor:human:trustforge.dev/maintainers`,
`2026-04-25T00:00:00Z`):

1. **Compromised host kernel** — a privileged attacker on the same
   machine can read TrustForge memory, ptrace the daemon, or tamper
   with `.tf/` files.
2. **Compromised TPM / HSM** — if the hardware key store lies,
   signing and sealing collapse. No remote attestation of the TPM
   itself in 0.1.0.
3. **Physical key extraction** — sustained physical access can
   extract long-term private keys despite vault sealing.
4. **Side-channel leakage** — timing, power, EM side channels in
   upstream crypto libraries are not independently audited; we rely
   on upstream review.
5. **Malicious browser** — a compromised browser can scrape WebAuthn
   UI, exfiltrate cookies, and approve attacker-chosen capabilities.
6. **Malicious LSP / IDE** — a hostile editor extension can
   synthesise plausible TrustForge actions the user accepts without
   review.

If a deployment must close one of these, the route is a custom
profile under [`../profiles/`](../profiles/) plus an ADR.

## Reading the YAML

The YAML schema is `schemas/threat-model.schema.json`. Every change
to the YAML must validate against the schema and pass the
`tf-conformance run` pipeline. Treat this page as a derivative work;
when the YAML changes, update this page in the same PR.
