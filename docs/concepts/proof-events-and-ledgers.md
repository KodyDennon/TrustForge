# Proof Events and Ledgers

> An action without a proof event is an action no one can verify
> later. TrustForge makes "verifiable later" the default.

## What problem this solves

Audit logs in conventional systems are best-effort: an app emits a
log line, ships it to a SIEM, hopes the SIEM keeps it long enough,
and trusts that nobody tampered with it in transit or at rest. When
something goes wrong six months later, the questions investigators
actually need answered are:

- Who acted, and under what *instance* identity?
- Under what *authority* — which delegation chain, which approval?
- Was that authority valid *at the moment of action*?
- Who issued the policy decision that allowed it, and what
  ruleset version was active?
- Has anyone tampered with this log since it was written?

Plain log lines cannot answer most of these without inference. Even
when they can, they have no defence against an attacker who got root
on the log host.

TrustForge replaces "log lines" with **proof events** — signed,
hash-chained records that include the actor, instance, authority,
decision, payload commitment, and time. Events are appended to a
**ledger** that is itself hash-chained, producing tamper-evident
history. The ledger can be local-only, federated, anchored to a
public transparency log, or notarized via RFC 3161 — depending on
profile. See `TF-0005-proof-events-ledgers.md`.

## The shape of a proof event

Every proof event conforms to `schemas/proof-event.schema.json`.
Fields that matter:

- **event_id** — unique within the ledger.
- **prev_hash** — hash of the previous event in the chain.
- **event_type** — e.g. `session.opened`, `capability.granted`,
  `policy.decision`, `approval.granted`, `action.executed`,
  `revocation.issued`, `proof.anchored`.
- **actor** and **instance** — who/what acted.
- **trust_domain** — the interpretation context.
- **authority** — pointer to the capability / delegation /
  approval that authorized the event.
- **payload_commitment** — hash of the affected payload (file
  contents, RPC body, …) when applicable. The hash is sufficient
  for verification without the body itself.
- **proof_level** — `L0`–`L5` (see `docs/concepts/proof-levels-
  l0-to-l5.md`).
- **timestamp** — wall-clock plus monotonic anchor.
- **signature** — ed25519 by default, optionally hybrid PQ.
- **anchor** — optional pointer to an external anchor (RFC 3161
  TSA, RFC 6962 CT log, blockchain, …).

The signing key is the *actor instance's* key, not a shared service
key. This is the load-bearing property: an event is verifiable
without trusting the daemon that hosted it. Cross-language parity
vectors (`conformance/signature-vectors.yaml`,
`cross-language-signature-vectors.yaml`) ensure the same event
signed by the Rust implementation verifies under the TS one and vice
versa.

## The ledger

A **ledger** is an append-only sequence of proof events. Each event
contains the hash of the previous event, so any tampering breaks the
chain. Ledgers can be:

- **local append-only logs** — `.tflog` files on disk; the
  cheapest mode, fine for home and constrained profiles.
- **organization proof servers** — a daemon that aggregates
  ledgers from many actors in a trust domain.
- **federated proof exchange** — two organizations swap ledger
  segments and verify each other's chains.
- **public transparency logs** — RFC 6962 CT-style monotonic logs.
- **timestamp-authority anchored** — RFC 3161 stamps periodically
  notarize the ledger head, which ties the chain to wall time
  defensibly (the compliance-evidence profile requires this).
- **optional blockchain anchored** — for the Merkle-root-on-chain
  pattern. TrustForge supports this without depending on it.

A **proof bundle** (`.tfbundle`) is a portable subset of a ledger
plus the public keys and authority chains needed to verify it
offline. Bundles are how you hand a verifier a slice of history
that they can check without your daemon being online.

## Worked example

The agent in this repo writes a markdown file. The events emitted
might be:

```text
ev-001  session.opened      actor=human:kody       prev_hash=∅
ev-002  delegation.issued   actor=human:kody       to=agent:code-helper
ev-003  session.opened      actor=agent:code-helper instance=…/sess-A
ev-004  policy.decision     subject=…/sess-A action=fs.write
                            target=docs/foo.md verdict=allow
ev-005  action.executed     subject=…/sess-A action=fs.write
                            target=docs/foo.md
                            payload_commitment=blake3:9c1b…
ev-006  proof.anchored      head_hash=blake3:0fae…
                            anchor=rfc3161:tsa.example/2026-04-25
```

`prev_hash` chains them; the signature on each event covers
`prev_hash`, the body, and the actor's domain-separation tag (see
`ed25519-domain-separation` in `.tf/threat-model.yaml`). A verifier
fed `ev-001..006` plus the actor's public key and the federation
roots can replay the chain, confirm every signature, walk the
authority chain back from `ev-005` to `ev-002` to the human's
authority root, and confirm the payload commitment matches the
file. None of that requires the original daemon to be online.

If the file later changes — say, in `ev-099` — the chain shows
exactly when, by whom, and under what authority. If an attacker
goes back and edits `ev-005`, the change breaks `ev-006`'s
`prev_hash` link and is detected.

## Common misconceptions

**"Proof events are just signed log lines."** They are signed,
chained, and structured. The chain hash is what gives you tamper
evidence; the structure is what makes them verifiable mechanically;
the actor signing is what makes them attributable.

**"Surely this is too expensive for high-volume systems."** Proof
levels exist precisely so you do not pay full cost for every
action. Read-only, low-risk actions can run at L0 (no proof) or L1
(session-only proof). High-risk actions pay for L3+. The policy
controls what gets what.

**"This is blockchain, right?"** It uses *proof-chain* properties
without being a blockchain. There is no token, no consensus, no
mining; the chain is local and signed. Optional public anchoring
lets you tie ledger heads to a public transparency log or an RFC
3161 TSA, but the protocol works fine without that. See "Blockchain-
like properties" in `DECISIONS.md`.

**"If the ledger lives on the same host as the daemon, an attacker
who roots the host can edit it."** They can edit the file, but they
cannot forge the signatures or repair the prev-hash chain without
the actor instance's private key (which lives in the vault, sealed
with Argon2id). And once the head hash has been anchored externally,
any rewrite is detectable by replaying the chain against the anchor.
The compliance-evidence profile requires periodic anchoring for
exactly this reason.

**"Anyone who reads the ledger learns everything."** Payloads are
not in the ledger; only their commitments (hashes) are. To prove a
payload matches a commitment, you reveal the payload separately. The
L4 evidence-bundle format encrypts payloads to a recipient set so
auditors with the right key can open them while general readers
cannot.

**"What about packet mode?"** Proof events generated offline are
batched into proof bundles and sync-merged into the canonical ledger
when the actor reconnects. Sync uses chain-merge rules (per-actor
sub-chains anchored into the global chain at sync time). Constrained
profile (LoRa, sneakernet) explicitly supports this; see
`TF-0011-constrained-offline-profile.md`.

## Where to look next

- `docs/concepts/proof-levels-l0-to-l5.md` — what each level
  guarantees.
- `docs/concepts/policy-decisions.md` — decisions are themselves
  proof events.
- `docs/concepts/sessions-vs-packets.md` — how proofs are emitted in
  each mode.
- `TF-0005-proof-events-ledgers.md` — normative spec.
- `schemas/proof-event.schema.json` and
  `schemas/proof-bundle.schema.json` — wire formats.
- `conformance/chain-vectors.yaml` and
  `conformance/framing-vectors.yaml` — parity vectors.
