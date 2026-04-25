# Relays as First-Class Actors

> A relay is a citizen, not a pipe. It has identity, authority,
> reputation — and forwarding power that is **strictly separate** from
> action power.

## What problem this solves

Conventional networking gives relays no identity worth speaking of.
A SOCKS proxy is anonymous; a Tor relay is pseudonymous; a queue
broker has credentials but no externally visible identity beyond
"talks the protocol". When a relay misbehaves — drops priority
packets, replays old packets, forwards revocation messages slowly —
you have no signed record to point at, and you have no way to
revoke that *one* relay without breaking every consumer.

Worse, a lot of systems conflate "this relay forwarded a request"
with "this relay endorsed the request". So if an attacker gets
control of a relay, they can sometimes cause downstream actors to
treat the relayed request as if it had relay authority — even when
the relay was never supposed to be able to authorize anything.

TrustForge fixes both by making relays first-class actors with
their own URIs, keys, and capabilities — *and* by enforcing a hard
split between **forwarding authority** and **action authority**. A
relay can carry a packet without ever being able to read,
authorize, or execute it.

## Relay identity

A relay's actor URI looks like:

```text
tf:actor:relay:public/relay-8841
tf:actor:relay:northstar.msp/lora-gateway-rig-A
tf:actor:relay:home.local/usb-drop-relay-1
```

A relay has all the things any actor has (`docs/concepts/actors-vs-
instances.md`):

- an actor URI and one or more instance URIs (for restarted
  daemons, replicas, firmware upgrades);
- a long-term ed25519 key and a vault to seal it;
- a trust level (often T2 or T3 for org-run relays, T1 for
  self-claimed public ones);
- proof obligations (every forward is logged);
- a revocation state.

Relays declare what they will and will not forward. A typical
declaration:

```yaml
relay:
  actor: tf:actor:relay:northstar.msp/lora-gateway-rig-A
  forwards:
    - audience_pattern: "tf:instance:device:northstar.msp/customer/acme/*"
      max_priority: P1
      max_packet_bytes: 256
    - audience_pattern: "tf:actor:human:northstar.msp/*"
      max_priority: P3
  rate_limits:
    per_actor: 10/min
    p0_per_hour: 5
  proof_emit:
    forward_logged_at: L1
```

This relay forwards small packets to the customer-acme device set,
forwards human messages at higher priority, and rate-limits to keep
abuse contained. Each forward emits an `relay.forwarded` proof
event recording the relay instance, the packet hash, the source
audience, and the destination audience.

## Forwarding authority vs. action authority

This is the load-bearing rule: **forwarding authority and action
authority are separate capabilities.**

A relay holds:

- a **`relay-authority` token** that authorises it to forward
  certain packets to certain audiences for a certain time. Without
  this, no destination accepts forwarded packets from this relay.
- *no* implicit action authority. Even if every customer device
  trusts this relay to deliver firmware-update packets, the relay
  cannot itself originate a firmware-update packet. Origination
  requires the customer's signing authority, full stop.

The mitigation is captured in `.tf/threat-model.yaml`:

```yaml
- id: relay-forwarding-authority-split
  applies_to:
    - agent.to.agent.session
    - relay-forwarding-authority-confusion
  description: >-
    Relay actors carry a `relay-authority` token that authorises
    forwarding only; action authority is checked separately at the
    destination, so a relay cannot confuse forwarding with
    execution rights.
  status: implemented
```

Two parity vectors exercise this:
`conformance/relay-forwarding-vectors.yaml` confirms that across
languages, a relay-authority token never satisfies an
action-authority check, and vice versa.

## Worked example

Imagine a delegated-approval flow with a public relay:

```text
human:kody  →  packet  →  relay:public/relay-8841  →  device:home.local/router-01
```

The packet is encrypted to `device:home.local/router-01`'s key.
`kody` signs the packet body. The relay receives the packet, sees:

- the packet's destination audience is `device:home.local/router-01`;
- the packet's priority is P1 (revocation update);
- the relay's relay-authority lists `home.local/*` audiences with
  max priority P1 — fine, forward.

The relay records a `relay.forwarded` proof event. The relay
**cannot** decrypt the packet — the AEAD key is derived for the
destination device only. The relay **cannot** modify the packet —
the body is signed by `kody`. The relay **cannot** spoof a
similarly-shaped packet signed as `kody` — it does not have
`kody`'s key.

The router receives the packet. Its action-authority check sees:

- packet signed by `kody`;
- `kody` has authority to issue revocation packets to this device
  (per the device's pinned authority root);
- relay-forwarding metadata is *informational* — the router does
  not derive any authority from the relay's identity.

If the relay were compromised and tried to inject its own
firmware-update packet signed as the relay, the router would reject
it because relays do not hold firmware-update authority over
devices.

## Reputation and revocation

Relays accumulate reputation over time:

- forward latency and reliability;
- dropped or reordered priority packets;
- attempted replays;
- abuse rate-limit hits.

Relays can be revoked the same way any actor can be (see
`docs/concepts/offline-revocation-lists.md`). A revoked relay still
exists physically, but its `relay-authority` token is invalidated
and downstream actors stop accepting forwarded packets from it.
Multi-path mesh designs route around revoked relays automatically.

## Common misconceptions

**"A relay must see the packet contents to forward intelligently."**
For most policies, no. The relay needs *audience* (so it can route)
and *priority class* (so it can schedule). Both are
authenticated metadata outside the AEAD-protected body. Some
constrained transports (LoRa) put both in the unencrypted header.
Body confidentiality is preserved.

**"If I run my own relay, I can give it broad authority for
convenience."** You can — but the cost is that compromise of the
relay compromises every authority it holds. Default design:
relays have *only* forwarding authority. If you find yourself
wanting to grant action authority to a relay, ask whether a
co-located action-bearing actor with separate keys would do.

**"Relays can drop priority packets to deny service."** They can,
and that is why packet expiry, multi-path routing, and emergency
priority classes (P0) exist. Repeated drops of P0/P1 packets are
themselves proof events that feed reputation scoring. Mesh design
in TF-0011 (`docs/specs/TF-0011-constrained-offline-profile.md`)
includes redundancy guidelines.

**"I can only run relays on the public internet."** Relays run
anywhere: a USB-stick relay (sneakernet), a BLE relay (proximity
mesh), a serial relay (industrial protocols), a LoRa gateway, an
in-organization message bus. The *abstraction* is the same; the
transport differs.

**"Relays are optional."** They are optional in single-host
deployments. They become essential the moment you have offline
audiences, mesh routing, store-and-forward, or air-gapped delivery.
They are also useful as policy enforcement points: a relay can
refuse to forward packets that violate transport-level policy
(rate limits, priority caps) before they ever reach the
destination.

## Where to look next

- `docs/concepts/sessions-vs-packets.md` — what relays move.
- `docs/concepts/offline-revocation-lists.md` — revoking a relay.
- `docs/topologies/mesh-of-relays.md` — multi-relay deployment.
- `docs/topologies/edge-mesh-lora.md` — LoRa relay topology.
- `TF-0003-proofwire-transport.md` — relay model.
- `conformance/relay-forwarding-vectors.yaml` — parity vectors.
