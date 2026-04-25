# Profiles and Enforcement Levels

> Profiles say "what features are present and required". Enforcement
> levels say "how strictly do we apply them right now". Together they
> let one architecture serve a Raspberry Pi and an enterprise.

## What problem this solves

A single trust architecture has to fit:

- a home automation rig with one operator, no compliance, and
  intermittent connectivity;
- a regulated MSP that ships compliance evidence to auditors;
- a LoRa mesh of battery-powered sensors with 51-byte packets;
- a service mesh enforcing per-RPC authority across thousands of
  pods.

If the spec forces every deployment to ship every feature, the home
case is a nightmare. If the spec leaves features optional with no
discipline, two implementations that both claim "TrustForge" will
not interoperate.

TrustForge resolves this with two orthogonal axes:

- **Profiles** answer "what feature set does this deployment claim
  to support?" They are *static* labels checked at boot
  (`tf-home-compatible`, `tf-enterprise-compatible`,
  `tf-constrained-compatible`,
  `tf-compliance-evidence-compatible`).
- **Enforcement levels** answer "how strictly should we enforce
  policy *right now*?" They are *dynamic* and per-policy
  (`E0`–`E5`, see `docs/concepts/enforcement-levels-e0-to-e5.md`).

A deployment picks a profile to declare its conformance posture.
It picks enforcement levels per-action or per-domain to control
strictness while migrating from observation to enforcement.

## Profiles

The four profiles shipped at v0.1.0 are normatively defined in
`docs/profiles/`:

- **`tf-home-compatible`** — single operator, no federation
  required, simple ceremony types. Floor: E3 / L1.
- **`tf-enterprise-compatible`** — federation, transparency
  anchoring (RFC 6962), quorum, multi-tenant. Floor: E4 / L2.
- **`tf-constrained-compatible`** — LoRa, BLE, serial,
  store-and-forward, offline revocation. Tiny packet support is
  mandatory. Floor: E3 / L1.
- **`tf-compliance-evidence-compatible`** — RFC 3161 anchoring +
  RFC 6962 transparency, encrypted evidence bundles, replay
  timeline reconstruction. Floor: E4 / L3.

Each profile declares a set of MUST features (the daemon refuses
to boot if the deployment cannot provide them), SHOULD features
(strongly recommended), and MAY features (optional). The
conformance suite (`tools/tf-conformance/`) verifies a deployment
meets its claimed profile by running profile-specific test
vectors.

Profiles compose: a deployment can claim multiple profiles
simultaneously (e.g. `tf-enterprise-compatible` and
`tf-compliance-evidence-compatible` together). The intersection of
their MUST sets is the operative floor.

## How profile selection works

In `tf-spec.yaml` (or the daemon config), the operator writes:

```yaml
profile:
  primary: tf-enterprise-compatible
  also: [tf-compliance-evidence-compatible]
```

On boot, the daemon evaluates the profile floor against the active
configuration. If, for example, the compliance-evidence profile
requires RFC 3161 anchoring and the operator did not configure a
TSA, the daemon refuses to start with an explanatory error. This
is the difference between a label and a checkbox: the label is
enforced, not aspirational.

The conformance label runner publishes a signed assertion that
"this deployment, on this commit, ran the test vectors for these
profiles and passed all of them" — useful for downstream consumers
deciding whether to federate.

## Profiles vs. enforcement levels

Profiles are about **capability**: what features exist and work.
Enforcement levels are about **posture**: how strictly we are
applying them today.

A deployment can claim `tf-enterprise-compatible` (so it has
quorum, transparency, …) and run at `E0` (observe-only) while
shadowing an existing system. Once confidence is high, the
operator flips to `E4` and the same deployment now refuses
unauthorized actions. The profile didn't change; the posture did.

See `docs/tutorials/03-flip-to-enforcement.md` for the safe
migration path.

## Worked example

A small MSP is rolling out TrustForge. Their journey:

1. **Day 0** — Pick `tf-home-compatible` for a pilot on the
   technician's laptop. Run at E0/L1 to learn what flows look
   like.
2. **Day 14** — Pilot is stable. Add staging customer environments
   under `northstar.msp/customer/<x>` trust domains. Switch to
   `tf-enterprise-compatible` for federation support; keep E1
   (warn) for staging.
3. **Day 60** — Compliance review approaches. Add
   `tf-compliance-evidence-compatible` to the profile set. The
   daemon refuses to boot until an RFC 3161 TSA is configured;
   the MSP signs up with a TSA, redeploys, daemon starts.
4. **Day 75** — Flip enforcement for production customers from E1
   to E4. Observe-only events stop; real denials fire; the
   compliance evidence bundles begin to accumulate.

At every step the *profile* set tracks "features available"; the
*enforcement* level tracks "how strict we are today".

## Common misconceptions

**"My deployment doesn't need a profile, it's just internal."**
Every deployment has a profile, even if it is `home`. Without one,
downstream consumers cannot tell whether your daemon honours the
features they need. Profiles are also the only mechanism the
conformance suite has to know what to test against.

**"More profiles = more rigorous."** Not exactly. Profiles are
*claims*. Claiming `tf-compliance-evidence-compatible` without
the infrastructure to back it is a configuration error, not extra
rigor — the daemon will refuse to start. Pick the smallest profile
set that matches your deployment's reality.

**"I can extend a profile inline."** You cannot. Profiles are
normative names tied to test vectors. Custom feature combinations
become *plugins* (see `TF-0008-plugins-extensions.md`) or
*overlays* (custom policy on top of a base profile). The label
itself stays standardized.

**"Constrained profile is for IoT only."** Constrained covers
anything with bandwidth, packet-size, latency, or power constraints
— LoRa, serial, BLE, satellite-relayed marine telemetry. It does
not have to be small CPU; it has to be small *transport*.

**"Profiles and enforcement levels are the same thing."** They
are orthogonal. Profile says what you *can* do; enforcement says
what you *will* do. You can be enterprise-profile + E0
(observe-only enterprise) or home-profile + E5 (paranoid home
deployment). The matrix is intentional.

**"Switching profile mid-deployment is risky."** It is, but it is
also designed-for. Profile changes are themselves proof events
(`profile.changed`) and the daemon refuses to relax MUSTs without
explicit operator confirmation. Going *up* (more features) is
common; going *down* requires acknowledging that downstream
consumers may stop federating.

## Where to look next

- `docs/concepts/enforcement-levels-e0-to-e5.md` — the dynamic
  posture axis.
- `docs/profiles/home-profile.md`,
  `docs/profiles/enterprise-profile.md`,
  `docs/profiles/constrained-profile.md`,
  `docs/profiles/compliance-evidence-profile.md` — normative
  profile defs.
- `docs/tutorials/03-flip-to-enforcement.md` — observe → enforce.
- `TF-0010-conformance-governance.md` — how labels are assigned.
- `tools/tf-conformance/` — runner that validates profile
  conformance.
