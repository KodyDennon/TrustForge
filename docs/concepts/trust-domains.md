# Trust Domains

> A trust domain is the *context* that decides what an authority claim
> means.

## What problem this solves

The same string — "alice@example.com" — can mean three different
things in three different contexts: the user inside Example Corp's
SSO; an external collaborator on a federated project; a customer
reaching in from the public internet. Conventional auth systems
either ignore the distinction (and grant Alice the same authority in
all three) or hard-code separate identity providers per surface (and
duplicate every policy three times).

TrustForge introduces a first-class concept — the **trust domain** —
that captures *where the authority claim is being interpreted*.
Authority always travels with its domain. Two actors with identical
URIs but different domains are different principals. A federation
between domains is an explicit, signed event, not an accident of
shared usernames.

This buys you four things:

1. **Multi-tenancy without tenant-prefix accidents.** Two tenants
   can both have an actor named `agent/build-bot`; they are
   `tenant-a:trustforge.dev/agent/build-bot` and
   `tenant-b:trustforge.dev/agent/build-bot`, and policy applies
   independently.
2. **Federation that is auditable.** Every cross-domain authority
   transfer is a signed `federation-attestation` proof event
   (see `schemas/federation-attestation.schema.json`).
3. **Local-first deployments that can later federate.** A home
   deployment lives in its own domain; if the user later joins an
   org, the org's domain federates *in*, rather than the home
   identity getting silently overwritten.
4. **Compromise containment.** A compromised peer trust domain
   cannot forge authority inside another domain. Federation is
   mediated by pinned issuer keys (the `federation-issuer-key-verify`
   mitigation in `.tf/threat-model.yaml`).

## The distinction

Every TrustForge artefact — actor URI, capability, proof event,
session, packet — carries an explicit `trust_domain` field. Examples:

- `home.local` — single-operator home deployment.
- `trustforge.dev` — the project's own dogfood domain (you can see
  it in `.tf/agent-contract.yaml` and `.tf/policy.yaml`).
- `acme.corp` — an enterprise.
- `acme.corp/eu` — sub-domain for an EU subsidiary with stricter
  policy.
- `public.tf` — a public federation (e.g., for relay marketplaces).

Domains can be hierarchical (`acme.corp` → `acme.corp/eu`). They can
be private to a deployment, scoped to an organization, or public.
The choice is encoded in `tf-spec.yaml` and the daemon's profile.

A trust domain owns:

- A set of **authority roots** (CA, federation key, hardware
  manufacturer attestation, transparency anchor). See "Authority
  model" in `DECISIONS.md`.
- A **policy bundle** (`policy.yaml`, Cedar, Rego, native).
- A **conformance profile** (home / enterprise / constrained /
  compliance-evidence — see `docs/profiles/`).
- A **proof ledger** (or set of ledgers).

## Worked example

A small MSP, `northstar.msp`, runs TrustForge for itself and for
each of its customers. The deployment looks like this:

```text
trust domain:    northstar.msp
  ├── actor:    tf:actor:human:northstar.msp/alice
  ├── actor:    tf:actor:service:northstar.msp/dispatch
  └── policy:   "MSP staff may approve customer support sessions"

trust domain:    northstar.msp/customer/acme
  ├── actor:    tf:actor:human:northstar.msp/customer/acme/bob
  ├── actor:    tf:actor:device:northstar.msp/customer/acme/router-01
  └── policy:   "Tickets escalate to MSP staff after 30 minutes"

trust domain:    acme.corp   (Acme's own domain)
  └── federation-attestation: "northstar.msp/customer/acme is delegated
     read-only telemetry access from acme.corp until 2027-01-01"
```

When Alice (an MSP technician) opens a support session into Bob's
laptop, three trust domains touch the session:

1. `northstar.msp` — Alice's authority origin.
2. `northstar.msp/customer/acme` — the scoped customer domain that
   says "Alice may act on Acme's gear under the support agreement".
3. `acme.corp` — Acme's own domain, which signed the federation
   attestation that allows Alice's authority to be honoured at all.

The proof event records all three. If Acme later revokes the
federation attestation, the `northstar.msp/customer/acme` scope is
unaffected for *future* purposes (the MSP still has internal records
of past work) but Alice can no longer perform new authoritative
actions inside `acme.corp`-rooted infrastructure.

## Common misconceptions

**"A trust domain is just a tenant ID."** It is more than that. A
tenant ID is a label; a trust domain carries authority roots, policy,
ledgers, and federation state. Two trust domains can share a tenant
label but have completely different policy regimes — that is by
design.

**"My deployment only has one domain, so I can ignore the field."**
You should still set it. Future-you, when you need to federate or
spin up a per-customer subdomain, will thank present-you for not
having to retro-fit `trust_domain` everywhere. The schemas already
require it.

**"Federation means trusting another domain's policy."** It does
not. Federation means *importing specific authority claims* from
another domain after they have been signed and pinned. The
importing domain still applies its own policy. A federated peer
cannot say "Alice is now an admin of your domain"; it can only say
"this is a signed claim that Alice has authority X in our domain;
you decide whether to honour it for action Y." The pinned-issuer-key
check (see `federation-issuer-key-verify` in
`.tf/threat-model.yaml`) is the safety net.

**"Trust domains and DNS domains are the same thing."** They are
related but not equivalent. A trust domain often *uses* DNS for
naming (because DNS is the most widely deployed naming system on
earth), but a trust domain can be a key fingerprint, a SPIFFE
identity, a UUID, or anything that satisfies the URI grammar. A
deployment with no DNS at all (an air-gapped LoRa mesh) has trust
domains, just not DNS-named ones.

**"Once I pick a domain I'm stuck with it forever."** Domains can be
renamed, but renaming is a federation operation: the old domain
issues a federation attestation that says "actors in `old-name` are
now `new-name`", verifiers cross-check, and ledgers record the
rename so old proofs are still verifiable. See
`docs/tutorials/16-federate-two-trust-domains.md`.

## Where to look next

- `docs/concepts/federation-and-bridges.md` — how cross-domain trust
  is brokered.
- `docs/concepts/profiles-and-enforcement-levels.md` — how a domain
  picks its conformance posture.
- `docs/profiles/home-profile.md` and
  `docs/profiles/enterprise-profile.md` — concrete domain templates.
- `schemas/federation-attestation.schema.json` — wire format for
  cross-domain authority transfer.
- `.tf/agent-contract.yaml` — see `trust_domain: "trustforge.dev"` in
  action.
