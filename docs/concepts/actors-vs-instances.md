# Actors vs. Actor Instances

> "Who is acting?" is two questions. TrustForge insists on answering
> both.

## What problem this solves

Every existing authentication system collapses identity into a single
abstraction: a "user", a "service account", a "client". That works
when the thing being authenticated is stable — a human at a keyboard,
a long-lived daemon, a registered app.

It breaks the moment you have to reason about:

- An AI coding agent named `code-helper` that runs in **three
  different sessions** on three different laptops, possibly at the
  same time. Two of them are doing safe work; one of them has been
  prompt-injected and is trying to delete files.
- A microservice that is replicated **fifty times** behind a load
  balancer. One replica's process memory was just dumped by a kernel
  exploit; you need to revoke that *one replica's* keys without
  taking down the other forty-nine.
- A relay that has been running for six months and has now been
  re-flashed with a new firmware. The actor is the same; the running
  software is not.

If you only have one identifier, you cannot revoke "the compromised
session of the agent" without revoking "the agent" — which kills the
forty-nine other innocent replicas too. So TrustForge separates the
two from day one.

## The distinction

An **actor** is the named entity that authority is granted to. It is
stable, long-lived, and addressable across deployments. Actor URIs
look like:

```text
tf:actor:human:example.com/kody
tf:actor:agent:example.com/code-helper
tf:actor:service:spiffe/example.org/ns/prod/sa/api
tf:actor:relay:public/relay-8841
tf:actor:device:honesttechservices.com/backup-box-01
```

An **actor instance** is one specific running process, session,
replica, browser tab, container, or device boot of that actor.
Instance URIs extend the actor URI with a path that the operator
chooses:

```text
tf:instance:agent:example.com/code-helper/macbook/session-9912
tf:instance:service:spiffe/example.org/ns/prod/sa/api/replica-7
tf:instance:device:honesttechservices.com/backup-box-01/boot-2026-04-25
```

Both halves carry their own keys. Both halves are independently
revocable. Authority can be granted to either:

- "Agent `code-helper` may read `**/*.md`" — applies to every
  instance of that agent.
- "Instance `code-helper/macbook/session-9912` may also write
  `src/auth.rs` until 14:30" — applies to *only that running
  session*; if the user opens a second editor tab, that tab does not
  get the elevated grant.

See `TF-0002-actor-identity.md` for the URI grammar and
`crates/tf-types/src/actor_id.rs` (and its TS twin
`tools/tf-types-ts/src/core/actor-id.ts`) for the canonical
implementation, including the key-derived form
`tf:actor:process:key/<thumbprint>` that the daemon hands to
AgentGuard.

## Worked example

A developer named `kody` runs Claude Code in two terminals. Both
sessions log in as the agent actor `tf:actor:agent:example.com/code-
helper`. Each terminal handshake mints a fresh instance URI:

```text
session A: tf:instance:agent:example.com/code-helper/laptop/session-A
session B: tf:instance:agent:example.com/code-helper/laptop/session-B
```

Kody opens a PR review in session A and approves the agent to write
`docs/**/*.md`. Policy issues a capability bound to session A's
instance URI:

```yaml
capability:
  subject: tf:instance:agent:example.com/code-helper/laptop/session-A
  action: fs.write
  target_pattern: "docs/**/*.md"
  expires_at: 2026-04-25T18:00:00Z
```

In session B, the same agent (same actor URI!) tries to write a
markdown file. AgentGuard checks the capability — the subject is the
session-A instance URI, not session-B's — and **denies** the write,
even though the actor is identical. The denial is a proof event of
type `capability_denied` (see `TF-0005-proof-events-ledgers.md`).

If session A is compromised mid-task, kody can revoke
`tf:instance:agent:example.com/code-helper/laptop/session-A`. The
agent itself, and session B, keep working.

## Common misconceptions

**"Surely the actor is enough; instances are an implementation
detail."** No. The whole point of TrustForge is to make
authority-bearing distinctions visible in proof events and
revocations. An attacker who steals an actor-level grant can run it
from anywhere; an attacker who steals an instance-level grant can run
it only from the session it was bound to, and that binding is
verifiable cryptographically (`capability-token-aud-bind` mitigation
in `.tf/threat-model.yaml`).

**"Can I just use the actor URI for everything if I'm not running
AI?"** You can — TrustForge will not force instance binding on a
profile that does not need it. But the moment you have replicas, hot
spares, multi-tab browser sessions, or any other "same actor, several
running copies" situation, you will need instance URIs to revoke
surgically. Designing them in from the start costs nothing; bolting
them on later is painful.

**"Instances must be globally unique forever."** They do not. An
instance is meaningful for the lifetime of the running thing it
identifies plus a retention window. After expiry, the URI may be
reissued. What must not be reissued is the **keys** — every
instance gets fresh per-instance signing material, and old material
is destroyed when the instance ends.

**"Models are actors too, right?"** No — by default. A model is
provenance metadata recorded alongside the action, not an
authority-bearing actor. The agent or runtime that *invoked* the
model is the responsible actor. A model-serving system *can* be an
actor in its own right when it independently holds authority (e.g.,
an OpenAI-style cloud service signing requests with its own key);
that case is explicit, not the default. See "Model identity" in
`DECISIONS.md`.

## Where to look next

- `docs/concepts/delegation-chains.md` — how actor and instance URIs
  appear in delegation paths.
- `docs/concepts/continuous-authorization.md` — how live sessions
  re-check both halves on every relevant event.
- `docs/concepts/agent-contracts-for-ai.md` — how AI agents request
  per-instance authority dynamically.
- `TF-0002-actor-identity.md` — normative URI grammar.
- `tools/tf-types-ts/src/core/actor-id.ts` and
  `crates/tf-types/src/actor_id.rs` — reference implementations.
