# TF-0002: Actor Identity

## Status

Draft.

## Universal Actor URI

TrustForge requires a universal actor URI.

Example categories:

```text
tf:actor:human:example.com/kody
tf:actor:agent:local/code-helper
tf:actor:device:example.com/backup-box-01
tf:actor:service:spiffe/example.org/ns/prod/sa/api
tf:actor:relay:public/relay-8841
tf:actor:org:example.com
tf:actor:plugin:tf-spiffe-bridge
```

## Actor types

Core actor types include human, agent, device, service, site, organization, relay, plugin, process, tool, model-provider, policy-engine, proof-anchor, and emergency-authority.

## Actor Instance URI

Actor instances identify specific active instances.

Example:

```text
tf:instance:agent:example.com/code-helper/macbook/session-9912
```

## Identity modes

TrustForge supports local-only identity, domain-scoped identity, global portable identity, federated identity, and temporary/session identity.

## Authority model

TrustForge is multi-root and policy-rooted.

Authority may come from owner, organization, manufacturer, hardware key, federation, compliance issuer, local emergency authority, transparency anchor, or trust domain.

## Trust levels

Base trust levels:

- T0 Unknown
- T1 Self-claimed
- T2 Locally trusted
- T3 Organization-issued
- T4 Hardware-backed
- T5 Multi-party verified
- T6 Publicly attestable
- T7 Regulated/compliance verified

## Model identity

Models are provenance metadata by default.

A model-serving system may be an actor.

The responsible actor is usually the agent, service, or runtime that invoked the model.
