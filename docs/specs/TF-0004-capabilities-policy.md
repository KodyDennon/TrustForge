# TF-0004: Capabilities and Policy

## Status

Draft.

## Capabilities

A capability grants authority to perform an action.

Capabilities may be time-limited, session-bound, actor-bound, actor-instance-bound, device-bound, human-bound, approval-bound, offline-valid, revocable, delegable, non-delegable, single-use, or quorum-required.

## Negative capabilities

Explicit denials are core and may override grants.

## Risk classes

Initial risk classes:

- R0 harmless/read-only/public
- R1 low-risk normal action
- R2 sensitive read or limited write
- R3 privileged operation
- R4 destructive/financial/security-impacting
- R5 emergency/life-safety/irreversible

## Policy model

TrustForge defines a policy model and decision format.

TrustForge supports OPA/Rego, Cedar, custom policy backends, plugin policy engines, and a future TrustForge-native policy profile.

## Approval ceremonies

Approval ceremonies are core.

Examples include click approval, passkey approval, YubiKey tap, mobile push, quorum approval, time-delay approval, emergency override, physical presence proof, customer-present approval, and offline signed approval packet.

## Quorum approval

Quorum approval is core and policy-controlled.

## Delegation chains

Delegation chains are core.

Every delegation should define delegator, delegate, capabilities, constraints, expiration, redelegation rules, proof requirements, and revocation path.

## Expiration

Expiration is mandatory/default for authority-bearing objects.

## Continuous authorization

TrustForge continuously reevaluates authorization during live sessions.
