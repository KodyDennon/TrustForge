# Security Policy

## Reporting a vulnerability

If you discover a vulnerability in TrustForge, please report it
privately rather than opening a public issue. There are two channels:

1. **GitHub private security advisory** — preferred. From the repo's
   "Security" tab, choose "Report a vulnerability". This puts the
   report in front of the maintainers immediately and lets us
   coordinate a fix without exposing users in the meantime.
2. **Encrypted email** — `security@trustforge.dev` (placeholder until
   the production address is published; for v0.1.0 prefer the GitHub
   advisory channel). PGP key fingerprint to be published in a follow-
   up release.

Please include enough detail for us to reproduce: affected version /
commit, the steps that surface the vulnerability, the impact you
believe it has, and any proof-of-concept code. We commit to:

- acknowledging receipt within **72 hours**;
- providing a triage summary within **7 days**;
- coordinating disclosure on a timeline that matches severity (CVSS-
  high or worse → 30-day default; tracking longer if patches require
  spec changes).

We will credit you in the CHANGELOG and the release notes unless you
ask to remain anonymous.

## Security posture

TrustForge is security infrastructure. It must be treated as
high-risk software. The 0.1.0 release is **explicitly experimental**:
the protocol is published, the reference implementation passes its
conformance suite, but the spec has not yet been independently
reviewed and **must not** be deployed to protect production systems
or human safety.

## Cryptography rule

TrustForge does not invent cryptographic primitives. Where a primitive
is needed, TrustForge composes reviewed standards:

- ed25519 (RFC 8032) for classical signatures
- X25519 + HKDF-SHA256 + ChaCha20-Poly1305 for session keying
- ml-dsa-65 (FIPS 204) for the post-quantum half of hybrid signatures
- SHA-256 / BLAKE3 for hashing
- Argon2id for KDF / passphrase stretching

If a design proposal requires a new primitive, treat that as a red
flag and push back.

## Threat model

The full threat model lives in `docs/specs/TF-0010-threat-model.md`.
Summary: TrustForge defends against impersonation, capability
escalation, replay, downgrade, and revocation laundering across the
following surfaces:

- session establishment + rekey (Phase 3)
- proof emission + verification (Phase 2)
- agent-contract enforcement (Phase 5)
- offline / packet-mode delivery (Phase 9)
- federated trust merge (Phase 8 / TF-0008)

It does **not** claim to defend against compromised host kernels,
compromised TPM/HSM hardware, or physical key extraction.

## Required security work before 1.0

- independent protocol review
- independent cryptographic review
- broader fuzzing across all binary parsers
- formal analysis of the session protocol where tractable
- key-management review (vault, plugin signing)
- plugin sandbox review across Linux + macOS
- misuse-resistance audit of every bridge

## Experimental status

Initial TrustForge drafts and reference code are experimental until
reviewed.
