# Vulnerability disclosure

This page documents the TrustForge security vulnerability disclosure
process. The short version is repeated in
[`README.md`](README.md) and in the top-level
[`../../SECURITY.md`](../../SECURITY.md). If those disagree with this
page, the top-level `SECURITY.md` wins (it is the document published
on GitHub's "Security" tab).

## Reporting a vulnerability

Send an email to **security@trustforge.dev** with:

- Subject line beginning `[TrustForge security]`.
- A description of the issue, including reproduction steps and
  affected versions or commits.
- Whether you have already disclosed the issue elsewhere.
- Whether you plan to publish your own write-up, and on what
  timeline.

PGP encryption is preferred but not required. The team's PGP key is
published at:

- `https://trustforge.dev/.well-known/security.asc`
- Fingerprint: published in `SECURITY.md`. We do not duplicate it
  here to avoid drift; check `SECURITY.md` for the current one.

If `SECURITY.md` does not yet have a fingerprint published (the v0.1.0
repo may not), email in plaintext is acceptable; we will respond with
a key for any subsequent exchange.

## What to include

A complete report typically contains:

1. **Summary** — one sentence.
2. **Impact** — which threat boundary is crossed (use the asset ids
   from [`threat-model.md`](threat-model.md)) and which trust class
   is broken (R0–R5).
3. **Reproduction** — minimal steps. A failing conformance vector,
   a fuzz input, or a unit test is ideal.
4. **Affected versions / commits** — git SHAs preferred.
5. **Suggested mitigation** — optional but appreciated.
6. **Coordinated disclosure preferences** — your timeline, any
   downstream parties to notify.

## Response timeline

| Step | Target |
|---|---|
| Acknowledgement | within 72 hours |
| Triage and severity assessment | within 7 days |
| Fix in progress notification | within 14 days |
| Coordinated disclosure window | 90 days from acknowledgement, by default |
| CVE assignment (if applicable) | concurrent with fix release |

If the issue is being actively exploited or affects a deployed
production system known to us, the timeline compresses. If a fix
requires deeper protocol work, we may request an extension; we will
explain why and propose a new date.

## Severity

We use the threat-model risk classes (TF-0004 R0–R5) as the
severity scale. Roughly:

| Class | Examples | Response posture |
|---|---|---|
| R5 | Vault unlock without passphrase, daemon-admin token forgery | Same-day patch; coordinate disclosure with downstream operators. |
| R4 | Capability inflation, federation peer impersonation, transparency-anchor takeover | Patch within 7–14 days; private notification to known operators. |
| R3 | Plugin sandbox escape, host-fs read outside policy | Patch in next minor release; public advisory at disclosure. |
| R2 | Local DoS, log injection, metadata leak | Patch in next minor release. |
| R1, R0 | Hardening, defense-in-depth | Tracked as a normal issue. |

## Out-of-scope reports

The residual risks listed in
[`../../.tf/threat-model.yaml`](../../.tf/threat-model.yaml) are
explicitly out of scope for v0.1.0. We will not assign CVEs or
expedite responses for:

- Compromised host kernel scenarios.
- Compromised TPM / HSM (hardware lies).
- Physical key extraction.
- Side-channel leakage in upstream crypto libraries (report to the
  upstream library).
- Malicious browser scraping the user session.
- Malicious LSP / IDE auto-completing TrustForge actions.

If a deployment must close one of these gaps, the route is a custom
profile and an ADR — not a vulnerability report.

## Coordinated disclosure

Our default coordinated-disclosure window is **90 days** from the
acknowledgement date. We may extend it once, by mutual agreement,
for issues that require deep protocol work. We do not pay bounties.

We will credit reporters who request credit, in:

- The `CHANGELOG.md` entry for the release containing the fix.
- The advisory published on the GitHub Security Advisories page.
- A `THANKS.md` or equivalent if the reporter requests a permanent
  acknowledgement.

Reporters who prefer to remain anonymous are welcome to request
that.

## CVE numbering

TrustForge is not currently a CVE Numbering Authority (CNA). For
issues that warrant a CVE, we request one through GitHub Security
Advisories, which acts as the CNA on our behalf for public
repositories. The advisory will be linked from the changelog
entry.

## Public-issue and PR hygiene

If you accidentally open a public issue or PR for a security-class
problem, do not delete it (a deleted issue is harder for us to
investigate). Instead:

1. Email security@trustforge.dev immediately and reference the
   issue number.
2. We will lock the issue and continue privately.
3. Once a fix is available and disclosure is coordinated, the
   issue is reopened with the patch link.

## Defensive posture for downstream operators

While 0.1.0 is not production-ready, downstream operators
experimenting with TrustForge should:

- Subscribe to the GitHub Security Advisories feed for this repo.
- Pin to specific commits, not branches.
- Run `tf-conformance run` against any release before deploying.
- Review the `mitigations[]` list in `.tf/threat-model.yaml` and
  confirm `status: implemented` for the threats relevant to their
  deployment profile.
- Keep the vault passphrase rotation runbook
  ([`../ops/runbook-incident.md`](../ops/runbook-incident.md))
  printed and tested.

## What we ask of researchers

- Do not test against deployments you do not own, including any
  hosted demo we may stand up.
- Do not exfiltrate data beyond what is necessary to demonstrate
  the issue.
- Do not publish exploit code before the coordinated disclosure
  window closes.
- Talk to us. Most "I think this is a vulnerability" questions get
  resolved quickly when we can clarify the threat model.

## Contact

- Security email: **security@trustforge.dev**
- General: **hello@trustforge.dev** (for non-security questions)
- GitHub Security Advisories: use the "Report a vulnerability"
  button on the repo's Security tab.

This page is draft and will move with the spec; the contact email
and the timelines above are stable across the 0.1.x line.
