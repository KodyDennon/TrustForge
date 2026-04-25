# @trustforge/sdk

Thin TypeScript client over the `tf-daemon` HTTP API. Use this from any
Node/Bun runtime to call `/v1/decide`, `/v1/credentials/import`,
`/v1/proofs/sign`, and `/v1/proofs/verify`.

The wire format is pinned by `conformance/decide-protocol-vectors.yaml` and
must stay byte-compatible with every other-language adapter.

## Install

```sh
bun add @trustforge/sdk
# or
npm install @trustforge/sdk
```

## Usage

```ts
import { TrustForge } from "@trustforge/sdk";

const tf = new TrustForge({
  daemonUrl: "http://127.0.0.1:7616",
  adminToken: process.env.TF_ADMIN_TOKEN,
});

const decision = await tf.decide({
  actor: null,
  host_token: req.headers.authorization?.replace(/^Bearer /, ""),
  host_token_kind: "auto",
  action: "fs.read",
  target: "/etc/hosts",
  context: { ip: req.ip },
  trace_id: crypto.randomUUID(),
});

if (decision.decision === "allow") {
  // proceed
} else if (decision.decision === "deny") {
  res.status(403).json(decision);
} else if (decision.decision === "approval-required") {
  res.status(202).header("Location", `/approvals/${decision.approval_id}`).end();
}
```

## API

- `new TrustForge({ daemonUrl, adminToken?, fetchImpl?, timeoutMs? })`
- `decide(req: DecideRequest): Promise<DecideResponse>`
- `importCredential(cred): Promise<{ actor, credential_id, trust_level }>`
- `signProof(event): Promise<{ event_hash, signature }>`
- `verifyProof(signedEvent): Promise<{ ok, signer_actor, trust_level }>`

Errors are surfaced as `TrustForgeError` (with `.status` + `.body`).

## Status

Draft — experimental; see top-level `SECURITY.md`.
