#!/usr/bin/env bun
/**
 * Unified tf command. Dispatches to the specialized CLIs and adds the
 * `policy simulate`, `actor create`, `actor inspect`, and `approval`
 * operations.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYAML } from "yaml";
import {
  AgentGuard,
  NativePolicyEngine,
  b64encode,
  canonicalize,
  ed25519Generate,
  ed25519PublicKey,
  policyEngineForManifest,
  signFederationAttestation,
  verifyFederationAttestation,
  type FederationAttestation,
} from "tf-types";
import type { Policy } from "../../tf-types-ts/src/generated/policy.js";

function arg(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

async function policySimulate(args: string[]): Promise<number> {
  const file = args[0];
  const action = arg(args, "--action") ?? args[1];
  const target = arg(args, "--target");
  const subject = arg(args, "--subject") ?? "tf:actor:process:local/policy-simulator";
  const policyFlag = arg(args, "--policy");
  const enforcementFlag = arg(args, "--enforcement-level");
  if (!file || !action) {
    console.error(
      "usage: tf policy simulate <contract.yaml | policy.yaml> <action> [--target <t>] [--subject <actor>] [--policy <policy.yaml>] [--enforcement-level E0..E5]",
    );
    return 2;
  }
  const raw = readFileSync(resolve(file), "utf8");
  const doc = parseYAML(raw) as Record<string, unknown>;
  const isPolicyManifest = "rules" in doc && "trust_domain" in doc && "policy_version" in doc;
  if (isPolicyManifest || policyFlag) {
    const policyDoc = policyFlag
      ? (parseYAML(readFileSync(resolve(policyFlag), "utf8")) as Policy)
      : (doc as unknown as Policy);
    const engine = policyEngineForManifest(policyDoc) as NativePolicyEngine;
    const decision = engine.evaluate({
      subject,
      action,
      target,
      enforcementLevel: enforcementFlag as Parameters<NativePolicyEngine["evaluate"]>[0]["enforcementLevel"],
    });
    console.log(canonicalize(decision));
    return decision.decision === "deny" ? 1 : 0;
  }
  const guard = AgentGuard.fromContract(doc);
  const decision = guard.check({
    actor: subject,
    action,
    target,
  });
  console.log(canonicalize(decision));
  return decision.kind === "deny" ? 1 : 0;
}

async function actorCreate(args: string[]): Promise<number> {
  const type = arg(args, "--type") ?? "agent";
  const name = arg(args, "--name");
  const domain = arg(args, "--domain") ?? "local.example";
  const out = arg(args, "--out");
  if (!name) {
    console.error("usage: tf actor create --name <slug> [--type <actor-type>] [--domain <d>] [--out <file>]");
    return 2;
  }
  const pair = await ed25519Generate();
  const actorId = `tf:actor:${type}:${domain}/${name}`;
  const identity = {
    identity_version: "1",
    actor_id: actorId,
    actor_type: type,
    public_keys: [
      {
        key_id: `${name}-signing-1`,
        algorithm: "ed25519",
        public_key: b64encode(pair.publicKey),
        purpose: "signing",
      },
    ],
    trust_levels: ["T1"],
    authority_roots: [{ kind: "owner", id: name }],
    valid_from: new Date().toISOString(),
  };
  const output = canonicalize({
    identity,
    private_key_base64: b64encode(pair.privateKey),
  });
  if (out) writeFileSync(out, output);
  console.log(output);
  return 0;
}

async function trustDomainFederate(args: string[]): Promise<number> {
  const issuerDomain = arg(args, "--issuer-domain");
  const subjectDomain = arg(args, "--subject-domain");
  const validUntil = arg(args, "--valid-until");
  const issuer = arg(args, "--issuer");
  const keyPath = arg(args, "--key");
  const bundlePath = arg(args, "--trust-bundle");
  if (!issuerDomain || !subjectDomain || !validUntil || !issuer || !keyPath || !bundlePath) {
    console.error(
      "usage: tf trust-domain federate --issuer-domain <d> --subject-domain <d> --valid-until <iso> --issuer <actor> --key <priv> --trust-bundle <file> [--scope <action>...] [--out <file>]",
    );
    return 2;
  }
  const trustBundle = JSON.parse(readFileSync(resolve(bundlePath), "utf8"));
  if (!Array.isArray(trustBundle) || trustBundle.length === 0) {
    console.error("trust bundle must be a non-empty JSON array");
    return 2;
  }
  const scope: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--scope" && args[i + 1]) scope.push(args[i + 1]!);
  }
  const subjectActor = arg(args, "--subject-actor");
  const keyJson = JSON.parse(readFileSync(resolve(keyPath), "utf8")) as { key_bytes_b64?: string; key_bytes?: string };
  const privBytes = new Uint8Array(Buffer.from(keyJson.key_bytes_b64 ?? keyJson.key_bytes ?? "", "base64"));
  if (privBytes.length !== 32) {
    console.error("key must contain a base64 32-byte ed25519 private key");
    return 2;
  }
  const attestationId = arg(args, "--id") ?? `fed-${Date.now().toString(16)}`;
  const attestation = await signFederationAttestation({
    attestationId,
    issuerDomain,
    subjectDomain,
    subjectActor: subjectActor as Parameters<typeof signFederationAttestation>[0]["subjectActor"],
    scope: scope as Parameters<typeof signFederationAttestation>[0]["scope"],
    trustBundle,
    issuer,
    validUntil,
    privateKey: privBytes,
  });
  const output = JSON.stringify(attestation, null, 2);
  const out = arg(args, "--out");
  if (out) writeFileSync(resolve(out), output);
  console.log(output);
  return 0;
}

async function trustDomainVerifyFederation(args: string[]): Promise<number> {
  const path = arg(args, "--attestation");
  const pubPath = arg(args, "--issuer-pubkey");
  if (!path || !pubPath) {
    console.error("usage: tf trust-domain verify-federation --attestation <f> --issuer-pubkey <f>");
    return 2;
  }
  const attestation = JSON.parse(readFileSync(resolve(path), "utf8")) as FederationAttestation;
  const keyJson = JSON.parse(readFileSync(resolve(pubPath), "utf8")) as { public_key?: string; key_bytes_b64?: string };
  const pubBytes = new Uint8Array(Buffer.from(keyJson.public_key ?? keyJson.key_bytes_b64 ?? "", "base64"));
  const v = await verifyFederationAttestation({ attestation, issuerPublicKey: pubBytes });
  console.log(JSON.stringify(v, null, 2));
  return v.ok ? 0 : 1;
}

async function actorInspect(args: string[]): Promise<number> {
  const file = args[0];
  if (!file) {
    console.error("usage: tf actor inspect <file>");
    return 2;
  }
  const raw = readFileSync(resolve(file), "utf8");
  const parsed = JSON.parse(raw);
  const identity = parsed.identity ?? parsed;
  console.log(canonicalize({
    actor_id: identity.actor_id,
    actor_type: identity.actor_type,
    public_keys: (identity.public_keys ?? []).map((k: Record<string, unknown>) => ({
      key_id: k.key_id,
      algorithm: k.algorithm,
      purpose: k.purpose,
    })),
    trust_levels: identity.trust_levels ?? [],
    authority_roots: identity.authority_roots ?? [],
    valid_from: identity.valid_from,
    valid_until: identity.valid_until,
  }));
  return 0;
}

function usage(): number {
  console.error([
    "usage: tf <command> [args]",
    "",
    "commands:",
    "  schema ...                 forward to tf-schema (use tools/tf-schema/src/cli.ts directly)",
    "  proof ...                  forward to tf-proof",
    "  daemon run [...]           run the daemon",
    "  policy simulate <contract> <action> [--target t]",
    "  actor create --name slug [--type t] [--domain d] [--out file]",
    "  actor inspect <file>",
    "  trust-domain federate --issuer-domain d --subject-domain d --valid-until iso --issuer actor --key priv --trust-bundle file [--scope action ...]",
    "  trust-domain verify-federation --attestation file --issuer-pubkey file",
    "",
  ].join("\n"));
  return 2;
}

async function main(): Promise<number> {
  const [cmd, sub, ...rest] = process.argv.slice(2);
  if (!cmd) return usage();

  if (cmd === "policy" && sub === "simulate") return policySimulate(rest);
  if (cmd === "actor" && sub === "create") return actorCreate(rest);
  if (cmd === "actor" && sub === "inspect") return actorInspect(rest);
  if (cmd === "trust-domain" && sub === "federate") return trustDomainFederate(rest);
  if (cmd === "trust-domain" && sub === "verify-federation") return trustDomainVerifyFederation(rest);

  // Forward commands — we don't shell out; users invoke those CLIs directly.
  if (cmd === "schema" || cmd === "proof" || cmd === "daemon") {
    console.error(
      `use \`bun run tools/tf-${cmd}/src/cli.ts ${[sub, ...rest].filter(Boolean).join(" ")}\` — tf-cli does not shell out in this phase`,
    );
    return 2;
  }

  return usage();
}

const exit = await main();
process.exit(exit);
