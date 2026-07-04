#!/usr/bin/env bun
/**
 * tf-evidence CLI — full TF-0012 compliance evidence pipeline.
 *
 * Subcommands:
 *   assemble   --tflog <file> --start <iso> --end <iso> --label <text>
 *              --issuer <actor> --key <priv> [--out <file>]
 *              [--actor <actor>...] [--type-pattern <regex>]
 *              [--policy <file>] [--approvals <file>]
 *              [--domain <name>...]
 *   verify     --bundle <file> --issuer-pubkey <file>
 *   seal       --bundle <file> --recipient <actor> --recipient-pubkey <file>
 *              --signer <actor> --key <priv> [--out <file>]
 *   open       --encrypted <file> --recipient <actor> --recipient-key <priv>
 *              [--signer-pubkey <file>] [--out <file>]
 *   anchor     --bundle <file> [--out <file>] (memory anchor demo)
 *   replay     --bundle <file>
 *   redact     --bundle <file> --policy <file> --key <priv> [--out <file>]
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  anchorEvidenceBundle,
  assembleEvidenceBundle,
  MemoryAnchor,
  openEvidenceBundle,
  redactBundle,
  replayEvidence,
  sealEvidenceBundle,
  verifyEvidenceBundle,
  type EvidenceBundle,
  type IncidentDomain,
  type RedactionPolicy,
} from "@trustforge-protocol/types";

function arg(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

function multi(args: string[], flag: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === flag) {
      const next = args[i + 1];
      if (next !== undefined) out.push(next);
    }
  }
  return out;
}

function readPriv(path: string): Uint8Array {
  const raw = JSON.parse(readFileSync(resolve(path), "utf8")) as { key_bytes_b64?: string; key_bytes?: string };
  const b64 = raw.key_bytes_b64 ?? raw.key_bytes;
  if (!b64) throw new Error(`${path} has no key_bytes`);
  return new Uint8Array(Buffer.from(b64, "base64"));
}

function readPub(path: string): Uint8Array {
  const raw = JSON.parse(readFileSync(resolve(path), "utf8")) as { public_key?: string; key_bytes_b64?: string };
  const b64 = raw.public_key ?? raw.key_bytes_b64;
  if (!b64) throw new Error(`${path} has no public_key`);
  return new Uint8Array(Buffer.from(b64, "base64"));
}

async function cmdAssemble(args: string[]): Promise<number> {
  const tflog = arg(args, "--tflog");
  const start = arg(args, "--start");
  const end = arg(args, "--end");
  const label = arg(args, "--label");
  const issuer = arg(args, "--issuer");
  const keyPath = arg(args, "--key");
  if (!tflog || !start || !label || !issuer || !keyPath) {
    console.error("usage: tf-evidence assemble --tflog <f> --start <iso> [--end <iso>] --label <txt> --issuer <actor> --key <priv> [...]");
    return 2;
  }
  const policy = arg(args, "--policy")
    ? JSON.parse(readFileSync(resolve(arg(args, "--policy")!), "utf8"))
    : [];
  const approvals = arg(args, "--approvals")
    ? JSON.parse(readFileSync(resolve(arg(args, "--approvals")!), "utf8"))
    : [];
  const actors = multi(args, "--actor");
  const typePattern = arg(args, "--type-pattern");
  const domains = multi(args, "--domain") as IncidentDomain[];
  const result = await assembleEvidenceBundle({
    bundleId: arg(args, "--bundle-id") ?? `evidence-${Date.now().toString(16)}`,
    trustDomain: arg(args, "--trust-domain") ?? issuer.split(":")[3] ?? "example.com",
    incident: {
      label,
      startedAt: start,
      endedAt: end,
      domains: domains.length > 0 ? domains : undefined,
      description: arg(args, "--description"),
    },
    tflogPath: resolve(tflog),
    actorFilter: actors.length > 0 ? actors : undefined,
    eventTypePattern: typePattern ? new RegExp(typePattern) : undefined,
    policyDecisions: policy,
    approvals,
    issuer,
    privateKey: readPriv(keyPath),
  });
  const out = arg(args, "--out");
  const json = JSON.stringify(result.bundle, null, 2);
  if (out) writeFileSync(resolve(out), json);
  else console.log(json);
  console.error(`assembled ${result.bundle.events.length} events; ${result.skipped} skipped`);
  return 0;
}

async function cmdVerify(args: string[]): Promise<number> {
  const bundlePath = arg(args, "--bundle");
  const pubPath = arg(args, "--issuer-pubkey");
  if (!bundlePath || !pubPath) {
    console.error("usage: tf-evidence verify --bundle <f> --issuer-pubkey <f>");
    return 2;
  }
  const bundle = JSON.parse(readFileSync(resolve(bundlePath), "utf8")) as EvidenceBundle;
  const pub = readPub(pubPath);
  const v = await verifyEvidenceBundle({ bundle, issuerPublicKey: pub });
  console.log(JSON.stringify(v, null, 2));
  return v.ok ? 0 : 1;
}

async function cmdSeal(args: string[]): Promise<number> {
  const bundlePath = arg(args, "--bundle");
  const recipient = arg(args, "--recipient");
  const recipientPubPath = arg(args, "--recipient-pubkey");
  const signer = arg(args, "--signer");
  const keyPath = arg(args, "--key");
  if (!bundlePath || !recipient || !recipientPubPath || !signer || !keyPath) {
    console.error("usage: tf-evidence seal --bundle <f> --recipient <actor> --recipient-pubkey <f> --signer <actor> --key <priv> [--out <f>]");
    return 2;
  }
  const bundle = JSON.parse(readFileSync(resolve(bundlePath), "utf8")) as EvidenceBundle;
  const enc = await sealEvidenceBundle({
    bundle,
    recipients: [{ actor: recipient, kemPublic: readPub(recipientPubPath) }],
    signerPrivateKey: readPriv(keyPath),
    signer,
  });
  const out = arg(args, "--out");
  const json = JSON.stringify(enc, null, 2);
  if (out) writeFileSync(resolve(out), json);
  else console.log(json);
  return 0;
}

async function cmdOpen(args: string[]): Promise<number> {
  const path = arg(args, "--encrypted");
  const recipient = arg(args, "--recipient");
  const keyPath = arg(args, "--recipient-key");
  if (!path || !recipient || !keyPath) {
    console.error("usage: tf-evidence open --encrypted <f> --recipient <actor> --recipient-key <priv> [--signer-pubkey <f>] [--out <f>]");
    return 2;
  }
  const enc = JSON.parse(readFileSync(resolve(path), "utf8"));
  const opened = await openEvidenceBundle({
    encrypted: enc,
    recipientPrivateKey: readPriv(keyPath),
    recipientActor: recipient,
    signerPublicKey: arg(args, "--signer-pubkey") ? readPub(arg(args, "--signer-pubkey")!) : undefined,
  });
  const out = arg(args, "--out");
  const json = JSON.stringify(opened, null, 2);
  if (out) writeFileSync(resolve(out), json);
  else console.log(json);
  return 0;
}

async function cmdAnchor(args: string[]): Promise<number> {
  const bundlePath = arg(args, "--bundle");
  if (!bundlePath) {
    console.error("usage: tf-evidence anchor --bundle <f> [--out <f>]");
    return 2;
  }
  const bundle = JSON.parse(readFileSync(resolve(bundlePath), "utf8")) as EvidenceBundle;
  const next = await anchorEvidenceBundle({ bundle, anchors: [new MemoryAnchor()] });
  const out = arg(args, "--out");
  const json = JSON.stringify(next, null, 2);
  if (out) writeFileSync(resolve(out), json);
  else console.log(json);
  return 0;
}

async function cmdReplay(args: string[]): Promise<number> {
  const bundlePath = arg(args, "--bundle");
  if (!bundlePath) {
    console.error("usage: tf-evidence replay --bundle <f>");
    return 2;
  }
  const bundle = JSON.parse(readFileSync(resolve(bundlePath), "utf8")) as EvidenceBundle;
  console.log(JSON.stringify(replayEvidence(bundle), null, 2));
  return 0;
}

async function cmdRedact(args: string[]): Promise<number> {
  const bundlePath = arg(args, "--bundle");
  const policyPath = arg(args, "--policy");
  const keyPath = arg(args, "--key");
  if (!bundlePath || !policyPath || !keyPath) {
    console.error("usage: tf-evidence redact --bundle <f> --policy <f> --key <priv> [--out <f>]");
    return 2;
  }
  const bundle = JSON.parse(readFileSync(resolve(bundlePath), "utf8")) as EvidenceBundle;
  const policies = JSON.parse(readFileSync(resolve(policyPath), "utf8")) as RedactionPolicy[];
  const redacted = await redactBundle(bundle, policies, readPriv(keyPath));
  const out = arg(args, "--out");
  const json = JSON.stringify(redacted, null, 2);
  if (out) writeFileSync(resolve(out), json);
  else console.log(json);
  return 0;
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case "assemble":
      return cmdAssemble(rest);
    case "verify":
      return cmdVerify(rest);
    case "seal":
      return cmdSeal(rest);
    case "open":
      return cmdOpen(rest);
    case "anchor":
      return cmdAnchor(rest);
    case "replay":
      return cmdReplay(rest);
    case "redact":
      return cmdRedact(rest);
    default:
      console.error("usage: tf-evidence <assemble|verify|seal|open|anchor|replay|redact> [...]");
      return 2;
  }
}

const exit = await main();
process.exit(exit);
