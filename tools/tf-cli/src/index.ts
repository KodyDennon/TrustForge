#!/usr/bin/env bun
/**
 * Unified `tf` command, full subcommand surface (Phase A8).
 *
 * Architecture:
 *  - A flat command registry (noun, verb) → handler. The handler accepts a
 *    parsed `CliArgs` struct and returns an exit code.
 *  - Every leaf supports `--help` (loads from `help/<noun>-<verb>.yaml` if
 *    present, else uses the registry's inline help string), `--json`,
 *    `--quiet`, and `--dry-run` (where applicable).
 *  - Live operations that target the daemon use `fetch`. The CLI never
 *    spawns sibling tf-* binaries; all logic is imported from the
 *    workspace libraries.
 */

import {
  existsSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { parse as parseYAML } from "yaml";
import {
  AgentGuard,
  NativePolicyEngine,
  RpcClient,
  Vault,
  b64decode,
  b64encode,
  canonicalize,
  ed25519Generate,
  ed25519PublicKey,
  ed25519Sign,
  ed25519Verify,
  policyEngineForManifest,
  signFederationAttestation,
  verifyFederationAttestation,
  signPacket,
  verifyPacket,
  fragmentPacket,
  reassembleFragments,
  simulateLora,
  attestationFromSpiffeBundle,
  derivePeerActor,
  parseSpiffeId,
  spiffeToActorId,
  webauthnToActorIdentity,
  buildProofEvent,
  signProofEvent,
  eventDigest,
  eventHash,
  verifyChain,
  assembleEvidenceBundle,
  sealEvidenceBundle,
  openEvidenceBundle,
  anchorEvidenceBundle,
  verifyEvidenceBundle,
  replayEvidence,
  redactBundle,
  type FederationAttestation,
  type Packet,
  type ProofEvent,
} from "tf-types";
import type { Policy } from "../../tf-types-ts/src/generated/policy.js";
import {
  attachInitiator,
  rpcTransportFromEndpoint,
  type SessionEndpoint,
} from "tf-session";

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

export interface CliArgs {
  positional: string[];
  flags: Map<string, string[]>;
  json: boolean;
  quiet: boolean;
  help: boolean;
  dryRun: boolean;
}

export function parseArgs(argv: string[]): CliArgs {
  const positional: string[] = [];
  const flags = new Map<string, string[]>();
  let i = 0;
  while (i < argv.length) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const name = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        const list = flags.get(name) ?? [];
        list.push(next);
        flags.set(name, list);
        i += 2;
      } else {
        flags.set(name, ["true"]);
        i += 1;
      }
    } else {
      positional.push(a);
      i += 1;
    }
  }
  return {
    positional,
    flags,
    json: flags.has("json"),
    quiet: flags.has("quiet"),
    help: flags.has("help"),
    dryRun: flags.has("dry-run"),
  };
}

export function flagOne(args: CliArgs, name: string): string | undefined {
  const list = args.flags.get(name);
  return list && list[0] !== "true" ? list[0] : list?.[0];
}

export function flagMany(args: CliArgs, name: string): string[] {
  return args.flags.get(name)?.filter((s) => s !== "true") ?? [];
}

export function flagBool(args: CliArgs, name: string): boolean {
  return args.flags.has(name);
}

function emit(args: CliArgs, payload: unknown, summary?: string): void {
  if (args.json) {
    console.log(canonicalize(payload));
  } else if (!args.quiet) {
    if (summary) console.log(summary);
    console.log(canonicalize(payload));
  } else if (typeof payload === "string") {
    console.log(payload);
  }
}

function emitJson(args: CliArgs, payload: unknown): void {
  // Strict JSON-only output (used when --json).
  console.log(canonicalize(payload));
}

// ---------------------------------------------------------------------------
// Daemon HTTP helpers
// ---------------------------------------------------------------------------

export const DAEMON_HINT =
  "the daemon is not reachable. Start it with `bun run tools/tf-daemon/src/cli.ts start` and set TF_ADMIN_TOKEN.";

function adminBase(args: CliArgs): string {
  return flagOne(args, "daemon") ?? process.env.TF_ADMIN_URL ?? "http://127.0.0.1:8787";
}

function adminToken(): string {
  return process.env.TF_ADMIN_TOKEN ?? "";
}

async function adminGet(args: CliArgs, path: string): Promise<unknown> {
  const url = `${adminBase(args)}${path}`;
  let res: Response;
  try {
    res = await fetch(url, { headers: { authorization: `Bearer ${adminToken()}` } });
  } catch (err) {
    throw new Error(`${DAEMON_HINT} (${(err as Error).message})`);
  }
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
  return await res.json();
}

async function adminPost(args: CliArgs, path: string, body: unknown): Promise<unknown> {
  const url = `${adminBase(args)}${path}`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminToken()}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body ?? {}),
    });
  } catch (err) {
    throw new Error(`${DAEMON_HINT} (${(err as Error).message})`);
  }
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
  return await res.json();
}

// ---------------------------------------------------------------------------
// Help system
// ---------------------------------------------------------------------------

function helpDir(): string {
  return resolve(import.meta.dir, "..", "help");
}

function loadHelpYaml(noun: string, verb: string): string | undefined {
  const path = resolve(helpDir(), `${noun}-${verb}.yaml`);
  if (!existsSync(path)) return undefined;
  return readFileSync(path, "utf8");
}

function defaultHelp(spec: CommandSpec): string {
  return [
    `tf ${spec.noun} ${spec.verb} — ${spec.summary}`,
    "",
    spec.usage ?? `usage: tf ${spec.noun} ${spec.verb} [flags]`,
    "",
    spec.details ?? "",
    "",
    "Common flags:",
    "  --json        emit machine-readable JSON output",
    "  --quiet       suppress non-essential text",
    "  --dry-run     print what would happen without contacting external services",
    "  --help        show this help text",
  ]
    .filter((s) => s !== "")
    .join("\n");
}

function showHelp(args: CliArgs, spec: CommandSpec): number {
  const fromYaml = loadHelpYaml(spec.noun, spec.verb);
  const text = fromYaml ?? defaultHelp(spec);
  if (args.json) {
    emitJson(args, {
      noun: spec.noun,
      verb: spec.verb,
      summary: spec.summary,
      usage: spec.usage ?? null,
      help: text,
    });
  } else {
    console.log(text);
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Command registry
// ---------------------------------------------------------------------------

type Handler = (args: CliArgs) => Promise<number> | number;

interface CommandSpec {
  noun: string;
  verb: string;
  summary: string;
  usage?: string;
  details?: string;
  /** When true, --dry-run produces a structured stub instead of executing. */
  supportsDryRun?: boolean;
  handler: Handler;
}

const REGISTRY = new Map<string, CommandSpec>();

function key(noun: string, verb: string): string {
  return `${noun} ${verb}`;
}

function register(spec: CommandSpec): void {
  REGISTRY.set(key(spec.noun, spec.verb), spec);
}

// ---------------------------------------------------------------------------
// Common helpers shared by commands
// ---------------------------------------------------------------------------

function dryRunStub(args: CliArgs, spec: CommandSpec, extra: Record<string, unknown> = {}): number {
  const payload = {
    dry_run: true,
    noun: spec.noun,
    verb: spec.verb,
    summary: spec.summary,
    flags: Object.fromEntries(args.flags),
    positional: args.positional,
    ...extra,
  };
  emitJson(args, payload);
  return 0;
}

function readJsonOrYaml(path: string): unknown {
  const raw = readFileSync(resolve(path), "utf8");
  if (path.endsWith(".json")) return JSON.parse(raw);
  if (path.endsWith(".yaml") || path.endsWith(".yml")) return parseYAML(raw);
  // Try JSON first, fall back to YAML.
  try {
    return JSON.parse(raw);
  } catch {
    return parseYAML(raw);
  }
}

function readPrivateKey(path: string): Uint8Array {
  const obj = JSON.parse(readFileSync(resolve(path), "utf8")) as {
    key_bytes_b64?: string;
    key_bytes?: string;
    private_key_base64?: string;
  };
  const enc = obj.key_bytes_b64 ?? obj.key_bytes ?? obj.private_key_base64;
  if (!enc) throw new Error(`${path} does not contain a base64 private key`);
  return new Uint8Array(Buffer.from(enc, "base64"));
}

function readPublicKey(path: string): Uint8Array {
  const obj = JSON.parse(readFileSync(resolve(path), "utf8")) as {
    public_key?: string;
    key_bytes_b64?: string;
  };
  const enc = obj.public_key ?? obj.key_bytes_b64;
  if (!enc) throw new Error(`${path} does not contain a base64 public key`);
  return new Uint8Array(Buffer.from(enc, "base64"));
}

function ensureDir(path: string): void {
  mkdirSync(path, { recursive: true });
}

function writeFileEnsuringDir(path: string, content: string | Uint8Array): void {
  ensureDir(dirname(path));
  writeFileSync(path, content);
}

function notImplemented(args: CliArgs, spec: CommandSpec, hint?: string): number {
  if (args.dryRun) return dryRunStub(args, spec, hint ? { hint } : {});
  const msg = hint ?? "this command requires runtime context that is not available in this environment.";
  if (args.json) {
    emitJson(args, { ok: false, error: "not-yet-runnable", message: msg, noun: spec.noun, verb: spec.verb });
  } else {
    console.error(`tf ${spec.noun} ${spec.verb}: ${msg}`);
  }
  return 1;
}

// ---------------------------------------------------------------------------
// actor commands
// ---------------------------------------------------------------------------

register({
  noun: "actor",
  verb: "create",
  summary: "Generate a new actor identity (ed25519 signing key).",
  usage: "tf actor create --name <slug> [--type agent|user|service|...] [--domain <d>] [--out <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("actor create")!, { actor_id: "tf:actor:agent:dry.example/dry-run" });
    const type = flagOne(args, "type") ?? "agent";
    const name = flagOne(args, "name");
    const domain = flagOne(args, "domain") ?? "local.example";
    const out = flagOne(args, "out");
    if (!name) {
      console.error("usage: tf actor create --name <slug> [--type <t>] [--domain <d>] [--out <file>]");
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
    const payload = { identity, private_key_base64: b64encode(pair.privateKey) };
    const output = canonicalize(payload);
    if (out) writeFileEnsuringDir(resolve(out), output);
    if (args.quiet) {
      if (args.json) emitJson(args, payload);
    } else {
      console.log(output);
    }
    return 0;
  },
});

register({
  noun: "actor",
  verb: "list",
  summary: "List actors known to the daemon.",
  usage: "tf actor list [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("actor list")!, { actors: [] });
    try {
      const out = await adminGet(args, "/admin/actors");
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "actor",
  verb: "inspect",
  summary: "Inspect an actor identity file (without revealing private key).",
  usage: "tf actor inspect <file>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("actor inspect")!);
    const file = args.positional[0];
    if (!file) {
      console.error("usage: tf actor inspect <file>");
      return 2;
    }
    const parsed = JSON.parse(readFileSync(resolve(file), "utf8"));
    const identity = parsed.identity ?? parsed;
    const out = {
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
    };
    emitJson(args, out);
    return 0;
  },
});

register({
  noun: "actor",
  verb: "revoke",
  summary: "Revoke an actor via the daemon admin API.",
  usage: "tf actor revoke <actor-id> [--reason <text>] [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    const id = args.positional[0];
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("actor revoke")!, { kind: "actor", id });
    if (!id) {
      console.error("usage: tf actor revoke <actor-id> [--reason <text>]");
      return 2;
    }
    try {
      const out = await adminPost(args, "/admin/revocations", {
        kind: "actor",
        id,
        reason: flagOne(args, "reason"),
      });
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "actor",
  verb: "key-rotate",
  summary: "Rotate an actor's signing key. Adds a new key and marks the old one as superseded.",
  usage: "tf actor key-rotate <identity.json> [--out <file>] [--key-id <id>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("actor key-rotate")!);
    const file = args.positional[0];
    if (!file) {
      console.error("usage: tf actor key-rotate <identity.json> [--out <file>] [--key-id <id>]");
      return 2;
    }
    const parsed = JSON.parse(readFileSync(resolve(file), "utf8"));
    const identity = parsed.identity ?? parsed;
    const pair = await ed25519Generate();
    const newKeyId =
      flagOne(args, "key-id") ??
      `${(identity.actor_id as string).split("/").pop()}-signing-${(identity.public_keys?.length ?? 0) + 1}`;
    identity.public_keys = identity.public_keys ?? [];
    for (const k of identity.public_keys) k.superseded = true;
    identity.public_keys.push({
      key_id: newKeyId,
      algorithm: "ed25519",
      public_key: b64encode(pair.publicKey),
      purpose: "signing",
    });
    const payload = {
      identity,
      private_key_base64: b64encode(pair.privateKey),
      rotated_key_id: newKeyId,
    };
    const out = flagOne(args, "out");
    if (out) writeFileEnsuringDir(resolve(out), canonicalize(payload));
    emitJson(args, payload);
    return 0;
  },
});

// ---------------------------------------------------------------------------
// instance commands
// ---------------------------------------------------------------------------

register({
  noun: "instance",
  verb: "list",
  summary: "List active actor instances tracked by the daemon.",
  usage: "tf instance list [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("instance list")!, { instances: [] });
    try {
      const out = await adminGet(args, "/admin/instances");
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "instance",
  verb: "inspect",
  summary: "Inspect a specific actor instance.",
  usage: "tf instance inspect <instance-id> [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    const id = args.positional[0];
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("instance inspect")!, { instance_id: id });
    if (!id) {
      console.error("usage: tf instance inspect <instance-id>");
      return 2;
    }
    try {
      const out = await adminGet(args, `/admin/instances/${encodeURIComponent(id)}`);
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "instance",
  verb: "terminate",
  summary: "Terminate an active actor instance via the daemon.",
  usage: "tf instance terminate <instance-id> [--reason <text>] [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    const id = args.positional[0];
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("instance terminate")!, { instance_id: id });
    if (!id) {
      console.error("usage: tf instance terminate <instance-id>");
      return 2;
    }
    try {
      const out = await adminPost(args, `/admin/instances/${encodeURIComponent(id)}/terminate`, {
        reason: flagOne(args, "reason"),
      });
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

// ---------------------------------------------------------------------------
// trust-domain commands
// ---------------------------------------------------------------------------

register({
  noun: "trust-domain",
  verb: "init",
  summary: "Initialize a fresh trust bundle with a generated root key set.",
  usage: "tf trust-domain init --name <domain> [--keys <n>] [--out <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("trust-domain init")!);
    const name = flagOne(args, "name");
    const out = flagOne(args, "out");
    if (!name) {
      console.error("usage: tf trust-domain init --name <domain> [--keys <n>] [--out <file>]");
      return 2;
    }
    const keys = parseInt(flagOne(args, "keys") ?? "1", 10);
    const entries: Array<{ kind: string; key_id: string; value: string }> = [];
    const privateKeys: Array<{ key_id: string; private_key_base64: string }> = [];
    for (let i = 0; i < keys; i++) {
      const pair = await ed25519Generate();
      const keyId = `${name}-root-${i + 1}`;
      entries.push({ kind: "ed25519", key_id: keyId, value: b64encode(pair.publicKey) });
      privateKeys.push({ key_id: keyId, private_key_base64: b64encode(pair.privateKey) });
    }
    const bundle = {
      trust_bundle_version: "1",
      trust_domain: name,
      issued_at: new Date().toISOString(),
      keys: entries,
    };
    const payload = { bundle, private_keys: privateKeys };
    const output = canonicalize(payload);
    if (out) writeFileEnsuringDir(resolve(out), output);
    emitJson(args, payload);
    return 0;
  },
});

register({
  noun: "trust-domain",
  verb: "federate",
  summary: "Sign a federation attestation between two trust domains.",
  usage:
    "tf trust-domain federate --issuer-domain <d> --subject-domain <d> --valid-until <iso> --issuer <actor> --key <priv> --trust-bundle <file> [--scope <a>...] [--out <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("trust-domain federate")!);
    const issuerDomain = flagOne(args, "issuer-domain");
    const subjectDomain = flagOne(args, "subject-domain");
    const validUntil = flagOne(args, "valid-until");
    const issuer = flagOne(args, "issuer");
    const keyPath = flagOne(args, "key");
    const bundlePath = flagOne(args, "trust-bundle");
    if (!issuerDomain || !subjectDomain || !validUntil || !issuer || !keyPath || !bundlePath) {
      console.error("missing required flags. See `tf trust-domain federate --help`.");
      return 2;
    }
    const trustBundle = JSON.parse(readFileSync(resolve(bundlePath), "utf8"));
    const scope = flagMany(args, "scope");
    const subjectActor = flagOne(args, "subject-actor");
    const privBytes = readPrivateKey(keyPath);
    const attestationId = flagOne(args, "id") ?? `fed-${Date.now().toString(16)}`;
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
    const out = flagOne(args, "out");
    if (out) writeFileEnsuringDir(resolve(out), JSON.stringify(attestation, null, 2));
    emitJson(args, attestation);
    return 0;
  },
});

register({
  noun: "trust-domain",
  verb: "verify-federation",
  summary: "Verify a federation attestation using the issuer's public key.",
  usage: "tf trust-domain verify-federation --attestation <f> --issuer-pubkey <f>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("trust-domain verify-federation")!);
    const path = flagOne(args, "attestation");
    const pubPath = flagOne(args, "issuer-pubkey");
    if (!path || !pubPath) {
      console.error("usage: tf trust-domain verify-federation --attestation <f> --issuer-pubkey <f>");
      return 2;
    }
    const attestation = JSON.parse(readFileSync(resolve(path), "utf8")) as FederationAttestation;
    const pubBytes = readPublicKey(pubPath);
    const v = await verifyFederationAttestation({ attestation, issuerPublicKey: pubBytes });
    emitJson(args, v);
    return v.ok ? 0 : 1;
  },
});

register({
  noun: "trust-domain",
  verb: "list-roots",
  summary: "List trust roots loaded by the daemon.",
  usage: "tf trust-domain list-roots [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("trust-domain list-roots")!, { roots: [] });
    try {
      const out = await adminGet(args, "/admin/trust-roots");
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

// ---------------------------------------------------------------------------
// bridge commands
// ---------------------------------------------------------------------------

register({
  noun: "bridge",
  verb: "list",
  summary: "List bridges installed in the daemon.",
  usage: "tf bridge list [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("bridge list")!, { bridges: [] });
    try {
      const out = await adminGet(args, "/admin/bridges");
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "bridge",
  verb: "install",
  summary: "Install a bridge plugin into the daemon's registry.",
  usage: "tf bridge install --kind <k> --config <file> [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("bridge install")!);
    const kind = flagOne(args, "kind");
    const cfg = flagOne(args, "config");
    if (!kind || !cfg) {
      console.error("usage: tf bridge install --kind <k> --config <file>");
      return 2;
    }
    const config = readJsonOrYaml(cfg);
    try {
      const out = await adminPost(args, "/admin/bridges", { kind, config });
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "bridge",
  verb: "configure",
  summary: "Update a bridge's configuration.",
  usage: "tf bridge configure --id <bridge-id> --config <file> [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("bridge configure")!);
    const id = flagOne(args, "id");
    const cfg = flagOne(args, "config");
    if (!id || !cfg) {
      console.error("usage: tf bridge configure --id <id> --config <file>");
      return 2;
    }
    const config = readJsonOrYaml(cfg);
    try {
      const out = await adminPost(args, `/admin/bridges/${encodeURIComponent(id)}`, { config });
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "bridge",
  verb: "test",
  summary: "Round-trip a sample credential through a bridge.",
  usage: "tf bridge test --id <bridge-id> --credential <file> [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("bridge test")!);
    const id = flagOne(args, "id");
    const cred = flagOne(args, "credential");
    if (!id || !cred) {
      console.error("usage: tf bridge test --id <id> --credential <file>");
      return 2;
    }
    const credential = readJsonOrYaml(cred);
    try {
      const out = await adminPost(args, `/admin/bridges/${encodeURIComponent(id)}/test`, { credential });
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "bridge",
  verb: "spiffe-import",
  summary: "Convert a SPIFFE JWKS bundle into a TrustForge attestation draft.",
  usage:
    "tf bridge spiffe-import --bundle <jwks.json> --issuer <actor> --issuer-domain <d> --valid-until <iso> [--out <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("bridge spiffe-import")!);
    const file = flagOne(args, "bundle");
    const issuer = flagOne(args, "issuer");
    const issuerDomain = flagOne(args, "issuer-domain");
    const validUntil = flagOne(args, "valid-until");
    if (!file || !issuer || !issuerDomain || !validUntil) {
      console.error("missing required flags. See `tf bridge spiffe-import --help`.");
      return 2;
    }
    const parsed = JSON.parse(readFileSync(resolve(file), "utf8")) as {
      trust_domain: string;
      keys: Array<Record<string, unknown>>;
    };
    const draft = attestationFromSpiffeBundle(parsed, { issuerDomain, issuer, validUntil });
    const out = flagOne(args, "out");
    if (out) writeFileEnsuringDir(resolve(out), canonicalize(draft));
    emitJson(args, draft);
    return 0;
  },
});

register({
  noun: "bridge",
  verb: "spiffe-federate",
  summary: "Federate a SPIFFE trust bundle with a remote domain.",
  usage:
    "tf bridge spiffe-federate --bundle <jwks.json> --issuer <actor> --issuer-domain <d> --subject-domain <d> --valid-until <iso> --key <priv> [--out <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("bridge spiffe-federate")!);
    const file = flagOne(args, "bundle");
    const issuer = flagOne(args, "issuer");
    const issuerDomain = flagOne(args, "issuer-domain");
    const subjectDomain = flagOne(args, "subject-domain");
    const validUntil = flagOne(args, "valid-until");
    const keyPath = flagOne(args, "key");
    if (!file || !issuer || !issuerDomain || !subjectDomain || !validUntil || !keyPath) {
      console.error("missing required flags. See `tf bridge spiffe-federate --help`.");
      return 2;
    }
    const parsed = JSON.parse(readFileSync(resolve(file), "utf8")) as {
      trust_domain: string;
      keys: Array<Record<string, unknown>>;
    };
    const draft = attestationFromSpiffeBundle(parsed, { issuerDomain, issuer, validUntil });
    const privBytes = readPrivateKey(keyPath);
    const attestation = await signFederationAttestation({
      attestationId: flagOne(args, "id") ?? `fed-${Date.now().toString(16)}`,
      issuerDomain,
      subjectDomain,
      issuer,
      validUntil,
      trustBundle: draft.trust_bundle ?? [],
      privateKey: privBytes,
    });
    const out = flagOne(args, "out");
    if (out) writeFileEnsuringDir(resolve(out), JSON.stringify(attestation, null, 2));
    emitJson(args, attestation);
    return 0;
  },
});

register({
  noun: "bridge",
  verb: "oauth-register-issuer",
  summary: "Register a new OAuth issuer with the daemon.",
  usage: "tf bridge oauth-register-issuer --issuer <url> --jwks <file> [--audience <a>] [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("bridge oauth-register-issuer")!);
    const issuer = flagOne(args, "issuer");
    const jwksPath = flagOne(args, "jwks");
    if (!issuer || !jwksPath) {
      console.error("usage: tf bridge oauth-register-issuer --issuer <url> --jwks <file>");
      return 2;
    }
    const jwks = JSON.parse(readFileSync(resolve(jwksPath), "utf8"));
    try {
      const out = await adminPost(args, "/admin/bridges/oauth/issuers", {
        issuer,
        jwks,
        audience: flagOne(args, "audience"),
      });
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "bridge",
  verb: "oauth-introspect",
  summary: "Introspect an OAuth token via the daemon's OAuth bridge.",
  usage: "tf bridge oauth-introspect --token <jwt> [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("bridge oauth-introspect")!);
    const token = flagOne(args, "token");
    if (!token) {
      console.error("usage: tf bridge oauth-introspect --token <jwt>");
      return 2;
    }
    try {
      const out = await adminPost(args, "/admin/bridges/oauth/introspect", { token });
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "bridge",
  verb: "webauthn-register",
  summary: "Register a WebAuthn credential as a TrustForge actor.",
  usage: "tf bridge webauthn-register --credential <file> [--rp-id <id>] [--out <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("bridge webauthn-register")!);
    const credPath = flagOne(args, "credential");
    if (!credPath) {
      console.error("usage: tf bridge webauthn-register --credential <file>");
      return 2;
    }
    const credential = JSON.parse(readFileSync(resolve(credPath), "utf8"));
    const identity = webauthnToActorIdentity(credential, {
      rpId: flagOne(args, "rp-id") ?? credential.rp_id,
    });
    const out = flagOne(args, "out");
    if (out) writeFileEnsuringDir(resolve(out), canonicalize(identity));
    emitJson(args, identity);
    return 0;
  },
});

register({
  noun: "bridge",
  verb: "webauthn-assert-test",
  summary: "Run a synthetic WebAuthn assertion through the daemon's bridge for debugging.",
  usage: "tf bridge webauthn-assert-test --assertion <file> [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("bridge webauthn-assert-test")!);
    const a = flagOne(args, "assertion");
    if (!a) {
      console.error("usage: tf bridge webauthn-assert-test --assertion <file>");
      return 2;
    }
    const assertion = JSON.parse(readFileSync(resolve(a), "utf8"));
    try {
      const out = await adminPost(args, "/admin/bridges/webauthn/assert", { assertion });
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

// ---------------------------------------------------------------------------
// packet commands
// ---------------------------------------------------------------------------

register({
  noun: "packet",
  verb: "sign",
  summary: "Sign a payload as a TrustForge packet.",
  usage:
    "tf packet sign --packet-id <id> --source <a> --destination <a> --priority P0..P5 --payload <file> --key <priv> --signer <actor> [--out <file>] [--encoding json|cbor]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("packet sign")!);
    const packetId = flagOne(args, "packet-id");
    const source = flagOne(args, "source");
    const destination = flagOne(args, "destination");
    const priority = (flagOne(args, "priority") ?? "P3") as "P0" | "P1" | "P2" | "P3" | "P4" | "P5";
    const payloadPath = flagOne(args, "payload");
    const keyPath = flagOne(args, "key");
    const signer = flagOne(args, "signer");
    if (!packetId || !source || !destination || !payloadPath || !keyPath || !signer) {
      console.error("missing required flags. See `tf packet sign --help`.");
      return 2;
    }
    const payload = readFileSync(resolve(payloadPath));
    const privateKey = readPrivateKey(keyPath);
    const packet = await signPacket({
      packetId,
      source,
      destination,
      priority,
      payload: new Uint8Array(payload),
      privateKey,
      signer,
      encoding: (flagOne(args, "encoding") as "json" | "cbor" | undefined) ?? "cbor",
      emergency: flagBool(args, "emergency"),
    });
    const out = flagOne(args, "out");
    if (out) writeFileEnsuringDir(resolve(out), canonicalize(packet));
    emitJson(args, packet);
    return 0;
  },
});

register({
  noun: "packet",
  verb: "verify",
  summary: "Verify a packet's signature with a public key.",
  usage: "tf packet verify --packet <file> --pubkey <file>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("packet verify")!);
    const file = flagOne(args, "packet") ?? args.positional[0];
    const pubPath = flagOne(args, "pubkey");
    if (!file || !pubPath) {
      console.error("usage: tf packet verify --packet <file> --pubkey <file>");
      return 2;
    }
    const packet = JSON.parse(readFileSync(resolve(file), "utf8")) as Packet;
    const pub = readPublicKey(pubPath);
    const v = await verifyPacket(packet, pub);
    emitJson(args, { ok: v.ok, reason: v.reason ?? null });
    return v.ok ? 0 : 1;
  },
});

register({
  noun: "packet",
  verb: "inspect",
  summary: "Print structured metadata about a signed packet.",
  usage: "tf packet inspect <file> | --packet <file>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("packet inspect")!);
    const file = flagOne(args, "packet") ?? args.positional[0];
    if (!file) {
      console.error("usage: tf packet inspect <file>");
      return 2;
    }
    const packet = JSON.parse(readFileSync(resolve(file), "utf8")) as Packet;
    const summary = {
      packet_id: packet.packet_id,
      source: packet.source,
      destination: packet.destination,
      priority: packet.priority,
      emergency: packet.emergency ?? false,
      created_at: packet.created_at,
      expires_at: packet.expires_at,
      ttl_hops: packet.ttl_hops,
      encoding: packet.encoding,
      compression: packet.compression,
      payload_bytes: Buffer.from(packet.payload, "base64").length,
      fragment: packet.fragment ?? null,
      signer: packet.signature?.signer,
      signature_algorithm: packet.signature?.algorithm,
    };
    emitJson(args, summary);
    return 0;
  },
});

register({
  noun: "packet",
  verb: "fragment",
  summary: "Fragment a large packet into a sequence of indexed sub-packets.",
  usage: "tf packet fragment --packet <file> --mtu <n> --key <priv> [--out-dir <dir>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("packet fragment")!);
    const packetPath = flagOne(args, "packet");
    const mtu = parseInt(flagOne(args, "mtu") ?? flagOne(args, "max-bytes") ?? "256", 10);
    const keyPath = flagOne(args, "key");
    if (!packetPath || !keyPath) {
      console.error("usage: tf packet fragment --packet <file> --mtu <n> --key <priv>");
      return 2;
    }
    const packet = JSON.parse(readFileSync(resolve(packetPath), "utf8")) as Packet;
    const privateKey = readPrivateKey(keyPath);
    const fragments = await fragmentPacket(packet, privateKey, { mtu });
    const outDir = flagOne(args, "out-dir");
    if (outDir) {
      ensureDir(resolve(outDir));
      fragments.forEach((f, i) => {
        writeFileEnsuringDir(resolve(outDir, `fragment-${i}.json`), canonicalize(f));
      });
    }
    emitJson(args, { count: fragments.length, fragments });
    return 0;
  },
});

register({
  noun: "packet",
  verb: "reassemble",
  summary: "Reassemble fragments produced by `tf packet fragment`.",
  usage: "tf packet reassemble --fragments <dir|file...> [--out <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("packet reassemble")!);
    const inputs = flagMany(args, "fragments");
    if (inputs.length === 0) {
      console.error("usage: tf packet reassemble --fragments <file>...");
      return 2;
    }
    const fragments: Packet[] = [];
    for (const path of inputs) {
      fragments.push(JSON.parse(readFileSync(resolve(path), "utf8")) as Packet);
    }
    const result = reassembleFragments(fragments);
    const out = flagOne(args, "out");
    if (result.ok && out && result.payload) {
      writeFileEnsuringDir(resolve(out), result.payload);
    }
    emitJson(args, {
      ok: result.ok,
      reason: result.reason ?? null,
      payload_bytes: result.payload?.length ?? 0,
    });
    return result.ok ? 0 : 1;
  },
});

register({
  noun: "packet",
  verb: "simulate-lora",
  summary: "Simulate LoRa airtime + duty cycle for a sequence of packets.",
  usage: "tf packet simulate-lora --packets <file>... [--bandwidth-bps <n>] [--duty-cycle <fraction>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("packet simulate-lora")!);
    const inputs = flagMany(args, "packets");
    if (inputs.length === 0) {
      console.error("usage: tf packet simulate-lora --packets <file>...");
      return 2;
    }
    const packets: Packet[] = [];
    for (const path of inputs) {
      packets.push(JSON.parse(readFileSync(resolve(path), "utf8")) as Packet);
    }
    const bandwidth = flagOne(args, "bandwidth-bps");
    const baseLatency = flagOne(args, "base-latency-ms");
    const loss = flagOne(args, "packet-loss");
    const result = simulateLora(packets, {
      bandwidthBps: bandwidth ? parseInt(bandwidth, 10) : undefined,
      baseLatencyMs: baseLatency ? parseInt(baseLatency, 10) : undefined,
      packetLoss: loss ? parseFloat(loss) : undefined,
    });
    emitJson(args, result);
    return 0;
  },
});

// ---------------------------------------------------------------------------
// session commands
// ---------------------------------------------------------------------------

register({
  noun: "session",
  verb: "inspect",
  summary: "Inspect active sessions on the daemon.",
  usage: "tf session inspect [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("session inspect")!, { sessions: [] });
    try {
      const out = await adminGet(args, "/admin/sessions");
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "session",
  verb: "migrate",
  summary: "Initiate a session migration to a new instance.",
  usage: "tf session migrate --session-id <id> --new-instance <id> [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("session migrate")!);
    const sid = flagOne(args, "session-id");
    const ni = flagOne(args, "new-instance");
    if (!sid || !ni) {
      console.error("usage: tf session migrate --session-id <id> --new-instance <id>");
      return 2;
    }
    try {
      const out = await adminPost(args, `/admin/sessions/${encodeURIComponent(sid)}/migrate`, {
        new_instance: ni,
      });
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "session",
  verb: "rekey",
  summary: "Trigger a key rotation on an active session.",
  usage: "tf session rekey --session-id <id> [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("session rekey")!);
    const sid = flagOne(args, "session-id");
    if (!sid) {
      console.error("usage: tf session rekey --session-id <id>");
      return 2;
    }
    try {
      const out = await adminPost(args, `/admin/sessions/${encodeURIComponent(sid)}/rekey`, {});
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "session",
  verb: "kill",
  summary: "Terminate an active session.",
  usage: "tf session kill --session-id <id> [--reason <text>] [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("session kill")!);
    const sid = flagOne(args, "session-id");
    if (!sid) {
      console.error("usage: tf session kill --session-id <id>");
      return 2;
    }
    try {
      const out = await adminPost(args, `/admin/sessions/${encodeURIComponent(sid)}/kill`, {
        reason: flagOne(args, "reason"),
      });
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

// ---------------------------------------------------------------------------
// approval commands
// ---------------------------------------------------------------------------

register({
  noun: "approval",
  verb: "list",
  summary: "List pending approvals.",
  usage: "tf approval list [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("approval list")!, { approvals: [] });
    try {
      const out = await adminGet(args, "/admin/approvals");
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "approval",
  verb: "approve",
  summary: "Approve a pending approval request by id.",
  usage: "tf approval approve <id> [--note <text>] [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("approval approve")!, { id: args.positional[0] });
    const id = args.positional[0];
    if (!id) {
      console.error("usage: tf approval approve <id>");
      return 2;
    }
    try {
      const out = await adminPost(args, `/admin/approvals/${encodeURIComponent(id)}/approve`, {
        note: flagOne(args, "note"),
      });
      emitJson(args, out);
      return (out as { ok?: boolean }).ok ? 0 : 1;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "approval",
  verb: "deny",
  summary: "Deny a pending approval request by id.",
  usage: "tf approval deny <id> [--note <text>] [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("approval deny")!, { id: args.positional[0] });
    const id = args.positional[0];
    if (!id) {
      console.error("usage: tf approval deny <id>");
      return 2;
    }
    try {
      const out = await adminPost(args, `/admin/approvals/${encodeURIComponent(id)}/deny`, {
        note: flagOne(args, "note"),
      });
      emitJson(args, out);
      return (out as { ok?: boolean }).ok ? 0 : 1;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "approval",
  verb: "drain",
  summary: "Drain expired or stale approval entries.",
  usage: "tf approval drain [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("approval drain")!);
    try {
      const out = await adminPost(args, "/admin/approvals/drain", {});
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

// ---------------------------------------------------------------------------
// revoke commands
// ---------------------------------------------------------------------------

function revokeKindHandler(kind: string, label: string) {
  return async (args: CliArgs): Promise<number> => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get(`revoke ${kind}`)!, { kind, id: args.positional[0] });
    const id = args.positional[0];
    if (!id) {
      console.error(`usage: tf revoke ${kind} <id> [--reason <text>]`);
      return 2;
    }
    try {
      const out = await adminPost(args, "/admin/revocations", { kind, id, reason: flagOne(args, "reason") });
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  };
}

register({
  noun: "revoke",
  verb: "actor",
  summary: "Revoke an actor.",
  usage: "tf revoke actor <actor-id> [--reason <text>]",
  supportsDryRun: true,
  handler: revokeKindHandler("actor", "actor"),
});
register({
  noun: "revoke",
  verb: "instance",
  summary: "Revoke an actor instance.",
  usage: "tf revoke instance <instance-id> [--reason <text>]",
  supportsDryRun: true,
  handler: revokeKindHandler("instance", "instance"),
});
register({
  noun: "revoke",
  verb: "capability",
  summary: "Revoke a capability grant.",
  usage: "tf revoke capability <capability-id> [--reason <text>]",
  supportsDryRun: true,
  handler: revokeKindHandler("capability", "capability"),
});
register({
  noun: "revoke",
  verb: "key",
  summary: "Revoke a specific signing key.",
  usage: "tf revoke key <key-id> [--reason <text>]",
  supportsDryRun: true,
  handler: revokeKindHandler("key", "key"),
});

register({
  noun: "revoke",
  verb: "list",
  summary: "List revocations known to the daemon.",
  usage: "tf revoke list [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("revoke list")!, { revocations: [] });
    try {
      const out = await adminGet(args, "/admin/revocations");
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "revoke",
  verb: "import-orl",
  summary: "Import a TrustForge object revocation list (ORL) file.",
  usage: "tf revoke import-orl --file <orl.json> [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("revoke import-orl")!);
    const file = flagOne(args, "file");
    if (!file) {
      console.error("usage: tf revoke import-orl --file <orl.json>");
      return 2;
    }
    const orl = JSON.parse(readFileSync(resolve(file), "utf8"));
    try {
      const out = await adminPost(args, "/admin/revocations/import", { orl });
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "revoke",
  verb: "export-orl",
  summary: "Export the current revocation list as an ORL file.",
  usage: "tf revoke export-orl [--out <file>] [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("revoke export-orl")!);
    try {
      const out = await adminGet(args, "/admin/revocations/export");
      const path = flagOne(args, "out");
      if (path) writeFileEnsuringDir(resolve(path), canonicalize(out));
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

// ---------------------------------------------------------------------------
// plugin commands
// ---------------------------------------------------------------------------

register({
  noun: "plugin",
  verb: "list",
  summary: "List plugins loaded by the daemon.",
  usage: "tf plugin list [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("plugin list")!, { plugins: [] });
    try {
      const out = await adminGet(args, "/admin/plugins");
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "plugin",
  verb: "install",
  summary: "Install a plugin from a manifest path.",
  usage: "tf plugin install --manifest <file> [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("plugin install")!);
    const file = flagOne(args, "manifest");
    if (!file) {
      console.error("usage: tf plugin install --manifest <file>");
      return 2;
    }
    const manifest = readJsonOrYaml(file);
    try {
      const out = await adminPost(args, "/admin/plugins", { manifest });
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "plugin",
  verb: "verify-manifest",
  summary: "Validate a plugin manifest against the local schema (offline).",
  usage: "tf plugin verify-manifest --manifest <file>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("plugin verify-manifest")!);
    const file = flagOne(args, "manifest");
    if (!file) {
      console.error("usage: tf plugin verify-manifest --manifest <file>");
      return 2;
    }
    const manifest = readJsonOrYaml(file) as Record<string, unknown>;
    const errors: string[] = [];
    if (typeof manifest.plugin_version !== "string") errors.push("missing plugin_version");
    if (typeof manifest.plugin_id !== "string") errors.push("missing plugin_id");
    if (typeof manifest.kind !== "string") errors.push("missing kind");
    emitJson(args, { ok: errors.length === 0, errors });
    return errors.length === 0 ? 0 : 1;
  },
});

register({
  noun: "plugin",
  verb: "sandbox-test",
  summary: "Run a plugin in the sandbox harness with a synthetic request.",
  usage: "tf plugin sandbox-test --manifest <file> --request <file>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("plugin sandbox-test")!);
    return notImplemented(args, REGISTRY.get("plugin sandbox-test")!,
      "sandbox-test requires the daemon's sandbox harness; use --dry-run to validate the CLI surface offline.");
  },
});

// ---------------------------------------------------------------------------
// rpc commands
// ---------------------------------------------------------------------------

register({
  noun: "rpc",
  verb: "call",
  summary: "Make a unary ProofRPC call against a remote endpoint.",
  usage:
    "tf rpc call --url <ws://host:port> --method <name> --key <priv> [--request <json|@file>] [--claim <self-claimed-actor>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("rpc call")!);
    const url = flagOne(args, "url");
    const method = flagOne(args, "method");
    const requestPath = flagOne(args, "request");
    const keyPath = flagOne(args, "key");
    const claim = flagOne(args, "claim");
    if (!url || !method || !keyPath) {
      console.error("usage: tf rpc call --url <ws://...> --method <name> --key <priv>");
      return 2;
    }
    let request: unknown = null;
    if (requestPath) {
      if (requestPath.startsWith("@")) {
        request = JSON.parse(readFileSync(resolve(requestPath.slice(1)), "utf8"));
      } else {
        request = JSON.parse(requestPath);
      }
    }
    const privBytes = readPrivateKey(keyPath);
    const pubBytes = await ed25519PublicKey(privBytes);
    const callerActor = derivePeerActor(pubBytes);
    const selfActor = claim ?? callerActor;

    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    await new Promise<void>((res, rej) => {
      ws.addEventListener("open", () => res(), { once: true });
      ws.addEventListener("error", () => rej(new Error("websocket error")), { once: true });
    });

    const messageListeners = new Set<(b: Uint8Array) => void>();
    const closeListeners = new Set<() => void>();
    const sink = {
      send(bytes: Uint8Array) {
        ws.send(bytes);
      },
      close() {
        ws.close();
      },
    };
    const source = {
      onMessage(l: (b: Uint8Array) => void) {
        messageListeners.add(l);
      },
      onClose(l: () => void) {
        closeListeners.add(l);
      },
    };
    ws.addEventListener("message", (ev) => {
      const data =
        ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : new TextEncoder().encode(String(ev.data));
      for (const l of messageListeners) l(data);
    });
    ws.addEventListener("close", () => {
      for (const l of closeListeners) l();
    });

    const endpoint: SessionEndpoint = await attachInitiator(
      {
        selfActor,
        peerHint: claim,
        identityPriv: privBytes,
        identityPub: pubBytes,
      },
      sink,
      source,
    );
    const client = new RpcClient(rpcTransportFromEndpoint(endpoint), { callerActor });
    const response = await client.call(method, request);
    emitJson(args, response);
    endpoint.close("rpc.call complete");
    ws.close();
    return 0;
  },
});

register({
  noun: "rpc",
  verb: "list-methods",
  summary: "List methods exposed by a ProofRPC service definition.",
  usage: "tf rpc list-methods --service <file>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("rpc list-methods")!, { methods: [] });
    const file = flagOne(args, "service");
    if (!file) {
      console.error("usage: tf rpc list-methods --service <file>");
      return 2;
    }
    const doc = readJsonOrYaml(file) as { methods?: Array<{ name: string; kind: string }> };
    emitJson(args, { methods: doc.methods ?? [] });
    return 0;
  },
});

register({
  noun: "rpc",
  verb: "inspect-method",
  summary: "Print a single method definition from a service file.",
  usage: "tf rpc inspect-method --service <file> --method <name>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("rpc inspect-method")!);
    const file = flagOne(args, "service");
    const method = flagOne(args, "method");
    if (!file || !method) {
      console.error("usage: tf rpc inspect-method --service <file> --method <name>");
      return 2;
    }
    const doc = readJsonOrYaml(file) as { methods?: Array<{ name: string }> };
    const m = (doc.methods ?? []).find((x) => x.name === method);
    if (!m) {
      console.error(`method ${method} not found`);
      return 1;
    }
    emitJson(args, m);
    return 0;
  },
});

// ---------------------------------------------------------------------------
// evidence commands (all native — no shelling out)
// ---------------------------------------------------------------------------

register({
  noun: "evidence",
  verb: "assemble",
  summary: "Assemble an evidence bundle from a tflog file or in-memory events.",
  usage:
    "tf evidence assemble --bundle-id <id> --trust-domain <d> --issuer <actor> --key <priv> --tflog <file> [--label <s>] [--started-at <iso>] [--out <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("evidence assemble")!);
    const bundleId = flagOne(args, "bundle-id");
    const trustDomain = flagOne(args, "trust-domain");
    const label = flagOne(args, "label") ?? "incident";
    const tflog = flagOne(args, "tflog");
    const issuer = flagOne(args, "issuer");
    const keyPath = flagOne(args, "key");
    const startedAt = flagOne(args, "started-at") ?? new Date().toISOString();
    if (!bundleId || !trustDomain || !issuer || !keyPath) {
      console.error(
        "usage: tf evidence assemble --bundle-id <id> --trust-domain <d> --issuer <actor> --key <priv> [--tflog <file>]",
      );
      return 2;
    }
    const privateKey = readPrivateKey(keyPath);
    const result = await assembleEvidenceBundle({
      bundleId,
      trustDomain,
      incident: { label, startedAt },
      tflogPath: tflog ? resolve(tflog) : undefined,
      issuer,
      privateKey,
    } as Parameters<typeof assembleEvidenceBundle>[0]);
    const out = flagOne(args, "out");
    if (out) writeFileEnsuringDir(resolve(out), canonicalize(result.bundle));
    emitJson(args, result.bundle);
    return 0;
  },
});

register({
  noun: "evidence",
  verb: "verify",
  summary: "Verify an evidence bundle's integrity and signatures.",
  usage: "tf evidence verify --bundle <file> --issuer-pubkey <file>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("evidence verify")!);
    const file = flagOne(args, "bundle") ?? args.positional[0];
    const pubPath = flagOne(args, "issuer-pubkey");
    if (!file || !pubPath) {
      console.error("usage: tf evidence verify --bundle <file> --issuer-pubkey <file>");
      return 2;
    }
    const bundle = JSON.parse(readFileSync(resolve(file), "utf8"));
    const issuerPublicKey = readPublicKey(pubPath);
    const result = await verifyEvidenceBundle({ bundle, issuerPublicKey });
    emitJson(args, result);
    return result.ok ? 0 : 1;
  },
});

register({
  noun: "evidence",
  verb: "seal",
  summary: "Seal an evidence bundle into an encrypted proof bundle.",
  usage:
    "tf evidence seal --bundle <file> --recipients <recipients.json> --signer <actor> --key <priv> [--out <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("evidence seal")!);
    const file = flagOne(args, "bundle");
    const recipsPath = flagOne(args, "recipients");
    const signer = flagOne(args, "signer");
    const keyPath = flagOne(args, "key");
    if (!file || !recipsPath || !signer || !keyPath) {
      console.error(
        "usage: tf evidence seal --bundle <file> --recipients <r.json> --signer <actor> --key <priv>",
      );
      return 2;
    }
    const bundle = JSON.parse(readFileSync(resolve(file), "utf8"));
    const recipients = JSON.parse(readFileSync(resolve(recipsPath), "utf8")) as Parameters<
      typeof sealEvidenceBundle
    >[0]["recipients"];
    const signerPrivateKey = readPrivateKey(keyPath);
    const sealed = await sealEvidenceBundle({ bundle, recipients, signerPrivateKey, signer });
    const out = flagOne(args, "out");
    if (out) writeFileEnsuringDir(resolve(out), canonicalize(sealed));
    emitJson(args, sealed);
    return 0;
  },
});

register({
  noun: "evidence",
  verb: "open",
  summary: "Open a sealed evidence bundle.",
  usage: "tf evidence open --sealed <file> --recipient-key <file> --recipient-actor <id>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("evidence open")!);
    const file = flagOne(args, "sealed");
    const keyPath = flagOne(args, "recipient-key");
    const recipientActor = flagOne(args, "recipient-actor");
    if (!file || !keyPath || !recipientActor) {
      console.error(
        "usage: tf evidence open --sealed <file> --recipient-key <file> --recipient-actor <id>",
      );
      return 2;
    }
    const encrypted = JSON.parse(readFileSync(resolve(file), "utf8"));
    const recipientPrivateKey = readPrivateKey(keyPath);
    const bundle = await openEvidenceBundle({ encrypted, recipientPrivateKey, recipientActor });
    emitJson(args, bundle);
    return 0;
  },
});

register({
  noun: "evidence",
  verb: "anchor",
  summary: "Anchor an evidence bundle by attaching a stub inclusion proof.",
  usage: "tf evidence anchor --bundle <file> [--kind <merkle|rfc3161>] [--url <url>] [--out <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("evidence anchor")!);
    const file = flagOne(args, "bundle");
    if (!file) {
      console.error("usage: tf evidence anchor --bundle <file> [--kind <k>] [--url <u>]");
      return 2;
    }
    const bundle = JSON.parse(readFileSync(resolve(file), "utf8"));
    const kind = flagOne(args, "kind") ?? "merkle";
    const url = flagOne(args, "url");
    // Local-stub anchor backend: returns a deterministic inclusion proof.
    const stubAnchor = {
      kind,
      url,
      submit: async (_bytes: Uint8Array) => ({ inclusion_proof: { stub: true, kind, at: new Date().toISOString() } }),
    } as Parameters<typeof anchorEvidenceBundle>[0]["anchors"][number];
    const anchored = await anchorEvidenceBundle({ bundle, anchors: [stubAnchor] });
    const out = flagOne(args, "out");
    if (out) writeFileEnsuringDir(resolve(out), canonicalize(anchored));
    emitJson(args, anchored);
    return 0;
  },
});

register({
  noun: "evidence",
  verb: "replay",
  summary: "Replay an evidence bundle as a chronological timeline.",
  usage: "tf evidence replay --bundle <file>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("evidence replay")!);
    const file = flagOne(args, "bundle");
    if (!file) {
      console.error("usage: tf evidence replay --bundle <file>");
      return 2;
    }
    const bundle = JSON.parse(readFileSync(resolve(file), "utf8"));
    const timeline = replayEvidence(bundle);
    emitJson(args, { count: timeline.length, timeline });
    return 0;
  },
});

register({
  noun: "evidence",
  verb: "redact",
  summary: "Redact sensitive fields from an evidence bundle.",
  usage: "tf evidence redact --bundle <file> --policies <file> --key <priv> [--out <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("evidence redact")!);
    const file = flagOne(args, "bundle");
    const policiesPath = flagOne(args, "policies") ?? flagOne(args, "policy");
    const keyPath = flagOne(args, "key");
    if (!file || !policiesPath || !keyPath) {
      console.error("usage: tf evidence redact --bundle <file> --policies <file> --key <priv>");
      return 2;
    }
    const bundle = JSON.parse(readFileSync(resolve(file), "utf8"));
    const policies = readJsonOrYaml(policiesPath) as Parameters<typeof redactBundle>[1];
    const issuerPrivateKey = readPrivateKey(keyPath);
    const redacted = await redactBundle(bundle, policies, issuerPrivateKey);
    const out = flagOne(args, "out");
    if (out) writeFileEnsuringDir(resolve(out), canonicalize(redacted));
    emitJson(args, redacted);
    return 0;
  },
});

// ---------------------------------------------------------------------------
// proof commands (native — no shelling out)
// ---------------------------------------------------------------------------

register({
  noun: "proof",
  verb: "sign",
  summary: "Sign a proof event draft with a local signing key.",
  usage: "tf proof sign --event <file> --key <priv> --signer <actor> [--out <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("proof sign")!);
    const file = flagOne(args, "event");
    const keyPath = flagOne(args, "key");
    const signer = flagOne(args, "signer");
    if (!file || !keyPath || !signer) {
      console.error("usage: tf proof sign --event <file> --key <priv> --signer <actor>");
      return 2;
    }
    const draft = readJsonOrYaml(file) as Parameters<typeof buildProofEvent>[0];
    const built = buildProofEvent(draft);
    const privBytes = readPrivateKey(keyPath);
    const signed = await signProofEvent(built, signer, privBytes);
    const out = flagOne(args, "out");
    if (out) writeFileEnsuringDir(resolve(out), canonicalize(signed));
    emitJson(args, signed);
    return 0;
  },
});

register({
  noun: "proof",
  verb: "verify",
  summary: "Verify a chain of proof events against their signers.",
  usage: "tf proof verify --events <file>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("proof verify")!);
    const file = flagOne(args, "events") ?? args.positional[0];
    if (!file) {
      console.error("usage: tf proof verify --events <file>");
      return 2;
    }
    const raw = JSON.parse(readFileSync(resolve(file), "utf8"));
    const events: ProofEvent[] = Array.isArray(raw) ? raw : raw.events ?? [];
    try {
      verifyChain(events);
      emitJson(args, { ok: true, count: events.length });
      return 0;
    } catch (err) {
      emitJson(args, { ok: false, reason: (err as Error).message });
      return 1;
    }
  },
});

register({
  noun: "proof",
  verb: "inspect",
  summary: "Pretty-print a proof event with its derived hash.",
  usage: "tf proof inspect <file>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("proof inspect")!);
    const file = flagOne(args, "event") ?? args.positional[0];
    if (!file) {
      console.error("usage: tf proof inspect <file>");
      return 2;
    }
    const event = JSON.parse(readFileSync(resolve(file), "utf8")) as ProofEvent;
    const digest = eventDigest(event as never);
    emitJson(args, {
      event,
      hash: eventHash(event),
      digest_b64: b64encode(digest),
    });
    return 0;
  },
});

register({
  noun: "proof",
  verb: "derive-pubkey",
  summary: "Derive the public key from an ed25519 private key.",
  usage: "tf proof derive-pubkey --key <priv>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("proof derive-pubkey")!);
    const keyPath = flagOne(args, "key");
    if (!keyPath) {
      console.error("usage: tf proof derive-pubkey --key <priv>");
      return 2;
    }
    const priv = readPrivateKey(keyPath);
    const pub = await ed25519PublicKey(priv);
    emitJson(args, { public_key: b64encode(pub) });
    return 0;
  },
});

register({
  noun: "proof",
  verb: "log-tail",
  summary: "Tail recent proof events from a tflog file.",
  usage: "tf proof log-tail --file <tflog> [--n <count>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("proof log-tail")!);
    const file = flagOne(args, "file");
    if (!file) {
      console.error("usage: tf proof log-tail --file <tflog> [--n <count>]");
      return 2;
    }
    const n = parseInt(flagOne(args, "n") ?? "10", 10);
    const raw = readFileSync(resolve(file), "utf8");
    const events = raw
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l));
    const tail = events.slice(-n);
    emitJson(args, { count: tail.length, events: tail });
    return 0;
  },
});

// ---------------------------------------------------------------------------
// policy commands
// ---------------------------------------------------------------------------

register({
  noun: "policy",
  verb: "simulate",
  summary: "Simulate a policy / contract decision against a candidate action.",
  usage:
    "tf policy simulate <contract.yaml | policy.yaml> <action> [--target <t>] [--subject <actor>] [--policy <p>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("policy simulate")!);
    const file = args.positional[0];
    const action = flagOne(args, "action") ?? args.positional[1];
    const target = flagOne(args, "target");
    const subject = flagOne(args, "subject") ?? "tf:actor:process:local/policy-simulator";
    const policyFlag = flagOne(args, "policy");
    const enforcementFlag = flagOne(args, "enforcement-level");
    if (!file || !action) {
      console.error("usage: tf policy simulate <file> <action>");
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
      emitJson(args, decision);
      return decision.decision === "deny" ? 1 : 0;
    }
    const guard = AgentGuard.fromContract(doc);
    const decision = guard.check({ actor: subject, action, target });
    emitJson(args, decision);
    return decision.kind === "deny" ? 1 : 0;
  },
});

register({
  noun: "policy",
  verb: "validate",
  summary: "Validate a policy YAML against the schema (offline).",
  usage: "tf policy validate <policy.yaml>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("policy validate")!);
    const file = args.positional[0] ?? flagOne(args, "policy");
    if (!file) {
      console.error("usage: tf policy validate <policy.yaml>");
      return 2;
    }
    const doc = parseYAML(readFileSync(resolve(file), "utf8")) as Record<string, unknown>;
    const errors: string[] = [];
    if (typeof doc.policy_version !== "string") errors.push("missing policy_version");
    if (typeof doc.policy_id !== "string") errors.push("missing policy_id");
    if (typeof doc.trust_domain !== "string") errors.push("missing trust_domain");
    if (!Array.isArray(doc.rules)) errors.push("missing rules array");
    emitJson(args, { ok: errors.length === 0, errors });
    return errors.length === 0 ? 0 : 1;
  },
});

register({
  noun: "policy",
  verb: "lint",
  summary: "Lint a policy YAML for style and best-practice issues.",
  usage: "tf policy lint <policy.yaml>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("policy lint")!);
    const file = args.positional[0] ?? flagOne(args, "policy");
    if (!file) {
      console.error("usage: tf policy lint <policy.yaml>");
      return 2;
    }
    const doc = parseYAML(readFileSync(resolve(file), "utf8")) as Record<string, unknown>;
    const warnings: string[] = [];
    const rules = (doc.rules as Array<Record<string, unknown>>) ?? [];
    if (rules.length === 0) warnings.push("policy has zero rules");
    for (const r of rules) {
      if (!r.id) warnings.push("rule missing id");
      if (!r.decision) warnings.push(`rule ${r.id ?? "<unnamed>"} missing decision`);
    }
    emitJson(args, { ok: warnings.length === 0, warnings });
    return 0;
  },
});

register({
  noun: "policy",
  verb: "explain",
  summary: "Explain why a policy made a particular decision (trace the rule chain).",
  usage: "tf policy explain <policy.yaml> <action> [--target <t>] [--subject <a>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("policy explain")!);
    const file = args.positional[0];
    const action = args.positional[1] ?? flagOne(args, "action");
    if (!file || !action) {
      console.error("usage: tf policy explain <policy.yaml> <action>");
      return 2;
    }
    const policyDoc = parseYAML(readFileSync(resolve(file), "utf8")) as Policy;
    const engine = policyEngineForManifest(policyDoc) as NativePolicyEngine;
    const decision = engine.evaluate({
      subject: flagOne(args, "subject") ?? "tf:actor:process:local/policy-explainer",
      action,
      target: flagOne(args, "target"),
    });
    emitJson(args, {
      decision: decision.decision,
      reason: decision.reason,
      matched_rule: (decision as Record<string, unknown>).matched_rule ?? null,
      trace: (decision as Record<string, unknown>).trace ?? [],
    });
    return 0;
  },
});

// ---------------------------------------------------------------------------
// vault commands (offline)
// ---------------------------------------------------------------------------

const VAULT_DEFAULT = process.env.TF_VAULT_PATH ?? `${process.env.HOME ?? "."}/.trustforge/vault.json`;

function vaultPath(args: CliArgs): string {
  return flagOne(args, "path") ?? VAULT_DEFAULT;
}

function vaultPassphrase(args: CliArgs): string {
  return flagOne(args, "passphrase") ?? process.env.TF_VAULT_PASSPHRASE ?? "";
}

register({
  noun: "vault",
  verb: "init",
  summary: "Initialize a fresh passphrase-encrypted vault file.",
  usage: "tf vault init [--path <file>] [--passphrase <p>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("vault init")!);
    const passphrase = vaultPassphrase(args);
    if (!passphrase) {
      console.error("provide --passphrase or set TF_VAULT_PASSPHRASE");
      return 2;
    }
    const path = vaultPath(args);
    ensureDir(dirname(path));
    await Vault.createAtPath(path, passphrase, {
      m_cost: 256, // small param for tests
      t_cost: 1,
      p_cost: 1,
    });
    emitJson(args, { ok: true, path });
    return 0;
  },
});

register({
  noun: "vault",
  verb: "unlock",
  summary: "Verify the vault can be opened with the supplied passphrase.",
  usage: "tf vault unlock [--path <file>] [--passphrase <p>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("vault unlock")!);
    const passphrase = vaultPassphrase(args);
    const path = vaultPath(args);
    try {
      await Vault.openAtPath(path, passphrase);
      emitJson(args, { ok: true });
      return 0;
    } catch (err) {
      emitJson(args, { ok: false, error: (err as Error).message });
      return 1;
    }
  },
});

register({
  noun: "vault",
  verb: "lock",
  summary: "Lock the vault (no-op for file-backed vaults; documented for parity).",
  usage: "tf vault lock [--path <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("vault lock")!);
    emitJson(args, { ok: true, note: "file-backed vaults are sealed at rest; nothing to flush." });
    return 0;
  },
});

register({
  noun: "vault",
  verb: "store",
  summary: "Store a key in the vault.",
  usage:
    "tf vault store --id <id> --purpose signing|kem|attestation|raw --algorithm <a> --key <priv> [--passphrase <p>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("vault store")!);
    const id = flagOne(args, "id");
    const purpose = flagOne(args, "purpose") ?? "signing";
    const algorithm = flagOne(args, "algorithm") ?? "ed25519";
    const keyPath = flagOne(args, "key");
    if (!id || !keyPath) {
      console.error("usage: tf vault store --id <id> --key <priv>");
      return 2;
    }
    const passphrase = vaultPassphrase(args);
    const path = vaultPath(args);
    const vault = await Vault.openAtPath(path, passphrase);
    const keyBytes = readPrivateKey(keyPath);
    vault.store({ id, purpose: purpose as "signing", algorithm, key_bytes: keyBytes });
    emitJson(args, { ok: true, id });
    return 0;
  },
});

register({
  noun: "vault",
  verb: "retrieve",
  summary: "Read a key from the vault.",
  usage: "tf vault retrieve --id <id> [--passphrase <p>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("vault retrieve")!);
    const id = flagOne(args, "id");
    if (!id) {
      console.error("usage: tf vault retrieve --id <id>");
      return 2;
    }
    const passphrase = vaultPassphrase(args);
    const path = vaultPath(args);
    const vault = await Vault.openAtPath(path, passphrase);
    const entry = vault.read(id);
    emitJson(args, {
      id: entry.id,
      purpose: entry.purpose,
      algorithm: entry.algorithm,
      key_bytes_b64: b64encode(entry.key_bytes),
      created_at: entry.created_at,
    });
    return 0;
  },
});

register({
  noun: "vault",
  verb: "list",
  summary: "List entries in the vault (without secret material).",
  usage: "tf vault list [--passphrase <p>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("vault list")!, { entries: [] });
    const passphrase = vaultPassphrase(args);
    const path = vaultPath(args);
    const vault = await Vault.openAtPath(path, passphrase);
    emitJson(args, { entries: vault.list() });
    return 0;
  },
});

register({
  noun: "vault",
  verb: "rotate-passphrase",
  summary: "Rotate the vault's encryption passphrase.",
  usage: "tf vault rotate-passphrase --new-passphrase <p> [--passphrase <p>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("vault rotate-passphrase")!);
    const oldPassphrase = vaultPassphrase(args);
    const newPassphrase = flagOne(args, "new-passphrase");
    if (!newPassphrase) {
      console.error("usage: tf vault rotate-passphrase --new-passphrase <p>");
      return 2;
    }
    const path = vaultPath(args);
    const vault = await Vault.openAtPath(path, oldPassphrase);
    if (typeof (vault as unknown as { rotatePassphrase?: (p: string) => Promise<void> }).rotatePassphrase === "function") {
      await (vault as unknown as { rotatePassphrase: (p: string) => Promise<void> }).rotatePassphrase(newPassphrase);
      emitJson(args, { ok: true });
      return 0;
    }
    emitJson(args, { ok: false, error: "vault rotate-passphrase not supported by this build" });
    return 1;
  },
});

// ---------------------------------------------------------------------------
// conformance commands
// ---------------------------------------------------------------------------

register({
  noun: "conformance",
  verb: "run",
  summary: "Run the conformance suite against this checkout.",
  usage: "tf conformance run [--profile <id>] [--root <dir>] [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("conformance run")!, { passed: 0, failed: 0 });
    const conf = await import("tf-conformance");
    const profileId = flagOne(args, "profile");
    const daemonUrl = flagOne(args, "daemon");
    const root = resolve(flagOne(args, "root") ?? ".");
    const result = await conf.runAll({
      root,
      profileId,
      daemonUrl,
      adminToken: process.env.TF_ADMIN_TOKEN,
    });
    emitJson(args, result);
    return result.failed === 0 ? 0 : 1;
  },
});

register({
  noun: "conformance",
  verb: "label",
  summary: "Print the conformance label for a profile (e.g. TF-CONF-Home-E2-Draft).",
  usage: "tf conformance label --profile <id>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("conformance label")!);
    const profile = flagOne(args, "profile") ?? "home";
    emitJson(args, { profile, label: `TF-CONF-${profile.replace(/^./, (c) => c.toUpperCase())}-Draft` });
    return 0;
  },
});

register({
  noun: "conformance",
  verb: "list-categories",
  summary: "List conformance categories implemented by this build.",
  usage: "tf conformance list-categories",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("conformance list-categories")!, { categories: [] });
    const categories = [
      "schema",
      "signature",
      "guard",
      "trust-overlay",
      "bridge",
      "canonical",
      "decide-protocol",
      "binary-format",
      "chain",
      "framing",
      "session",
      "relay",
      "negative-cap",
      "profile",
      "interop",
      "fuzz",
      "security-regression",
    ];
    emitJson(args, { categories });
    return 0;
  },
});

// ---------------------------------------------------------------------------
// generate commands
// ---------------------------------------------------------------------------

interface GenContext {
  outDir: string;
  slug: string;
}

function generateContext(args: CliArgs): GenContext | undefined {
  const out = flagOne(args, "out");
  const slug = flagOne(args, "name") ?? "scaffold";
  if (!out) return undefined;
  const outDir = resolve(out);
  ensureDir(outDir);
  return { outDir, slug };
}

function genWrite(ctx: GenContext, rel: string, content: string): string {
  const dest = resolve(ctx.outDir, rel);
  writeFileEnsuringDir(dest, content);
  return dest;
}

function generateRegister(verb: string, fn: (ctx: GenContext) => string[]): void {
  register({
    noun: "generate",
    verb,
    summary: `Generate a ${verb} scaffold.`,
    usage: `tf generate ${verb} --out <dir> [--name <slug>]`,
    supportsDryRun: true,
    handler: async (args) => {
      if (args.dryRun) return dryRunStub(args, REGISTRY.get(`generate ${verb}`)!);
      const ctx = generateContext(args);
      if (!ctx) {
        console.error(`usage: tf generate ${verb} --out <dir> [--name <slug>]`);
        return 2;
      }
      const written = fn(ctx);
      emitJson(args, { generated: verb, dir: ctx.outDir, name: ctx.slug, files: written });
      return 0;
    },
  });
}

generateRegister("policy", (ctx) => [
  genWrite(
    ctx,
    "policy.yaml",
    [
      "policy_version: \"1\"",
      `policy_id: ${ctx.slug}-policy-1`,
      "trust_domain: local.example",
      "rules:",
      "  - rule_version: \"1\"",
      `    id: ${ctx.slug}-deny-irreversible`,
      "    when:",
      "      action: \"*\"",
      "      danger_tags: [irreversible]",
      "    decision: deny",
      "    reason: \"irreversible actions require quorum\"",
      "negative_capabilities: []",
      "",
    ].join("\n"),
  ),
]);

generateRegister("mcp-tool-wrapper", (ctx) => [
  genWrite(
    ctx,
    "mcp-bridge.yaml",
    [
      "bridge_version: \"1\"",
      `bridge_id: ${ctx.slug}-mcp`,
      "kind: mcp",
      `actor_id: tf:actor:bridge:local.example/${ctx.slug}-mcp`,
      "tools: []",
      "",
    ].join("\n"),
  ),
  genWrite(ctx, "README.md", `# ${ctx.slug} MCP bridge\nGenerated by \`tf generate mcp-tool-wrapper\`.\n`),
]);

generateRegister("audit-viewer", (ctx) => [
  genWrite(
    ctx,
    "audit-viewer.html",
    [
      "<!doctype html>",
      "<meta charset=\"utf-8\">",
      `<title>${ctx.slug} audit viewer</title>`,
      "<h1>TrustForge audit viewer</h1>",
      "<p>Loaded events appear below.</p>",
      "<pre id=\"out\">loading…</pre>",
      "<script>",
      "  fetch('events.json').then(r => r.json()).then(j => document.getElementById('out').textContent = JSON.stringify(j, null, 2));",
      "</script>",
      "",
    ].join("\n"),
  ),
]);

generateRegister("bridge", (ctx) => [
  genWrite(
    ctx,
    "bridge.ts",
    [
      "import type { Bridge, BridgeKind } from \"tf-types\";",
      `export class ${ctx.slug.replace(/[^a-zA-Z0-9]/g, "_")}Bridge implements Bridge {`,
      "  readonly kind: BridgeKind = \"custom\";",
      `  constructor(public readonly bridgeId = "${ctx.slug}-bridge") {}`,
      "}",
      "",
    ].join("\n"),
  ),
]);

generateRegister("proofrpc-service", (ctx) => [
  genWrite(
    ctx,
    "service.tfrpc.yaml",
    [
      "rpc_version: \"1\"",
      `service: ${ctx.slug}.v1`,
      "methods:",
      "  - name: ping",
      "    kind: unary",
      "    request: \"#PingRequest\"",
      "    response: \"#PingResponse\"",
      "schemas:",
      "  PingRequest:",
      "    type: object",
      "    properties:",
      "      message: { type: string }",
      "  PingResponse:",
      "    type: object",
      "    properties:",
      "      ok: { type: boolean }",
      "      at: { type: string, format: date-time }",
      "",
    ].join("\n"),
  ),
]);

generateRegister("threat-model", (ctx) => [
  genWrite(
    ctx,
    "threat-model.yaml",
    [
      "threat_model_version: \"1\"",
      `project: ${ctx.slug}`,
      "trust_boundaries: []",
      "threats: []",
      "mitigations: []",
      "residual_risks: []",
      "",
    ].join("\n"),
  ),
]);

generateRegister("agent-contract", (ctx) => [
  genWrite(
    ctx,
    "agent-contract.yaml",
    [
      "contract_version: \"1\"",
      "spec_version: TF-0006-draft",
      `project: ${ctx.slug}`,
      "trust_domain: local.example",
      "actions:",
      "  - name: tf.ping",
      "    risk: R0",
      "    approval: none",
      "",
    ].join("\n"),
  ),
]);

generateRegister("dockerfile", (ctx) => [
  genWrite(
    ctx,
    "Dockerfile",
    [
      "FROM oven/bun:1 AS base",
      "WORKDIR /app",
      "COPY . .",
      "RUN bun install --frozen-lockfile",
      `ENV TF_PROJECT=${ctx.slug}`,
      "EXPOSE 8787",
      "CMD [\"bun\", \"run\", \"tools/tf-daemon/src/cli.ts\", \"start\"]",
      "",
    ].join("\n"),
  ),
]);

generateRegister("k8s-manifest", (ctx) => [
  genWrite(
    ctx,
    "deployment.yaml",
    [
      "apiVersion: apps/v1",
      "kind: Deployment",
      "metadata:",
      `  name: ${ctx.slug}-tf-daemon`,
      "spec:",
      "  replicas: 1",
      "  selector:",
      `    matchLabels: { app: ${ctx.slug}-tf-daemon }`,
      "  template:",
      "    metadata:",
      `      labels: { app: ${ctx.slug}-tf-daemon }`,
      "    spec:",
      "      containers:",
      `        - name: tf-daemon`,
      `          image: trustforge/tf-daemon:0.1`,
      `          ports: [{ containerPort: 8787 }]`,
      "",
    ].join("\n"),
  ),
]);

generateRegister("terraform-module", (ctx) => [
  genWrite(
    ctx,
    "main.tf",
    [
      `# ${ctx.slug} TrustForge Terraform module scaffold`,
      "terraform { required_version = \">= 1.6\" }",
      `variable \"profile\" { default = \"home\" }`,
      `variable \"daemon_image\" { default = \"trustforge/tf-daemon:0.1\" }`,
      "",
    ].join("\n"),
  ),
]);

// ---------------------------------------------------------------------------
// daemon control commands
// ---------------------------------------------------------------------------

register({
  noun: "daemon",
  verb: "start",
  summary: "Print the command to start the TrustForge daemon (does not fork).",
  usage: "tf daemon start [--port <n>] [--config <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("daemon start")!);
    const port = flagOne(args, "port") ?? "8787";
    const cfg = flagOne(args, "config");
    const cmd = ["bun", "run", "tools/tf-daemon/src/cli.ts", "start", "--port", port];
    if (cfg) cmd.push("--config", cfg);
    emitJson(args, { command: cmd.join(" "), note: "tf-cli does not spawn the daemon — run this command yourself." });
    return 0;
  },
});

register({
  noun: "daemon",
  verb: "stop",
  summary: "Request the daemon to shut down via its admin API.",
  usage: "tf daemon stop [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("daemon stop")!);
    try {
      const out = await adminPost(args, "/admin/shutdown", {});
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "daemon",
  verb: "status",
  summary: "Get the daemon's runtime status.",
  usage: "tf daemon status [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("daemon status")!, { ok: true, status: "unknown" });
    try {
      const out = await adminGet(args, "/admin/status");
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "daemon",
  verb: "reload-config",
  summary: "Trigger a config reload on the daemon.",
  usage: "tf daemon reload-config [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("daemon reload-config")!);
    try {
      const out = await adminPost(args, "/admin/reload-config", {});
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

register({
  noun: "daemon",
  verb: "dump-config",
  summary: "Dump the active daemon configuration.",
  usage: "tf daemon dump-config [--daemon <url>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("daemon dump-config")!, { config: {} });
    try {
      const out = await adminGet(args, "/admin/config");
      emitJson(args, out);
      return 0;
    } catch (err) {
      console.error((err as Error).message);
      return 1;
    }
  },
});

// ---------------------------------------------------------------------------
// adapter commands
// ---------------------------------------------------------------------------

register({
  noun: "adapter",
  verb: "list",
  summary: "List installed compatibility adapters (TS / Rust / native).",
  usage: "tf adapter list",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("adapter list")!, { adapters: [] });
    const root = resolve(import.meta.dir, "..", "..", "..", "tools", "adapters");
    let adapters: Array<{ language: string; name: string; path: string }> = [];
    if (existsSync(root)) {
      const { readdirSync, statSync } = await import("node:fs");
      for (const lang of readdirSync(root)) {
        const langDir = resolve(root, lang);
        if (!statSync(langDir).isDirectory()) continue;
        for (const name of readdirSync(langDir)) {
          const path = resolve(langDir, name);
          if (statSync(path).isDirectory()) {
            adapters.push({ language: lang, name, path });
          }
        }
      }
    }
    emitJson(args, { adapters });
    return 0;
  },
});

register({
  noun: "adapter",
  verb: "install",
  summary: "Install a compatibility adapter into a host project.",
  usage: "tf adapter install --name <pkg> [--target <dir>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("adapter install")!);
    const name = flagOne(args, "name");
    if (!name) {
      console.error("usage: tf adapter install --name <pkg>");
      return 2;
    }
    emitJson(args, {
      ok: true,
      hint: `add @trustforge/${name} to your host project's manifest. tf-cli does not modify host package files.`,
    });
    return 0;
  },
});

register({
  noun: "adapter",
  verb: "config",
  summary: "Print or update an adapter's configuration template.",
  usage: "tf adapter config --name <pkg> [--out <file>]",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("adapter config")!);
    const name = flagOne(args, "name");
    if (!name) {
      console.error("usage: tf adapter config --name <pkg>");
      return 2;
    }
    const template = {
      adapter: name,
      daemon_url: "http://127.0.0.1:8787",
      profile: "home",
      mode: "observe-only",
    };
    const out = flagOne(args, "out");
    if (out) writeFileEnsuringDir(resolve(out), canonicalize(template));
    emitJson(args, template);
    return 0;
  },
});

register({
  noun: "adapter",
  verb: "test",
  summary: "Round-trip a sample request through an installed adapter.",
  usage: "tf adapter test --name <pkg> --request <file>",
  supportsDryRun: true,
  handler: async (args) => {
    if (args.dryRun) return dryRunStub(args, REGISTRY.get("adapter test")!);
    return notImplemented(args, REGISTRY.get("adapter test")!,
      "adapter test requires a running host process; use --dry-run to validate the CLI surface offline.");
  },
});

// ---------------------------------------------------------------------------
// Top-level usage + dispatcher
// ---------------------------------------------------------------------------

export function listCommands(): CommandSpec[] {
  return Array.from(REGISTRY.values()).sort((a, b) => key(a.noun, a.verb).localeCompare(key(b.noun, b.verb)));
}

function topLevelUsage(args: CliArgs): number {
  const grouped = new Map<string, CommandSpec[]>();
  for (const spec of listCommands()) {
    const arr = grouped.get(spec.noun) ?? [];
    arr.push(spec);
    grouped.set(spec.noun, arr);
  }
  if (args.json) {
    emitJson(
      args,
      Object.fromEntries(
        Array.from(grouped.entries()).map(([noun, specs]) => [
          noun,
          specs.map((s) => ({ verb: s.verb, summary: s.summary })),
        ]),
      ),
    );
    return 0;
  }
  const lines: string[] = [];
  lines.push("usage: tf <noun> <verb> [flags]");
  lines.push("");
  lines.push("Common flags: --json --quiet --dry-run --help");
  lines.push("");
  for (const noun of Array.from(grouped.keys()).sort()) {
    const specs = grouped.get(noun)!;
    lines.push(`${noun}:`);
    for (const s of specs) {
      lines.push(`  tf ${s.noun} ${s.verb} — ${s.summary}`);
    }
    lines.push("");
  }
  console.log(lines.join("\n"));
  return 0;
}

// Aliases for verbs that registered with hyphenated forms (e.g. "spiffe-import")
// when the original plan wrote them as nested subcommands ("spiffe import").
const VERB_ALIASES: Array<{ noun: string; route: (parts: string[]) => string | undefined }> = [
  {
    noun: "bridge",
    route: (parts) => {
      // tf bridge spiffe import → bridge.spiffe-import
      // tf bridge oauth register-issuer → bridge.oauth-register-issuer
      // tf bridge webauthn register → bridge.webauthn-register
      const [head, tail] = parts;
      if (!head) return undefined;
      if (tail) return `${head}-${tail}`;
      return head;
    },
  },
];

function resolveCommand(noun: string, restArgs: string[]): { spec: CommandSpec; consumed: number } | undefined {
  // Try the longest-prefix match. We allow "bridge spiffe import" → "bridge spiffe-import".
  // Step 1: try the simple [noun, verb] form first.
  const verb = restArgs[0];
  if (verb) {
    const direct = REGISTRY.get(key(noun, verb));
    if (direct) return { spec: direct, consumed: 1 };
  }

  const alias = VERB_ALIASES.find((a) => a.noun === noun);
  if (alias) {
    // Try two-token alias.
    const aliasVerb = alias.route([restArgs[0] ?? "", restArgs[1] ?? ""]);
    if (aliasVerb) {
      const found = REGISTRY.get(key(noun, aliasVerb));
      if (found) return { spec: found, consumed: 2 };
    }
    // Try one-token alias.
    const aliasVerb1 = alias.route([restArgs[0] ?? ""]);
    if (aliasVerb1) {
      const found = REGISTRY.get(key(noun, aliasVerb1));
      if (found) return { spec: found, consumed: 1 };
    }
  }
  return undefined;
}

export async function run(argv: string[]): Promise<number> {
  // The top-level argv shape is: [noun] [verb...] [flags / positionals]
  // We strip the noun + verb tokens, then parse the rest.
  const [noun, ...restRaw] = argv;

  // Top-level help.
  if (!noun || noun === "--help" || noun === "-h" || noun === "help") {
    const args = parseArgs(restRaw);
    return topLevelUsage(args);
  }

  // Top-level json listing.
  if (noun === "--list" || noun === "list-commands") {
    const args = parseArgs(restRaw);
    args.json = true;
    return topLevelUsage(args);
  }

  // Resolve the command (handles 1- or 2-token verbs).
  const resolved = resolveCommand(noun, restRaw);
  if (!resolved) {
    // Allow `tf <noun> --help` to print the noun's verbs.
    if (restRaw.includes("--help")) {
      const verbs = listCommands().filter((c) => c.noun === noun);
      if (verbs.length > 0) {
        const args = parseArgs(restRaw);
        if (args.json) {
          emitJson(args, verbs.map((v) => ({ verb: v.verb, summary: v.summary })));
        } else {
          console.log(`tf ${noun} <verb> [flags]`);
          for (const v of verbs) console.log(`  ${v.verb} — ${v.summary}`);
        }
        return 0;
      }
    }
    console.error(`unknown command: tf ${noun} ${restRaw.join(" ")}`.trim());
    console.error("run `tf --help` for the full subcommand list.");
    return 2;
  }

  const cmdArgs = parseArgs(restRaw.slice(resolved.consumed));
  if (cmdArgs.help) return showHelp(cmdArgs, resolved.spec);
  return await resolved.spec.handler(cmdArgs);
}

// Run when executed as a script.
if (import.meta.main) {
  const exit = await run(process.argv.slice(2));
  process.exit(exit);
}
