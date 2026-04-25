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
  b64encode,
  canonicalize,
  ed25519Generate,
  ed25519PublicKey,
} from "tf-types";

function arg(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

async function policySimulate(args: string[]): Promise<number> {
  const contract = args[0];
  const action = arg(args, "--action") ?? args[1];
  const target = arg(args, "--target");
  if (!contract || !action) {
    console.error("usage: tf policy simulate <contract.yaml> <action> [--target <t>]");
    return 2;
  }
  const raw = readFileSync(resolve(contract), "utf8");
  const doc = parseYAML(raw) as Record<string, unknown>;
  const guard = AgentGuard.fromContract(doc);
  const decision = guard.check({
    actor: "tf:actor:process:local/policy-simulator",
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
