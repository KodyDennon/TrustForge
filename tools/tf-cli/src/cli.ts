#!/usr/bin/env bun
/**
 * Unified `tf` command. Dispatches to the specialized CLIs and adds the
 * Sprint-6 admin / introspection operations.
 */

import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYAML } from "yaml";
import {
  AgentGuard,
  NativePolicyEngine,
  RpcClient,
  b64encode,
  canonicalize,
  ed25519Generate,
  ed25519PublicKey,
  policyEngineForManifest,
  signFederationAttestation,
  verifyFederationAttestation,
  type FederationAttestation,
  type Packet,
} from "tf-types";
import type { Policy } from "../../tf-types-ts/src/generated/policy.js";
import {
  attachInitiator,
  rpcTransportFromEndpoint,
  type SessionEndpoint,
} from "tf-session";

function arg(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

function multiArg(args: string[], flag: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length - 1; i++) {
    if (args[i] === flag && args[i + 1]) {
      out.push(args[i + 1]!);
      i += 1;
    }
  }
  return out;
}

function flag(args: string[], name: string): boolean {
  return args.includes(name);
}

function adminBase(args: string[]): string {
  return arg(args, "--daemon") ?? process.env.TF_ADMIN_URL ?? "http://127.0.0.1:8787";
}

function adminToken(): string {
  return process.env.TF_ADMIN_TOKEN ?? "";
}

async function adminGet(args: string[], path: string): Promise<unknown> {
  const url = `${adminBase(args)}${path}`;
  const res = await fetch(url, {
    headers: { authorization: `Bearer ${adminToken()}` },
  });
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
  }
  return await res.json();
}

async function adminPost(args: string[], path: string, body: unknown): Promise<unknown> {
  const url = `${adminBase(args)}${path}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${adminToken()}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body ?? {}),
  });
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
  }
  return await res.json();
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
  const scope = multiArg(args, "--scope");
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

async function trustDomainInit(args: string[]): Promise<number> {
  const name = arg(args, "--name");
  const out = arg(args, "--out");
  if (!name) {
    console.error("usage: tf trust-domain init --name <domain> [--out <bundle.json>] [--keys <int>]");
    return 2;
  }
  const keys = parseInt(arg(args, "--keys") ?? "1", 10);
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
  const output = canonicalize({ bundle, private_keys: privateKeys });
  if (out) writeFileSync(resolve(out), output);
  console.log(output);
  return 0;
}

async function bridgeSpiffeImport(args: string[]): Promise<number> {
  const file = arg(args, "--bundle");
  const issuer = arg(args, "--issuer");
  const issuerDomain = arg(args, "--issuer-domain");
  const validUntil = arg(args, "--valid-until");
  if (!file || !issuer || !issuerDomain || !validUntil) {
    console.error(
      "usage: tf bridge spiffe import --bundle <jwks.json> --issuer <actor> --issuer-domain <d> --valid-until <iso> [--out <file>]",
    );
    return 2;
  }
  const tf = await import("tf-types");
  const raw = readFileSync(resolve(file), "utf8");
  const parsed = JSON.parse(raw) as { trust_domain: string; keys: Array<Record<string, unknown>> };
  const draft = tf.attestationFromSpiffeBundle(parsed, {
    issuerDomain,
    issuer,
    validUntil,
  });
  const output = canonicalize(draft);
  const out = arg(args, "--out");
  if (out) writeFileSync(resolve(out), output);
  console.log(output);
  return 0;
}

async function packetInspect(args: string[]): Promise<number> {
  const file = arg(args, "--packet") ?? args[0];
  if (!file) {
    console.error("usage: tf packet inspect <file> | --packet <file>");
    return 2;
  }
  const packet = JSON.parse(readFileSync(resolve(file), "utf8")) as Packet;
  console.log(canonicalize({
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
  }));
  return 0;
}

async function evidenceForward(sub: string, args: string[]): Promise<number> {
  // Forward to tf-evidence's CLI. tf-cli refuses to shell out for
  // schema/proof/daemon (those are a different process surface), but
  // tf-evidence is a sibling tool that we expose under `tf evidence`
  // for ergonomics; killing the dispatcher entirely is post-0.1.0.
  const child = Bun.spawn(
    ["bun", "run", resolve(__dirname, "../../tf-evidence/src/cli.ts"), sub, ...args],
    { stdio: ["inherit", "inherit", "inherit"] },
  );
  return await child.exited;
}

async function pluginList(args: string[]): Promise<number> {
  const out = await adminGet(args, "/admin/plugins");
  console.log(canonicalize(out));
  return 0;
}

async function sessionInspect(args: string[]): Promise<number> {
  const out = await adminGet(args, "/admin/sessions");
  console.log(canonicalize(out));
  return 0;
}

async function approvalList(args: string[]): Promise<number> {
  const out = await adminGet(args, "/admin/approvals");
  console.log(canonicalize(out));
  return 0;
}

async function approve(args: string[]): Promise<number> {
  const id = args[0];
  if (!id) {
    console.error("usage: tf approve <id> [--note <text>] [--daemon <url>]");
    return 2;
  }
  const note = arg(args.slice(1), "--note");
  const out = await adminPost(args, `/admin/approvals/${encodeURIComponent(id)}/approve`, note ? { note } : {});
  console.log(canonicalize(out));
  const ok = (out as { ok?: boolean }).ok;
  return ok ? 0 : 1;
}

async function deny(args: string[]): Promise<number> {
  const id = args[0];
  if (!id) {
    console.error("usage: tf deny <id> [--note <text>] [--daemon <url>]");
    return 2;
  }
  const note = arg(args.slice(1), "--note");
  const out = await adminPost(args, `/admin/approvals/${encodeURIComponent(id)}/deny`, note ? { note } : {});
  console.log(canonicalize(out));
  const ok = (out as { ok?: boolean }).ok;
  return ok ? 0 : 1;
}

async function revoke(args: string[]): Promise<number> {
  const kind = args[0];
  const id = args[1];
  if (!kind || !id) {
    console.error("usage: tf revoke <kind:actor|capability|delegation|instance> <id> [--reason <text>] [--daemon <url>]");
    return 2;
  }
  const reason = arg(args.slice(2), "--reason");
  const out = await adminPost(args, "/admin/revocations", { kind, id, reason });
  console.log(canonicalize(out));
  return 0;
}

async function rpcCall(args: string[]): Promise<number> {
  const url = arg(args, "--url");
  const method = arg(args, "--method");
  const requestPath = arg(args, "--request");
  const keyPath = arg(args, "--key");
  const claim = arg(args, "--claim");
  if (arg(args, "--caller")) {
    console.error(
      "error: --caller was removed; the caller actor URI is now derived from the key (tf:actor:process:key/<thumbprint>). Use --claim <uri> if you want to advertise a self-claimed alias.",
    );
    return 2;
  }
  if (!url || !method || !keyPath) {
    console.error(
      "usage: tf rpc call --url <ws://host:port> --method <name> --key <priv> [--request <json|@file>] [--claim <self-claimed-actor-uri>]",
    );
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
  const keyJson = JSON.parse(readFileSync(resolve(keyPath), "utf8")) as { key_bytes_b64?: string; key_bytes?: string };
  const privBytes = new Uint8Array(Buffer.from(keyJson.key_bytes_b64 ?? keyJson.key_bytes ?? "", "base64"));
  const pubBytes = await ed25519PublicKey(privBytes);
  const tf = await import("tf-types");
  const callerActor = tf.derivePeerActor(pubBytes);
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
    const data = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : new TextEncoder().encode(String(ev.data));
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
  console.log(canonicalize(response));
  endpoint.close("rpc.call complete");
  ws.close();
  return 0;
}

async function conformanceRun(args: string[]): Promise<number> {
  const conf = await import("tf-conformance");
  const profileId = arg(args, "--profile");
  const daemonUrl = arg(args, "--daemon");
  const root = resolve(arg(args, "--root") ?? ".");
  const result = await conf.runAll({
    root,
    profileId,
    daemonUrl,
    adminToken: process.env.TF_ADMIN_TOKEN,
  });
  console.log(canonicalize(result));
  return result.failed === 0 ? 0 : 1;
}

const GENERATOR_TARGETS = ["policy", "mcp-tool-wrapper", "audit-viewer", "bridge", "proofrpc-service"] as const;
type GeneratorTarget = typeof GENERATOR_TARGETS[number];

async function generate(args: string[]): Promise<number> {
  const target = args[0] as GeneratorTarget | undefined;
  const out = arg(args, "--out");
  const name = arg(args, "--name");
  if (!target || !GENERATOR_TARGETS.includes(target)) {
    console.error(`usage: tf generate <${GENERATOR_TARGETS.join("|")}> --out <dir> [--name <slug>]`);
    return 2;
  }
  if (!out) {
    console.error("--out <dir> is required");
    return 2;
  }
  const outDir = resolve(out);
  await Bun.spawnSync(["mkdir", "-p", outDir]);
  const slug = name ?? "scaffold";

  const writeFile = (rel: string, content: string) => {
    const dest = resolve(outDir, rel);
    Bun.spawnSync(["mkdir", "-p", resolve(dest, "..")]);
    writeFileSync(dest, content);
  };

  switch (target) {
    case "policy": {
      writeFile("policy.yaml", [
        "policy_version: \"1\"",
        `policy_id: ${slug}-policy-1`,
        `trust_domain: local.example`,
        "rules:",
        "  - rule_version: \"1\"",
        `    id: ${slug}-deny-irreversible`,
        "    when:",
        "      action: \"*\"",
        "      danger_tags: [irreversible]",
        "    decision: deny",
        "    reason: \"irreversible actions require quorum\"",
        "negative_capabilities: []",
        "",
      ].join("\n"));
      break;
    }
    case "mcp-tool-wrapper": {
      writeFile("mcp-bridge.yaml", [
        "bridge_version: \"1\"",
        `bridge_id: ${slug}-mcp`,
        "kind: mcp",
        `actor_id: tf:actor:bridge:local.example/${slug}-mcp`,
        "tools: []",
        "",
      ].join("\n"));
      writeFile("README.md", `# ${slug} MCP bridge\nGenerated by \`tf generate mcp-tool-wrapper\`.\n`);
      break;
    }
    case "audit-viewer": {
      writeFile("audit-viewer.html", [
        "<!doctype html>",
        "<meta charset=\"utf-8\">",
        `<title>${slug} audit viewer</title>`,
        "<h1>TrustForge audit viewer</h1>",
        "<p>Loaded events appear below.</p>",
        "<pre id=\"out\">loading…</pre>",
        "<script>",
        "  fetch('events.json').then(r => r.json()).then(j => document.getElementById('out').textContent = JSON.stringify(j, null, 2));",
        "</script>",
        "",
      ].join("\n"));
      break;
    }
    case "bridge": {
      writeFile("bridge.ts", [
        "import type { Bridge, BridgeKind } from \"tf-types\";",
        `export class ${slug.replace(/[^a-zA-Z0-9]/g, "_")}Bridge implements Bridge {`,
        "  readonly kind: BridgeKind = \"custom\";",
        `  constructor(public readonly bridgeId = "${slug}-bridge") {}`,
        "}",
        "",
      ].join("\n"));
      break;
    }
    case "proofrpc-service": {
      writeFile("service.tfrpc.yaml", [
        "rpc_version: \"1\"",
        `service: ${slug}.v1`,
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
      ].join("\n"));
      break;
    }
  }
  console.log(canonicalize({ generated: target, dir: outDir, name: slug }));
  return 0;
}

function usage(): number {
  console.error([
    "usage: tf <command> [args]",
    "",
    "introspection / admin (require running daemon + TF_ADMIN_TOKEN):",
    "  tf session inspect [--daemon <url>]",
    "  tf approval list   [--daemon <url>]",
    "  tf approve <id> [--note <text>] [--daemon <url>]",
    "  tf deny <id> [--note <text>] [--daemon <url>]",
    "  tf revoke <kind> <id> [--reason <text>] [--daemon <url>]",
    "  tf plugin list [--daemon <url>]",
    "",
    "policy + identity (offline):",
    "  tf policy simulate <contract|policy> <action>",
    "  tf actor create --name slug [--type t] [--domain d] [--out file]",
    "  tf actor inspect <file>",
    "  tf trust-domain init --name <domain> [--keys <n>] [--out <file>]",
    "  tf trust-domain federate ...",
    "  tf trust-domain verify-federation ...",
    "  tf bridge spiffe import --bundle <jwks.json> --issuer <actor> --issuer-domain <d> --valid-until <iso>",
    "  tf packet inspect <file>",
    "",
    "live RPC:",
    "  tf rpc call --url <ws://...> --method <name> --key <priv> [--request <json|@file>]",
    "",
    "evidence (forwards to tf-evidence):",
    "  tf evidence assemble ...",
    "",
    "conformance + scaffolding:",
    "  tf conformance run [--profile <id>] [--root <dir>]",
    "  tf generate <policy|mcp-tool-wrapper|audit-viewer|bridge|proofrpc-service> --out <dir> [--name <slug>]",
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
  if (cmd === "trust-domain" && sub === "init") return trustDomainInit(rest);
  if (cmd === "trust-domain" && sub === "federate") return trustDomainFederate(rest);
  if (cmd === "trust-domain" && sub === "verify-federation") return trustDomainVerifyFederation(rest);
  if (cmd === "bridge" && sub === "spiffe") {
    const [op, ...spiffeRest] = rest;
    if (op === "import") return bridgeSpiffeImport(spiffeRest);
  }
  if (cmd === "packet" && sub === "inspect") return packetInspect(rest);
  if (cmd === "session" && sub === "inspect") return sessionInspect(rest);
  if (cmd === "approval" && sub === "list") return approvalList(rest);
  if (cmd === "approve") return approve([sub ?? "", ...rest].filter((s) => s !== ""));
  if (cmd === "deny") return deny([sub ?? "", ...rest].filter((s) => s !== ""));
  if (cmd === "revoke") return revoke([sub ?? "", ...rest].filter((s) => s !== ""));
  if (cmd === "plugin" && sub === "list") return pluginList(rest);
  if (cmd === "rpc" && sub === "call") return rpcCall(rest);
  if (cmd === "evidence" && typeof sub === "string") {
    const allowed = new Set(["assemble", "verify", "seal", "open", "anchor", "replay", "redact"]);
    if (allowed.has(sub)) return evidenceForward(sub, rest);
  }
  if (cmd === "conformance" && sub === "run") return conformanceRun(rest);
  if (cmd === "generate") return generate([sub ?? "", ...rest].filter((s) => s !== ""));

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
