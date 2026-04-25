#!/usr/bin/env bun
/**
 * tf-packet CLI — sign, verify, inspect, fragment, reassemble, and
 * simulate transport-loss for TrustForge packets (TF-0011).
 *
 * Subcommands:
 *   sign       --source <a> --destination <b> --priority <P0..P5> [--emergency]
 *              --payload <file> --key <ed25519-priv-file> [--out <file>]
 *              [--encoding cbor|json] [--compression none|deflate]
 *              [--expires-at <iso>] [--ttl-hops <n>]
 *   verify     --packet <file> --pubkey <ed25519-pub-file> [--now <iso>]
 *   inspect    --packet <file>
 *   fragment   --packet <file> --key <priv> [--mtu <bytes>] [--out-dir <dir>]
 *   reassemble --in-dir <dir> [--out <file>]
 *   simulate-lora --packet <file> [--count <n>] [--packet-loss 0..1]
 *                 [--bandwidth-bps <n>] [--base-latency-ms <n>]
 */

import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  fragmentPacket,
  reassembleFragments,
  signPacket,
  simulateLora,
  verifyPacket,
  type Packet,
  type Priority,
} from "tf-types";

function arg(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

function flag(args: string[], name: string): boolean {
  return args.includes(name);
}

function readPriv(path: string): Uint8Array {
  const raw = JSON.parse(readFileSync(resolve(path), "utf8")) as { key_bytes_b64?: string; key_bytes?: string };
  const b64 = raw.key_bytes_b64 ?? raw.key_bytes;
  if (!b64) throw new Error(`${path} has no key_bytes / key_bytes_b64`);
  return new Uint8Array(Buffer.from(b64, "base64"));
}

function readPub(path: string): Uint8Array {
  const raw = JSON.parse(readFileSync(resolve(path), "utf8")) as { public_key?: string; key_bytes_b64?: string };
  const b64 = raw.public_key ?? raw.key_bytes_b64;
  if (!b64) throw new Error(`${path} has no public_key / key_bytes_b64`);
  return new Uint8Array(Buffer.from(b64, "base64"));
}

async function cmdSign(args: string[]): Promise<number> {
  const source = arg(args, "--source");
  const dest = arg(args, "--destination");
  const priority = (arg(args, "--priority") ?? "P3") as Priority;
  const payloadPath = arg(args, "--payload");
  const keyPath = arg(args, "--key");
  if (!source || !dest || !payloadPath || !keyPath) {
    console.error("usage: tf-packet sign --source <a> --destination <b> --priority <P0..P5> [--emergency] --payload <file> --key <priv> [--out <file>]");
    return 2;
  }
  const payload = readFileSync(resolve(payloadPath));
  const priv = readPriv(keyPath);
  const packetId = arg(args, "--packet-id") ?? `pkt-${Date.now().toString(16)}`;
  const packet = await signPacket({
    packetId,
    source,
    destination: dest,
    priority,
    emergency: flag(args, "--emergency"),
    payload: new Uint8Array(payload),
    encoding: (arg(args, "--encoding") as "cbor" | "json" | undefined),
    compression: (arg(args, "--compression") as "none" | "deflate" | undefined),
    expiresAt: arg(args, "--expires-at"),
    ttlHops: arg(args, "--ttl-hops") ? Number(arg(args, "--ttl-hops")) : undefined,
    privateKey: priv,
    signer: source,
  });
  const out = arg(args, "--out");
  const json = JSON.stringify(packet, null, 2);
  if (out) writeFileSync(resolve(out), json);
  else console.log(json);
  return 0;
}

async function cmdVerify(args: string[]): Promise<number> {
  const path = arg(args, "--packet");
  const pubPath = arg(args, "--pubkey");
  if (!path || !pubPath) {
    console.error("usage: tf-packet verify --packet <file> --pubkey <pub> [--now <iso>]");
    return 2;
  }
  const packet = JSON.parse(readFileSync(resolve(path), "utf8")) as Packet;
  const pub = readPub(pubPath);
  const now = arg(args, "--now") ?? new Date().toISOString();
  const v = await verifyPacket(packet, pub, now);
  console.log(JSON.stringify({ ok: v.ok, reason: v.reason }, null, 2));
  return v.ok ? 0 : 1;
}

async function cmdInspect(args: string[]): Promise<number> {
  const path = arg(args, "--packet");
  if (!path) {
    console.error("usage: tf-packet inspect --packet <file>");
    return 2;
  }
  const packet = JSON.parse(readFileSync(resolve(path), "utf8")) as Packet;
  console.log(JSON.stringify(
    {
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
      fragment: packet.fragment,
      signer: packet.signature.signer,
      signature_algorithm: packet.signature.algorithm,
    },
    null,
    2,
  ));
  return 0;
}

async function cmdFragment(args: string[]): Promise<number> {
  const path = arg(args, "--packet");
  const keyPath = arg(args, "--key");
  if (!path || !keyPath) {
    console.error("usage: tf-packet fragment --packet <file> --key <priv> [--mtu <bytes>] [--out-dir <dir>]");
    return 2;
  }
  const packet = JSON.parse(readFileSync(resolve(path), "utf8")) as Packet;
  const priv = readPriv(keyPath);
  const mtu = Number(arg(args, "--mtu") ?? 256);
  const fragments = await fragmentPacket(packet, priv, { mtu });
  const dir = arg(args, "--out-dir");
  if (dir) {
    fragments.forEach((f, i) => {
      writeFileSync(`${resolve(dir)}/fragment-${String(i).padStart(4, "0")}.json`, JSON.stringify(f, null, 2));
    });
    console.log(`wrote ${fragments.length} fragments to ${dir}`);
  } else {
    console.log(JSON.stringify(fragments, null, 2));
  }
  return 0;
}

async function cmdReassemble(args: string[]): Promise<number> {
  const dir = arg(args, "--in-dir");
  if (!dir) {
    console.error("usage: tf-packet reassemble --in-dir <dir> [--out <file>]");
    return 2;
  }
  const files = readdirSync(resolve(dir))
    .filter((f) => f.endsWith(".json"))
    .sort();
  const fragments = files.map((f) => JSON.parse(readFileSync(`${resolve(dir)}/${f}`, "utf8")) as Packet);
  const r = reassembleFragments(fragments);
  if (!r.ok) {
    console.error(`reassembly failed: ${r.reason}`);
    return 1;
  }
  const out = arg(args, "--out");
  if (out) writeFileSync(resolve(out), Buffer.from(r.payload!));
  else process.stdout.write(Buffer.from(r.payload!));
  return 0;
}

async function cmdSimulateLora(args: string[]): Promise<number> {
  const path = arg(args, "--packet");
  if (!path) {
    console.error("usage: tf-packet simulate-lora --packet <file> [--count <n>] [--packet-loss 0..1] [--bandwidth-bps <n>] [--base-latency-ms <n>]");
    return 2;
  }
  const packet = JSON.parse(readFileSync(resolve(path), "utf8")) as Packet;
  const count = Number(arg(args, "--count") ?? 16);
  const loss = Number(arg(args, "--packet-loss") ?? 0.1);
  const bw = Number(arg(args, "--bandwidth-bps") ?? 250);
  const baseLat = Number(arg(args, "--base-latency-ms") ?? 5000);
  const sim = simulateLora(Array.from({ length: count }, () => packet), {
    packetLoss: loss,
    bandwidthBps: bw,
    baseLatencyMs: baseLat,
  });
  console.log(JSON.stringify(
    {
      delivered: sim.delivered.length,
      dropped: sim.dropped.length,
      total_latency_ms: sim.totalLatencyMs,
      drop_rate: sim.dropped.length / count,
    },
    null,
    2,
  ));
  return 0;
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case "sign":
      return cmdSign(rest);
    case "verify":
      return cmdVerify(rest);
    case "inspect":
      return cmdInspect(rest);
    case "fragment":
      return cmdFragment(rest);
    case "reassemble":
      return cmdReassemble(rest);
    case "simulate-lora":
      return cmdSimulateLora(rest);
    default:
      console.error(
        "usage: tf-packet <sign|verify|inspect|fragment|reassemble|simulate-lora> [...]",
      );
      return 2;
  }
}

const exit = await main();
process.exit(exit);
