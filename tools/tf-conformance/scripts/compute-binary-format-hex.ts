/**
 * One-shot helper. Loads conformance/binary-format-vectors.yaml, parses
 * each fixture's `input_yaml` payload, runs writeTfbundle / writeTfpkt
 * via tf-types, hex-encodes the resulting bytes, and writes the file
 * back with `expected_hex` populated. Re-runnable; idempotent.
 *
 * Usage:  bun tools/tf-conformance/scripts/compute-binary-format-hex.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseYaml as parseYAML } from "@trustforge-protocol/types";
import { writeTfbundle, writeTfpkt } from "tf-types";

const ROOT = resolve(import.meta.dir, "..", "..", "..");
const VECTORS_PATH = resolve(ROOT, "conformance/binary-format-vectors.yaml");

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

interface BundleFixture {
  id: string;
  input_yaml: string;
  signature_hex?: string;
  expected_hex: string;
  expected_signature_hex?: string;
}

interface PacketFixture {
  id: string;
  input_yaml: string;
  expected_hex: string;
}

interface VectorFile {
  schema_version: number;
  description: string;
  tfbundle: BundleFixture[];
  tfpkt: PacketFixture[];
}

const raw = readFileSync(VECTORS_PATH, "utf8");
const doc = parseYAML(raw) as VectorFile;

// Compute expected hex per fixture.
for (const f of doc.tfbundle) {
  const body = parseYAML(f.input_yaml);
  const sig = f.signature_hex ? fromHex(f.signature_hex) : undefined;
  const bytes = writeTfbundle(body, sig);
  f.expected_hex = toHex(bytes);
}

for (const f of doc.tfpkt) {
  const pkt = parseYAML(f.input_yaml);
  const bytes = writeTfpkt(pkt);
  f.expected_hex = toHex(bytes);
}

// Re-emit the YAML in-place by string substitution so that we don't
// reshuffle the human-edited block scalars or comments. Each fixture
// has a `expected_hex: ""` placeholder followed (sometimes) by an
// `expected_signature_hex: ""`. We replace the empty value with the
// computed hex on the same line.
let updated = raw;
function setHex(blockHeader: RegExp, id: string, key: string, hex: string): void {
  // Find `id: "<id>"` line, then the next line whose key matches.
  const idAnchor = new RegExp(`(- id:\\s*"${id}"[\\s\\S]*?)(${key}:\\s*)(""|"[^"]*")`, "m");
  const before = updated;
  updated = updated.replace(idAnchor, (_m, prefix, k) => `${prefix}${k}"${hex}"`);
  if (updated === before) {
    throw new Error(`could not patch ${id}.${key}`);
  }
  // Silence the unused regex param.
  void blockHeader;
}

for (const f of doc.tfbundle) {
  setHex(/tfbundle:/, f.id, "expected_hex", f.expected_hex);
}
for (const f of doc.tfpkt) {
  setHex(/tfpkt:/, f.id, "expected_hex", f.expected_hex);
}

writeFileSync(VECTORS_PATH, updated);

console.log("Updated vectors:");
for (const f of doc.tfbundle) {
  console.log(`  tfbundle/${f.id}: ${f.expected_hex.length / 2} bytes`);
}
for (const f of doc.tfpkt) {
  console.log(`  tfpkt/${f.id}:    ${f.expected_hex.length / 2} bytes`);
}
