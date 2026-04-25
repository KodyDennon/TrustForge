/**
 * On-disk key format. A minimal JSON wrapper so keys are portable and
 * human-inspectable. No PEM/PKCS#8; if you need those, convert externally.
 *
 *   { "algorithm": "ed25519", "kind": "private", "key_bytes": "<base64>" }
 *   { "algorithm": "ed25519", "kind": "public",  "key_bytes": "<base64>" }
 */

import { readFileSync, writeFileSync } from "node:fs";
import { b64decode, b64encode, CryptoError } from "tf-types";

export interface KeyFile {
  readonly algorithm: "ed25519";
  readonly kind: "private" | "public";
  readonly key_bytes: string;
}

export function writeKeyFile(path: string, kind: "private" | "public", bytes: Uint8Array): void {
  const body: KeyFile = {
    algorithm: "ed25519",
    kind,
    key_bytes: b64encode(bytes),
  };
  writeFileSync(path, JSON.stringify(body, null, 2) + "\n", { mode: kind === "private" ? 0o600 : 0o644 });
}

export function readKeyFile(path: string): { bytes: Uint8Array; kind: "private" | "public" } {
  const raw = readFileSync(path, "utf8");
  const parsed = JSON.parse(raw) as KeyFile;
  if (parsed.algorithm !== "ed25519") {
    throw new CryptoError(`unsupported algorithm in ${path}: ${parsed.algorithm}`);
  }
  if (parsed.kind !== "private" && parsed.kind !== "public") {
    throw new CryptoError(`unsupported key kind in ${path}: ${parsed.kind}`);
  }
  const bytes = b64decode(parsed.key_bytes);
  if (bytes.length !== 32) {
    throw new CryptoError(`ed25519 key must be 32 bytes, got ${bytes.length} in ${path}`);
  }
  return { bytes, kind: parsed.kind };
}
