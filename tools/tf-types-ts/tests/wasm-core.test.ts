/**
 * Cross-language parity test: TS canonicalize / verify vs. the
 * `tf-core-wasm` cdylib compiled from the Rust `tf-types`.
 *
 * The wasm bundle is produced by `crates/tf-core-wasm/build.sh` and lives
 * at `crates/tf-core-wasm/dist/node/`. We skip this suite when the bundle
 * is missing so the rest of the TS test run isn't blocked.
 */

import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

import { canonicalize as tsCanonicalize } from "../src/core/canonical";
import { ed25519Generate, ed25519Sign } from "../src/core/crypto";

const wasmPath = resolve(
  import.meta.dir,
  "../../../crates/tf-core-wasm/dist/node/tf_core_wasm.js",
);

if (!existsSync(wasmPath)) {
  test.skip(
    "wasm not built; run `crates/tf-core-wasm/build.sh` first",
    () => {},
  );
} else {
  describe("tf-core-wasm parity with TS", () => {
    test("canonicalize matches TS byte-for-byte (simple)", async () => {
      const wasm = await import(wasmPath);
      const value = { z: 1, a: 2 };
      expect(wasm.canonicalize(value)).toBe(tsCanonicalize(value));
      expect(wasm.canonicalize(value)).toBe('{"a":2,"z":1}');
    });

    test("canonicalize matches TS byte-for-byte (nested + arrays)", async () => {
      const wasm = await import(wasmPath);
      const cases: unknown[] = [
        null,
        true,
        false,
        42,
        -0,
        1.5,
        "hi",
        [3, 1, 2],
        { b: 1, a: 2 },
        { z: 1, a: { y: 2, x: 1 } },
        { xs: [{ b: 1 }, { a: 2 }], meta: { tag: "x", n: 3 } },
      ];
      for (const v of cases) {
        expect(wasm.canonicalize(v)).toBe(tsCanonicalize(v));
      }
    });

    test("verify_packet on a known-good packet returns ok=true", async () => {
      const wasm = await import(wasmPath);
      const kp = await ed25519Generate();
      const pkB64 = Buffer.from(kp.publicKey).toString("base64");
      const signer = "tf:actor:agent:example.com/a";
      const draft = {
        packet_version: "1",
        source: signer,
        destination: "tf:actor:agent:example.com/b",
        kind: "test",
        priority: "P3",
        created_at: "2026-04-25T00:00:00Z",
      };
      const signingBytes = new TextEncoder().encode(tsCanonicalize(draft));
      const sig = await ed25519Sign(signingBytes, kp.privateKey);
      const packet = {
        ...draft,
        signature: {
          signer,
          algorithm: "ed25519",
          signature: Buffer.from(sig).toString("base64"),
        },
      };
      const result = wasm.verify_packet(packet, pkB64, "2026-04-25T00:00:00Z");
      expect(result.ok).toBe(true);
      expect(result.reason).toBeNull();
    });

    test("ed25519_verify accepts valid signature, rejects tampered", async () => {
      const wasm = await import(wasmPath);
      const kp = await ed25519Generate();
      const pkB64 = Buffer.from(kp.publicKey).toString("base64");
      const message = new TextEncoder().encode("hello trustforge");
      const sig = await ed25519Sign(message, kp.privateKey);
      const sigB64 = Buffer.from(sig).toString("base64");

      expect(wasm.ed25519_verify(pkB64, message, sigB64)).toBe(true);

      // Tamper one byte of the message.
      const tampered = new Uint8Array(message);
      tampered[0]! ^= 0x01;
      expect(wasm.ed25519_verify(pkB64, tampered, sigB64)).toBe(false);

      // Tamper one byte of the signature.
      const badSig = new Uint8Array(sig);
      badSig[0]! ^= 0x01;
      expect(
        wasm.ed25519_verify(
          pkB64,
          message,
          Buffer.from(badSig).toString("base64"),
        ),
      ).toBe(false);
    });
  });
}
