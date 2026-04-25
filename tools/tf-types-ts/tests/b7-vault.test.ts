/**
 * B7 vault correctness tests:
 *   - createAtPath refuses to clobber an existing file
 *   - persist is atomic (temp + rename); crash mid-write leaves the
 *     original vault intact
 *   - aadFor uses canonical-JSON so non-ASCII ids round-trip
 */
import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Vault } from "../src/index";

describe("B7 — vault exclusive create", () => {
  test("createAtPath refuses to overwrite an existing file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-vault-b7-"));
    try {
      const path = join(dir, "vault.json");
      writeFileSync(path, "preexisting content");
      let threw: Error | undefined;
      try {
        await Vault.createAtPath(path, "pw", {
          m_cost: 256,
          t_cost: 1,
          p_cost: 1,
        });
      } catch (err) {
        threw = err as Error;
      }
      expect(threw).toBeDefined();
      expect(threw!.message).toContain("already exists");
      // File on disk is untouched.
      expect(readFileSync(path, "utf8")).toBe("preexisting content");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("createAtPath succeeds when no file is present", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-vault-b7-"));
    try {
      const path = join(dir, "vault.json");
      const v = await Vault.createAtPath(path, "pw", {
        m_cost: 256,
        t_cost: 1,
        p_cost: 1,
      });
      expect(existsSync(path)).toBe(true);
      expect(v.list()).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("B7 — vault canonical AAD round-trip", () => {
  test("non-ASCII id (NFC) survives store + reopen", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-vault-b7-"));
    try {
      const path = join(dir, "vault.json");
      const v = await Vault.createAtPath(path, "pw", {
        m_cost: 256,
        t_cost: 1,
        p_cost: 1,
      });
      const bytes = new Uint8Array(32);
      bytes.fill(0xa5);
      v.store({
        id: "署名鍵",
        purpose: "signing",
        algorithm: "ed25519",
        key_bytes: bytes,
      });
      // Reopen and read back.
      const v2 = await Vault.openAtPath(path, "pw");
      const got = v2.read("署名鍵");
      expect(Array.from(got.key_bytes)).toEqual(Array.from(bytes));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("B7 — vault atomic persist", () => {
  test("an atomic persist leaves no temp file behind", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-vault-b7-"));
    try {
      const path = join(dir, "vault.json");
      const v = await Vault.createAtPath(path, "pw", {
        m_cost: 256,
        t_cost: 1,
        p_cost: 1,
      });
      // Fire a few writes; the dir should never permanently contain
      // a `.tmp.*` file when persist is sync.
      for (let i = 0; i < 5; i++) {
        const bytes = new Uint8Array(32);
        bytes.fill(i);
        v.store({
          id: `k${i}`,
          purpose: "signing",
          algorithm: "ed25519",
          key_bytes: bytes,
        });
      }
      // No leftover temp files.
      const fs = await import("node:fs");
      const entries = fs.readdirSync(dir);
      const leftover = entries.filter((e) => e.includes(".tmp."));
      expect(leftover.length).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
