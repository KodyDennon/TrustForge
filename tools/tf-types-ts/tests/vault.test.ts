import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Vault, VaultError } from "../src/core/vault";

function withTempFile(fn: (path: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "tf-vault-"));
  const file = join(dir, "vault.json");
  return Promise.resolve(fn(file)).finally(() => rmSync(dir, { recursive: true, force: true }));
}

// Small Argon2id params keep the suite fast.
const FAST: Parameters<typeof Vault.createAtPath>[2] = {
  m_cost: 256,
  t_cost: 1,
  p_cost: 1,
};

describe("Vault", () => {
  test("create, store, read, remove", async () => {
    await withTempFile(async (path) => {
      const vault = await Vault.createAtPath(path, "correct horse battery staple", FAST);
      const secret = new Uint8Array(32);
      for (let i = 0; i < 32; i++) secret[i] = i;
      vault.store({
        id: "agent-sign",
        purpose: "signing",
        algorithm: "ed25519",
        key_bytes: secret,
      });
      const read = vault.read("agent-sign");
      expect(Array.from(read.key_bytes)).toEqual(Array.from(secret));
      expect(vault.list()).toHaveLength(1);
      expect(vault.remove("agent-sign")).toBe(true);
      expect(vault.list()).toHaveLength(0);
    });
  });

  test("opens with the same passphrase, fails with a different one", async () => {
    await withTempFile(async (path) => {
      const vault = await Vault.createAtPath(path, "secret-one", FAST);
      vault.store({
        id: "k",
        purpose: "signing",
        algorithm: "ed25519",
        key_bytes: new Uint8Array([1, 2, 3]),
      });
      // Reopen with the correct passphrase.
      const reopened = await Vault.openAtPath(path, "secret-one");
      expect(Array.from(reopened.read("k").key_bytes)).toEqual([1, 2, 3]);
      // Reopen with the wrong passphrase: key derivation succeeds but AEAD
      // decrypt will fail because the wrap key is wrong.
      const wrong = await Vault.openAtPath(path, "secret-two");
      expect(() => wrong.read("k")).toThrow();
    });
  });

  test("reject missing vault file", async () => {
    await expect(Vault.openAtPath("/nonexistent/vault.json", "any")).rejects.toThrow(VaultError);
  });

  test("update rewrites the entry in place", async () => {
    await withTempFile(async (path) => {
      const vault = await Vault.createAtPath(path, "pw", FAST);
      vault.store({
        id: "k",
        purpose: "signing",
        algorithm: "ed25519",
        key_bytes: new Uint8Array([1, 1, 1]),
      });
      vault.store({
        id: "k",
        purpose: "signing",
        algorithm: "ed25519",
        key_bytes: new Uint8Array([9, 9, 9]),
      });
      expect(vault.list()).toHaveLength(1);
      expect(Array.from(vault.read("k").key_bytes)).toEqual([9, 9, 9]);
    });
  });
});
