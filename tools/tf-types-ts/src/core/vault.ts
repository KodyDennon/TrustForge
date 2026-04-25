/**
 * File-backed passphrase vault. Matches schemas/vault-file.schema.json.
 *
 *   wrap_key = Argon2id(passphrase, salt, m_cost, t_cost, p_cost, 32 bytes)
 *   entry.ciphertext = ChaCha20Poly1305(wrap_key, nonce, aad=id||purpose||algorithm, key_bytes)
 */

import { existsSync, openSync, closeSync, writeFileSync, writeSync, fsyncSync, renameSync, readFileSync } from "node:fs";
import { dirname, resolve as resolvePath } from "node:path";
import { canonicalize } from "./canonical.js";
import { argon2id } from "@noble/hashes/argon2";
import {
  b64decode,
  b64encode,
  chacha20poly1305Decrypt,
  chacha20poly1305Encrypt,
  utf8encode,
} from "./crypto.js";

export class VaultError extends Error {}

export interface VaultEntryPlain {
  id: string;
  purpose: "signing" | "kem" | "attestation" | "raw";
  algorithm: string;
  key_bytes: Uint8Array;
  created_at: string;
}

interface OnDiskEntry {
  id: string;
  purpose: VaultEntryPlain["purpose"];
  algorithm: string;
  nonce: string;
  ciphertext: string;
  created_at: string;
}

interface OnDiskVault {
  vault_version: "1";
  kdf: {
    algorithm: "argon2id";
    salt: string;
    m_cost: number;
    t_cost: number;
    p_cost: number;
  };
  cipher: { algorithm: "chacha20poly1305" };
  entries: OnDiskEntry[];
}

export interface VaultOptions {
  m_cost?: number; // KiB
  t_cost?: number;
  p_cost?: number;
  salt?: Uint8Array; // deterministic salt for testing
}

export class Vault {
  private constructor(
    private readonly path: string,
    private readonly wrapKey: Uint8Array,
    private readonly data: OnDiskVault,
  ) {}

  static async createAtPath(path: string, passphrase: string, opts: VaultOptions = {}): Promise<Vault> {
    // O_CREAT | O_EXCL — refuse to clobber an existing vault.
    let fd: number;
    try {
      fd = openSync(path, "wx", 0o600);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") {
        throw new VaultError(`vault already exists at ${path}`);
      }
      throw err;
    }
    const salt = opts.salt ?? crypto.getRandomValues(new Uint8Array(16));
    const m_cost = opts.m_cost ?? 19456;
    const t_cost = opts.t_cost ?? 2;
    const p_cost = opts.p_cost ?? 1;
    const wrapKey = deriveKey(passphrase, salt, m_cost, t_cost, p_cost);
    const data: OnDiskVault = {
      vault_version: "1",
      kdf: {
        algorithm: "argon2id",
        salt: b64encode(salt),
        m_cost,
        t_cost,
        p_cost,
      },
      cipher: { algorithm: "chacha20poly1305" },
      entries: [],
    };
    const buf = Buffer.from(JSON.stringify(data, null, 2) + "\n", "utf8");
    writeSync(fd, buf, 0, buf.length, 0);
    fsyncSync(fd);
    closeSync(fd);
    return new Vault(path, wrapKey, data);
  }

  static async openAtPath(path: string, passphrase: string): Promise<Vault> {
    if (!existsSync(path)) throw new VaultError(`vault not found: ${path}`);
    const raw = readFileSync(path, "utf8");
    const data = JSON.parse(raw) as OnDiskVault;
    if (data.vault_version !== "1") {
      throw new VaultError(`unsupported vault version: ${data.vault_version}`);
    }
    if (data.kdf.algorithm !== "argon2id" || data.cipher.algorithm !== "chacha20poly1305") {
      throw new VaultError("unsupported vault algorithm");
    }
    const salt = b64decode(data.kdf.salt);
    const wrapKey = deriveKey(passphrase, salt, data.kdf.m_cost, data.kdf.t_cost, data.kdf.p_cost);
    return new Vault(path, wrapKey, data);
  }

  list(): { id: string; purpose: VaultEntryPlain["purpose"]; algorithm: string; created_at: string }[] {
    return this.data.entries.map((e) => ({
      id: e.id,
      purpose: e.purpose,
      algorithm: e.algorithm,
      created_at: e.created_at,
    }));
  }

  store(entry: Omit<VaultEntryPlain, "created_at"> & { created_at?: string }): void {
    const now = entry.created_at ?? new Date().toISOString();
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const aad = aadFor(entry.id, entry.purpose, entry.algorithm);
    const ct = chacha20poly1305Encrypt(this.wrapKey, nonce, aad, entry.key_bytes);
    const diskEntry: OnDiskEntry = {
      id: entry.id,
      purpose: entry.purpose,
      algorithm: entry.algorithm,
      nonce: b64encode(nonce),
      ciphertext: b64encode(ct),
      created_at: now,
    };
    const existingIdx = this.data.entries.findIndex((e) => e.id === entry.id);
    if (existingIdx >= 0) this.data.entries[existingIdx] = diskEntry;
    else this.data.entries.push(diskEntry);
    this.persist();
  }

  read(id: string): VaultEntryPlain {
    const entry = this.data.entries.find((e) => e.id === id);
    if (!entry) throw new VaultError(`vault entry not found: ${id}`);
    const nonce = b64decode(entry.nonce);
    const aad = aadFor(entry.id, entry.purpose, entry.algorithm);
    const key_bytes = chacha20poly1305Decrypt(
      this.wrapKey,
      nonce,
      aad,
      b64decode(entry.ciphertext),
    );
    return {
      id: entry.id,
      purpose: entry.purpose,
      algorithm: entry.algorithm,
      key_bytes,
      created_at: entry.created_at,
    };
  }

  remove(id: string): boolean {
    const before = this.data.entries.length;
    this.data.entries = this.data.entries.filter((e) => e.id !== id);
    const changed = this.data.entries.length !== before;
    if (changed) this.persist();
    return changed;
  }

  private persist(): void {
    // Atomic: write to a temp sibling then rename. A crash mid-write
    // leaves the original vault intact instead of replacing it with a
    // truncated file.
    const dir = dirname(resolvePath(this.path));
    const tmp = `${this.path}.tmp.${Date.now().toString(36)}.${Math.floor(Math.random() * 1_000_000).toString(36)}`;
    const buf = Buffer.from(JSON.stringify(this.data, null, 2) + "\n", "utf8");
    const fd = openSync(tmp, "w", 0o600);
    try {
      writeSync(fd, buf, 0, buf.length, 0);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.path);
    void dir;
  }
}

/** Canonical AAD for a vault entry: the canonical-JSON encoding of
 *  `[id, purpose, algorithm]`. Pre-B7 the AAD was JSON.stringify which
 *  varies (escaping, key order in object form) across runtimes; using
 *  canonicalize makes the AAD bytes byte-identical to Rust's
 *  serde_json output for ASCII inputs AND ensures NFC-normalized
 *  Unicode is handled the same way. */
function aadFor(id: string, purpose: string, algorithm: string): Uint8Array {
  return utf8encode(canonicalize([id, purpose, algorithm]));
}

function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  m_cost: number,
  t_cost: number,
  p_cost: number,
): Uint8Array {
  // noble's argon2id takes m in KiB, t is iterations, p is parallelism, outputs 32 bytes.
  return argon2id(utf8encode(passphrase), salt, {
    m: m_cost,
    t: t_cost,
    p: p_cost,
    dkLen: 32,
    version: 0x13,
  });
}
