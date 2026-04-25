/**
 * Crypto primitives — thin wrappers over audited pure-JS libraries.
 *
 * Supported:
 *   - ed25519 signing / verifying (via @noble/ed25519).
 *   - SHA-256 and BLAKE3 hashing (via @noble/hashes).
 *
 * Post-quantum ML-DSA is reserved in the SignatureEnvelope schema and
 * added in Phase 3+ behind a feature flag. No custom crypto is introduced
 * in this module.
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { blake3 } from "@noble/hashes/blake3";

// The async APIs (signAsync / verifyAsync / getPublicKeyAsync) use the Web
// Crypto SHA-512 implementation and do not need a sha512 callback. We only
// use the async APIs in this module.

export class CryptoError extends Error {}

export interface Ed25519KeyPair {
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

/** Generate a fresh ed25519 key pair from a provided 32-byte seed or Web Crypto randomness. */
export async function ed25519Generate(seed?: Uint8Array): Promise<Ed25519KeyPair> {
  const privateKey = seed ?? crypto.getRandomValues(new Uint8Array(32));
  if (privateKey.length !== 32) {
    throw new CryptoError(`ed25519 seed must be 32 bytes, got ${privateKey.length}`);
  }
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey: new Uint8Array(privateKey), publicKey };
}

/** Derive the public key for an ed25519 private key. */
export async function ed25519PublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
  if (privateKey.length !== 32) {
    throw new CryptoError(`ed25519 private key must be 32 bytes, got ${privateKey.length}`);
  }
  return ed.getPublicKeyAsync(privateKey);
}

/** Sign a message with ed25519. Deterministic per RFC 8032. */
export async function ed25519Sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  if (privateKey.length !== 32) {
    throw new CryptoError(`ed25519 private key must be 32 bytes, got ${privateKey.length}`);
  }
  return ed.signAsync(message, privateKey);
}

/**
 * Verify an ed25519 signature. Resolves to `true` on success, `false` on any
 * failure mode. This mirrors the Rust implementation which returns
 * Result<(), CryptoError>.
 */
export async function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  if (publicKey.length !== 32) return false;
  if (signature.length !== 64) return false;
  try {
    return await ed.verifyAsync(signature, message, publicKey);
  } catch {
    return false;
  }
}

/** SHA-256 of the input, returned as `"sha256:<hex>"`. */
export function sha256HashRef(bytes: Uint8Array): string {
  return "sha256:" + toHex(sha256(bytes));
}

/** BLAKE3 of the input, returned as `"blake3:<hex>"`. */
export function blake3HashRef(bytes: Uint8Array): string {
  return "blake3:" + toHex(blake3(bytes));
}

/** Parse `"sha256:<hex>"` back into `{algorithm, bytes}`. */
export function parseHashRef(s: string): { algorithm: string; bytes: Uint8Array } {
  const colon = s.indexOf(":");
  if (colon < 0) throw new CryptoError(`malformed hashref: ${s}`);
  const algorithm = s.slice(0, colon);
  const hex = s.slice(colon + 1);
  if (hex.length % 2 !== 0) throw new CryptoError("odd-length hex");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const v = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(v)) throw new CryptoError("non-hex character");
    bytes[i] = v;
  }
  return { algorithm, bytes };
}

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new CryptoError("odd-length hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const v = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(v)) throw new CryptoError("non-hex character");
    out[i] = v;
  }
  return out;
}

export function b64encode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function utf8encode(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function utf8decode(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

// ---------- X25519 ----------

import { x25519 } from "@noble/curves/ed25519";

export interface X25519KeyPair {
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

export function x25519Generate(seed?: Uint8Array): X25519KeyPair {
  const privateKey = seed ?? crypto.getRandomValues(new Uint8Array(32));
  if (privateKey.length !== 32) {
    throw new CryptoError(`x25519 seed must be 32 bytes, got ${privateKey.length}`);
  }
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey: new Uint8Array(privateKey), publicKey };
}

export function x25519DiffieHellman(privateKey: Uint8Array, peerPublic: Uint8Array): Uint8Array {
  if (privateKey.length !== 32) throw new CryptoError("x25519 private must be 32 bytes");
  if (peerPublic.length !== 32) throw new CryptoError("x25519 public must be 32 bytes");
  return x25519.getSharedSecret(privateKey, peerPublic);
}

// ---------- HKDF-SHA256 ----------

import { hkdf as nobleHkdf } from "@noble/hashes/hkdf";

export function hkdfSha256(inputKey: Uint8Array, salt: Uint8Array, info: Uint8Array, outputLen: number): Uint8Array {
  return nobleHkdf(sha256, inputKey, salt, info, outputLen);
}

// ---------- ChaCha20-Poly1305-IETF ----------

import { chacha20poly1305 } from "@noble/ciphers/chacha";

export class AeadError extends Error {}

export function chacha20poly1305Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  if (key.length !== 32) throw new AeadError("aead key must be 32 bytes");
  if (nonce.length !== 12) throw new AeadError("aead nonce must be 12 bytes");
  return chacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

export function chacha20poly1305Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  if (key.length !== 32) throw new AeadError("aead key must be 32 bytes");
  if (nonce.length !== 12) throw new AeadError("aead nonce must be 12 bytes");
  try {
    return chacha20poly1305(key, nonce, aad).decrypt(ciphertext);
  } catch (e) {
    throw new AeadError(`aead authentication failed: ${(e as Error).message}`);
  }
}
