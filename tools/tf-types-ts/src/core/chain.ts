/**
 * Proof-event chain and merkle-tree helpers. Mirrors
 * `crates/tf-types/src/chain.rs` byte-for-byte via
 * `conformance/chain-vectors.yaml`.
 */

import type { ProofEvent } from "../generated/proof-event.js";
import { canonicalize } from "./canonical.js";
import { fromHex, parseHashRef, sha256HashRef, toHex, utf8encode } from "./crypto.js";
import { sha256 } from "@noble/hashes/sha2";

export class ChainError extends Error {}

/** Canonical JSON of an event with its signature stripped. */
export function eventSignedPayload(event: ProofEvent): string {
  const { signature: _sig, ...rest } = event as ProofEvent & { signature?: unknown };
  return canonicalize(rest);
}

/** The sha256:<hex> hash of an event's signed payload. */
export function eventHash(event: ProofEvent): string {
  return sha256HashRef(utf8encode(eventSignedPayload(event)));
}

/**
 * Verify a linear hash-chain. The first event may lack parent_hash; every
 * subsequent event must declare parent_hash = eventHash(previous).
 */
export function verifyChain(events: readonly ProofEvent[]): void {
  for (let i = 1; i < events.length; i++) {
    const expected = eventHash(events[i - 1]!);
    const parent = events[i]!.parent_hash;
    if (!parent) throw new ChainError(`event ${i} has no parent_hash`);
    if (parent !== expected) {
      throw new ChainError(`event ${i} declares parent_hash ${parent} but previous hashes to ${expected}`);
    }
  }
}

/**
 * Merkle root over the event hashes. Empty → sentinel zero hash;
 * single-event → its own hash; otherwise pair-wise hash with odd-level
 * duplication.
 */
export function merkleRoot(events: readonly ProofEvent[]): string {
  if (events.length === 0) {
    return "sha256:" + toHex(new Uint8Array(32));
  }
  let level: Uint8Array[] = events.map((e) => parseHashRef(eventHash(e)).bytes);
  while (level.length > 1) {
    if (level.length % 2 === 1) {
      level.push(level[level.length - 1]!);
    }
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const concat = new Uint8Array(level[i]!.length + level[i + 1]!.length);
      concat.set(level[i]!, 0);
      concat.set(level[i + 1]!, level[i]!.length);
      next.push(new Uint8Array(sha256(concat)));
    }
    level = next;
  }
  return "sha256:" + toHex(level[0]!);
}

/** Rolling chain hash: seeded with 32 zero bytes, sha256(prev || event_hash_bytes) per event. */
export function chainHash(events: readonly ProofEvent[]): string {
  let state = new Uint8Array(32);
  for (const e of events) {
    const evHash = parseHashRef(eventHash(e)).bytes;
    const concat = new Uint8Array(state.length + evHash.length);
    concat.set(state, 0);
    concat.set(evHash, state.length);
    state = new Uint8Array(sha256(concat));
  }
  return "sha256:" + toHex(state);
}
