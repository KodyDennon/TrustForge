/**
 * BuiltProofEvent builder + signed-append helpers used by the daemon.
 *
 * Replaces the ad-hoc `appendEventLine({ type: ..., actor: ..., ... })`
 * pattern with a builder that produces schema-conforming BuiltProofEvent
 * records (event_version, id, type, actor_id, timestamp, level,
 * parent_hash, signature) — the shape `schemas/proof-event.schema.json`
 * actually expects.
 *
 * Also exposes a parent_hash chain helper so consecutive appends form a
 * cryptographically-linked log.
 */

import { canonicalize } from "./canonical.js";
import { ed25519Sign, sha256 } from "./crypto.js";
import { utf8encode } from "./crypto.js";

/** Local re-exports under unambiguous names so callers can import the
 *  builder's types without colliding with the generated wire types. */
export type ProofChainLevel = "L0" | "L1" | "L2" | "L3" | "L4" | "L5";

export interface BuiltProofEvent {
  event_version: "1";
  id: string;
  type: string;
  actor_id: string;
  timestamp: string;
  level: ProofChainLevel;
  parent_hash?: string;
  context?: Record<string, unknown>;
  signature?: {
    algorithm: string;
    signer: string;
    signature: string;
  };
}

export interface ProofEventInput {
  type: string;
  actor: string;
  level?: ProofChainLevel;
  context?: Record<string, unknown>;
}

let counter = 0;

function nextId(prefix = "ev"): string {
  counter += 1;
  return `${prefix}-${Date.now().toString(16)}-${counter.toString(36)}`;
}

/**
 * Build a schema-conforming BuiltProofEvent (without signature). The caller
 * is responsible for chaining `parent_hash` and signing.
 */
export function buildProofEvent(input: ProofEventInput, parentHash?: string): BuiltProofEvent {
  return {
    event_version: "1",
    id: nextId(input.type.split(".")[0] ?? "ev"),
    type: input.type,
    actor_id: input.actor,
    timestamp: new Date().toISOString(),
    level: input.level ?? "L1",
    parent_hash: parentHash,
    context: input.context,
  };
}

/**
 * Compute the canonical hash of a BuiltProofEvent for `parent_hash` chaining
 * AND for the signature payload. Both consumers MUST use this exact
 * canonical form so cross-language (TS↔Rust) hashes match.
 */
export function eventDigest(ev: BuiltProofEvent): Uint8Array {
  // Drop the signature for digest purposes — we sign the canonical form
  // of the unsigned event. This matches the protocol's signed-log-events
  // semantics.
  const unsigned: BuiltProofEvent = { ...ev, signature: undefined };
  const bytes = utf8encode(canonicalize(unsigned));
  return sha256(bytes);
}

/** Hex-encoded `sha256:` prefixed hash for `parent_hash` storage. */
export function eventHashRef(ev: BuiltProofEvent): string {
  const d = eventDigest(ev);
  let hex = "";
  for (const b of d) hex += b.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}

/**
 * Sign a BuiltProofEvent in-place with the daemon identity key. The
 * signature covers the canonical unsigned form (so verifiers can
 * recompute the digest deterministically).
 */
export async function signProofEvent(
  ev: BuiltProofEvent,
  signerActor: string,
  signerPriv: Uint8Array,
): Promise<BuiltProofEvent> {
  const digest = eventDigest(ev);
  const sig = await ed25519Sign(digest, signerPriv);
  let b64 = "";
  // Avoid Buffer dependency for portability in non-Node runtimes.
  if (typeof Buffer !== "undefined") {
    b64 = Buffer.from(sig).toString("base64");
  } else {
    let s = "";
    for (const b of sig) s += String.fromCharCode(b);
    // eslint-disable-next-line no-undef
    b64 = btoa(s);
  }
  return {
    ...ev,
    signature: {
      algorithm: "ed25519",
      signer: signerActor,
      signature: b64,
    },
  };
}

/** Track the parent_hash of the previously-appended event. The daemon
 *  maintains one chain per .tflog. */
export class ProofChain {
  private prevHash: string | undefined;

  /** Bind a freshly-built event into the chain by setting parent_hash
   *  to the previous event's hash, then return the (still unsigned)
   *  event. The chain advances after `commit` is called. */
  bind(ev: BuiltProofEvent): BuiltProofEvent {
    return { ...ev, parent_hash: this.prevHash };
  }

  /** Advance the chain. Call AFTER signing the event so the chain hash
   *  covers the final committed bytes. */
  commit(ev: BuiltProofEvent): void {
    this.prevHash = eventHashRef(ev);
  }

  /** Convenience: bind + sign + commit in one shot. */
  async append(
    input: ProofEventInput,
    signerActor: string,
    signerPriv: Uint8Array,
  ): Promise<BuiltProofEvent> {
    const built = this.bind(buildProofEvent(input));
    const signed = await signProofEvent(built, signerActor, signerPriv);
    this.commit(signed);
    return signed;
  }

  /** Used in tests / replay. */
  reset(parent_hash?: string): void {
    this.prevHash = parent_hash;
  }
}
