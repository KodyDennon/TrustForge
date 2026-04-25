/**
 * Session migration helpers (TF-0003).
 *
 * `migrateSession` produces a signed `SessionMigration` record describing
 * a session moving between transports while preserving session_id and
 * generation. The session itself stays alive — only its transport
 * binding changes — so authority grants, capability tokens, and proof
 * lineage carry over.
 *
 * `verifySessionMigration` re-derives the digest and verifies the
 * ed25519 signature, plus enforces monotonic generation.
 *
 * `Ratchet` implements TF-0003's double-ratchet auto-trigger: the
 * caller signals that N messages or T seconds have elapsed and the
 * ratchet rotates symmetric keys via HKDF-SHA256(prev_key,
 * info="tf-session/ratchet"). It does not bind to the actual session
 * cipher — that's the SessionEndpoint's job — but it provides a
 * deterministic key sequence so both peers stay in lock-step.
 */

import type {
  ActorId,
  Capability,
  Timestamp,
  SignatureEnvelope,
} from "../generated/_common.js";
import type { TransportBinding } from "../generated/transport-binding.js";
import type { SessionMigration } from "../generated/session-migration.js";
import { canonicalize } from "./canonical.js";
import { ed25519Sign, ed25519Verify, hkdfSha256, sha256 } from "./crypto.js";

export interface MigrateSessionArgs {
  sessionId: string;
  generation: number;
  fromBinding: TransportBinding;
  toBinding: TransportBinding;
  rotatedKeys?: boolean;
  preservedCapabilities?: Capability[];
  reason?: string;
  signer: ActorId;
  privateKey: Uint8Array;
  migratedAt?: Timestamp;
}

export function migrationSigningBytes(m: SessionMigration): Uint8Array {
  const { signature: _signature, ...rest } = m;
  void _signature;
  return sha256(new TextEncoder().encode(canonicalize(rest as unknown)));
}

export async function migrateSession(args: MigrateSessionArgs): Promise<SessionMigration> {
  if (args.generation < 1) {
    throw new Error("session migration generation must be >= 1");
  }
  const migratedAt = args.migratedAt ?? new Date().toISOString();
  const draft: SessionMigration = {
    migration_version: "1",
    session_id: args.sessionId,
    generation: args.generation,
    from_binding: args.fromBinding,
    to_binding: args.toBinding,
    migrated_at: migratedAt,
    signer: args.signer,
    signature: { algorithm: "ed25519", signer: args.signer, signature: "" } as SignatureEnvelope,
  };
  if (args.rotatedKeys) draft.rotated_keys = true;
  if (args.preservedCapabilities && args.preservedCapabilities.length > 0) {
    draft.preserved_capabilities = args.preservedCapabilities;
  }
  if (args.reason) draft.reason = args.reason;
  const digest = migrationSigningBytes(draft);
  const sig = await ed25519Sign(digest, args.privateKey);
  draft.signature = {
    algorithm: "ed25519",
    signer: args.signer,
    signature: Buffer.from(sig).toString("base64"),
  };
  return draft;
}

export interface VerifySessionMigrationArgs {
  migration: SessionMigration;
  publicKey: Uint8Array;
  /** Last generation observed by the verifier; if set, the new
   *  generation must be strictly greater. */
  lastGeneration?: number;
  /** Expected session_id; if set, must match exactly. */
  expectedSessionId?: string;
}

export interface VerifySessionMigrationResult {
  ok: boolean;
  reason?: string;
}

export async function verifySessionMigration(
  args: VerifySessionMigrationArgs,
): Promise<VerifySessionMigrationResult> {
  const m = args.migration;
  if (m.migration_version !== "1") {
    return { ok: false, reason: `unsupported migration_version ${m.migration_version}` };
  }
  if (m.signature.signer !== m.signer) {
    return { ok: false, reason: "signature signer does not match signer" };
  }
  if (m.signature.algorithm !== "ed25519") {
    return { ok: false, reason: `unsupported signature algorithm ${m.signature.algorithm}` };
  }
  if (args.expectedSessionId && m.session_id !== args.expectedSessionId) {
    return { ok: false, reason: "session_id mismatch" };
  }
  if (args.lastGeneration !== undefined && m.generation <= args.lastGeneration) {
    return { ok: false, reason: `generation ${m.generation} <= last seen ${args.lastGeneration} (replay)` };
  }
  const digest = migrationSigningBytes(m);
  const sigBytes = new Uint8Array(Buffer.from(m.signature.signature, "base64"));
  const verified = await ed25519Verify(args.publicKey, digest, sigBytes);
  if (!verified) {
    return { ok: false, reason: "migration signature did not verify" };
  }
  return { ok: true };
}

/* -------------------------------------------------------------------------- */
/*  Double ratchet                                                            */
/* -------------------------------------------------------------------------- */

const RATCHET_INFO = new TextEncoder().encode("tf-session/ratchet");

export interface RatchetOptions {
  /** Rotate after this many messages have been processed. Default 1024. */
  maxMessages?: number;
  /** Rotate after this many seconds have elapsed since the last rotation.
   *  Default 600 seconds. */
  maxAgeSeconds?: number;
}

export class Ratchet {
  private readonly maxMessages: number;
  private readonly maxAgeMs: number;
  private currentKey: Uint8Array;
  private rotationCount = 0;
  private messagesSinceRotation = 0;
  private lastRotationMs: number;

  constructor(initialKey: Uint8Array, opts: RatchetOptions = {}) {
    if (initialKey.length !== 32) {
      throw new Error("ratchet key must be 32 bytes");
    }
    this.currentKey = new Uint8Array(initialKey);
    this.maxMessages = opts.maxMessages ?? 1024;
    this.maxAgeMs = (opts.maxAgeSeconds ?? 600) * 1000;
    this.lastRotationMs = Date.now();
  }

  /** Current 32-byte symmetric key. */
  key(): Uint8Array {
    return new Uint8Array(this.currentKey);
  }

  /** How many rotations have happened since construction. */
  generation(): number {
    return this.rotationCount;
  }

  /** Should be called on every successful frame send/receive. Returns
   *  true if the ratchet rotated as a result. */
  observeMessage(): boolean {
    this.messagesSinceRotation += 1;
    if (this.shouldRotate()) {
      this.rotate();
      return true;
    }
    return false;
  }

  /** Force a rotation right now. */
  rotate(): void {
    this.currentKey = hkdfSha256(this.currentKey, new Uint8Array(0), RATCHET_INFO, 32);
    this.rotationCount += 1;
    this.messagesSinceRotation = 0;
    this.lastRotationMs = Date.now();
  }

  private shouldRotate(): boolean {
    if (this.messagesSinceRotation >= this.maxMessages) return true;
    if (Date.now() - this.lastRotationMs >= this.maxAgeMs) return true;
    return false;
  }
}
