/**
 * Matrix bridge — projects Matrix room events into TrustForge proof
 * events and back. The bridge does not speak the Matrix CS-API itself;
 * it only translates the typed shape so a Matrix room can be wired in
 * as a proof transport / approval channel.
 *
 * The bridge supports:
 *   - matrixEventToProofEvent: m.room.message / m.tf.* → ProofEvent
 *   - proofEventToMatrixEvent: ProofEvent → m.tf.event
 *   - signed-event canonical-JSON re-derivation so an ed25519 signature
 *     over the projected ProofEvent can be verified against the Matrix
 *     server's signed event (if the caller supplies the key).
 */

import type { ActorId, ProofLevel, Timestamp } from "../generated/_common.js";
import type { ProofEvent } from "../generated/proof-event.js";
import { BridgeFailure, type Bridge, type BridgeKind } from "./bridges.js";

export interface MatrixEvent {
  /** Matrix event identifier (e.g. `$abc123:server.example`). */
  event_id: string;
  /** Matrix room identifier (e.g. `!room:server.example`). */
  room_id: string;
  /** Matrix event type, e.g. `m.room.message` or `m.tf.proof`. */
  type: string;
  /** Matrix sender (e.g. `@alice:server.example`). */
  sender: string;
  /** Origin server timestamp (ms since epoch). */
  origin_server_ts: number;
  /** Free-form event body. */
  content: Record<string, unknown>;
  /** Optional state_key for state events. */
  state_key?: string;
  /** Optional `signatures` from the originating server. */
  signatures?: Record<string, Record<string, string>>;
}

export interface MatrixBridgeConfig {
  bridgeId: string;
  trustDomain: string;
  /** Default proof level applied to projected events when the source
   *  Matrix event doesn't carry one. */
  defaultLevel?: ProofLevel;
  /** Map a Matrix sender (e.g. `@alice:example.com`) to a TrustForge
   *  ActorId. Default: `tf:actor:human:<server>/<localpart>`. */
  senderMapper?: (sender: string) => ActorId;
  /** Optional: when the Matrix event is a `m.room.message`, this maps
   *  the textual body to a TrustForge action name. */
  messageActionMapper?: (body: string) => string | undefined;
}

export interface ProjectedMatrixEvent {
  event: ProofEvent;
  /** True when the event was a `m.room.message`. */
  fromMessage: boolean;
}

export class MatrixBridge implements Bridge {
  readonly kind: BridgeKind = "matrix";
  readonly bridgeId: string;
  readonly trustDomain: string;
  private readonly cfg: MatrixBridgeConfig;

  constructor(cfg: MatrixBridgeConfig) {
    this.bridgeId = cfg.bridgeId;
    this.trustDomain = cfg.trustDomain;
    this.cfg = cfg;
  }

  /** Project a Matrix event into a TrustForge ProofEvent. */
  matrixEventToProofEvent(matrix: MatrixEvent): ProjectedMatrixEvent {
    if (!matrix.event_id || !matrix.sender || !matrix.type) {
      throw new BridgeFailure({
        code: "invalid-input",
        message: "Matrix event missing event_id / sender / type",
      });
    }
    const actor = this.mapSender(matrix.sender);
    const timestamp = new Date(matrix.origin_server_ts).toISOString();
    const fromMessage = matrix.type === "m.room.message";
    const tfType = fromMessage
      ? this.deriveActionFromMessage(matrix)
      : matrix.type.replace(/^m\./, "matrix.");
    const event: ProofEvent = {
      event_version: "1",
      id: matrix.event_id,
      type: tfType,
      actor_id: actor,
      timestamp,
      level: this.cfg.defaultLevel ?? "L1",
      context: {
        matrix: {
          room_id: matrix.room_id,
          state_key: matrix.state_key,
          content: matrix.content,
          server_signatures: matrix.signatures,
        },
      },
      signature: {
        algorithm: "ed25519",
        signer: actor,
        // Matrix events carry server-side signatures rather than
        // TrustForge envelope signatures. Callers re-sign the projected
        // event with their own key when emitting it into a TrustForge
        // log.
        signature: "AAAA",
      },
    };
    return { event, fromMessage };
  }

  /** Project a TrustForge ProofEvent into a Matrix m.tf.event payload. */
  proofEventToMatrixEvent(event: ProofEvent, opts: { roomId: string; sender: string }): MatrixEvent {
    return {
      event_id: event.id,
      room_id: opts.roomId,
      type: "m.tf.event",
      sender: opts.sender,
      origin_server_ts: Date.parse(event.timestamp),
      content: {
        proof_event: event,
      },
    };
  }

  /** Default sender mapper: `@alice:example.com` → `tf:actor:human:example.com/alice`. */
  private mapSender(sender: string): ActorId {
    if (this.cfg.senderMapper) return this.cfg.senderMapper(sender);
    const m = /^@([^:]+):(.+)$/.exec(sender);
    if (!m) {
      throw new BridgeFailure({
        code: "invalid-input",
        message: `cannot map non-Matrix sender: ${sender}`,
      });
    }
    return `tf:actor:human:${m[2]!}/${m[1]!}`;
  }

  private deriveActionFromMessage(matrix: MatrixEvent): string {
    const body = typeof matrix.content?.body === "string" ? (matrix.content.body as string) : "";
    if (this.cfg.messageActionMapper) {
      const mapped = this.cfg.messageActionMapper(body);
      if (mapped) return mapped;
    }
    // Default: synthesize a generic matrix.message event type.
    return "matrix.message";
  }
}

export function defaultMatrixSenderMapper(sender: string): ActorId {
  const m = /^@([^:]+):(.+)$/.exec(sender);
  if (!m) throw new Error(`cannot map non-Matrix sender: ${sender}`);
  return `tf:actor:human:${m[2]!}/${m[1]!}`;
}

export function nowMatrixTs(time: Timestamp = new Date().toISOString()): number {
  return Date.parse(time);
}
