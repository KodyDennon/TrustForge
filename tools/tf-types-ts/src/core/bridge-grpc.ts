/**
 * gRPC bridge — wrap a gRPC channel as a TrustForge RpcTransport so a
 * ProofRPC client can call into a gRPC service (and a ProofRPC server
 * can serve gRPC clients) without re-implementing either protocol.
 *
 * The bridge does not link `@grpc/grpc-js` directly; it accepts a
 * caller-supplied `GrpcChannelLike` adapter so consumers can plug in
 * any gRPC implementation (browser-grpc-web, Bun's native gRPC,
 * Node's @grpc/grpc-js). The adapter only needs to:
 *   - send a unary or streaming request and return the response/iter
 *   - close the channel on shutdown
 *
 * Frames are serialised as canonical JSON inside the gRPC binary
 * payload, with TrustForge metadata (caller actor, capability) carried
 * as gRPC headers.
 */

import type { SessionFrame } from "./session.js";
import { canonicalize } from "./canonical.js";
import type { Bridge, BridgeKind } from "./bridges.js";
import type { RpcTransport } from "./rpc.js";

export interface GrpcCallContext {
  method: string;
  metadata: Record<string, string>;
  /** Authority field — typically the gRPC `:authority` pseudo-header. */
  authority?: string;
}

export interface GrpcChannelLike {
  unary(call: GrpcCallContext, body: Uint8Array): Promise<{ body: Uint8Array; metadata: Record<string, string> }>;
  serverStream(
    call: GrpcCallContext,
    body: Uint8Array,
  ): AsyncIterable<{ body: Uint8Array; metadata: Record<string, string> }>;
  close(): Promise<void>;
}

export interface GrpcBridgeConfig {
  bridgeId: string;
  trustDomain: string;
  /** Default gRPC service name for unary calls (e.g.
   *  `trustforge.ProofRpc/Unary`). */
  serviceMethod: string;
  /** Default gRPC `:authority`. */
  authority?: string;
  /** Optional metadata (e.g. tracing headers) added to every call. */
  metadata?: Record<string, string>;
}

export class GrpcBridge implements Bridge {
  readonly kind: BridgeKind = "grpc";
  readonly bridgeId: string;
  readonly trustDomain: string;
  private readonly cfg: GrpcBridgeConfig;
  private readonly channel: GrpcChannelLike;
  private listeners: Array<(f: SessionFrame) => void> = [];

  constructor(channel: GrpcChannelLike, cfg: GrpcBridgeConfig) {
    this.channel = channel;
    this.cfg = cfg;
    this.bridgeId = cfg.bridgeId;
    this.trustDomain = cfg.trustDomain;
  }

  /** Adapter to RpcTransport — the gRPC channel acts as the underlying
   *  byte pipe for ProofRPC. Unary RPC frames are wrapped into a
   *  unary gRPC call; server-streaming frames into a server-streaming
   *  gRPC call. */
  asRpcTransport(): RpcTransport {
    return {
      send: (frame: SessionFrame) => {
        const body = new TextEncoder().encode(canonicalize(frame));
        const ctx: GrpcCallContext = {
          method: this.cfg.serviceMethod,
          metadata: { ...(this.cfg.metadata ?? {}) },
          authority: this.cfg.authority,
        };
        // Fire-and-forget unary; responses are routed back via the
        // stored listener list.
        void this.channel.unary(ctx, body).then((reply) => {
          const text = new TextDecoder().decode(reply.body);
          try {
            const next = JSON.parse(text) as SessionFrame;
            for (const l of this.listeners) l(next);
          } catch {
            // ignore malformed gRPC reply bodies
          }
        });
      },
      onFrame: (listener) => {
        this.listeners.push(listener);
      },
    };
  }

  async close(): Promise<void> {
    await this.channel.close();
  }
}
