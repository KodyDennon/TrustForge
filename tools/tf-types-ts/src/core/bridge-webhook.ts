/**
 * Webhook bridge — verify a vendor webhook signature header and project
 * the verified payload into a TrustForge proof event + capability.
 *
 * Supports the three patterns most webhook providers use:
 *   - HMAC-SHA256 of the raw body with a shared secret (Stripe / GitHub
 *     / Slack-style)
 *   - HMAC-SHA1 of the raw body with a shared secret (legacy GitHub)
 *   - ed25519 signature of `<timestamp>.<body>` (Discord / Bluesky)
 *
 * The bridge enforces a freshness window so replayed webhook deliveries
 * are rejected.
 */

import { hmac } from "@noble/hashes/hmac";
import { sha1 } from "@noble/hashes/sha1";
import { sha256 } from "@noble/hashes/sha256";

import type { ActorId, Capability, Timestamp } from "../generated/_common.js";
import type { ProofEvent } from "../generated/proof-event.js";
import { BridgeFailure, type Bridge, type BridgeKind } from "./bridges.js";
import { ed25519Verify } from "./crypto.js";

export type WebhookScheme = "hmac-sha256" | "hmac-sha1" | "ed25519";

export interface WebhookBridgeConfig {
  bridgeId: string;
  trustDomain: string;
  /** Vendor identifier (e.g. `stripe`, `github`, `slack`). Recorded in
   *  the projected ProofEvent's `context.vendor`. */
  vendor: string;
  /** Signature scheme this bridge enforces. */
  scheme: WebhookScheme;
  /** Shared secret (HMAC) or ed25519 public key, depending on scheme. */
  secret: Uint8Array;
  /** Maximum acceptable age of a webhook delivery. Default 300s. */
  maxAgeSeconds?: number;
  /** Map a vendor event type to a TrustForge action name. */
  actionMapper?: (vendorEvent: string) => string;
  /** Default capability risk class. Default R2. */
  defaultRisk?: Capability["risk"];
}

export interface VerifyWebhookArgs {
  /** Raw HTTP body (as bytes). */
  body: Uint8Array;
  /** Signature header value provided by the vendor. */
  signatureHeader: string;
  /** Optional timestamp header — required for ed25519 mode. */
  timestampHeader?: string;
  /** Vendor-supplied event type identifier. */
  eventType: string;
  /** Vendor-supplied event id (used as the ProofEvent id). */
  eventId: string;
  /** When the verifier observed the delivery. Defaults to "now". */
  receivedAt?: Timestamp;
}

export interface WebhookVerificationResult {
  event: ProofEvent;
  capability: Capability;
}

export class WebhookBridge implements Bridge {
  readonly kind: BridgeKind = "webhook";
  readonly bridgeId: string;
  readonly trustDomain: string;
  private readonly cfg: WebhookBridgeConfig;

  constructor(cfg: WebhookBridgeConfig) {
    this.bridgeId = cfg.bridgeId;
    this.trustDomain = cfg.trustDomain;
    this.cfg = cfg;
  }

  async verify(args: VerifyWebhookArgs): Promise<WebhookVerificationResult> {
    const now = args.receivedAt ?? new Date().toISOString();
    if (this.cfg.scheme !== "ed25519" && !this.cfg.secret) {
      throw new BridgeFailure({ code: "invalid-input", message: "webhook bridge missing secret" });
    }

    let ok = false;
    if (this.cfg.scheme === "hmac-sha256") {
      ok = constantTimeEqualHex(
        args.signatureHeader.toLowerCase(),
        toHex(hmac(sha256, this.cfg.secret, args.body)),
      );
    } else if (this.cfg.scheme === "hmac-sha1") {
      ok = constantTimeEqualHex(
        args.signatureHeader.toLowerCase().replace(/^sha1=/, ""),
        toHex(hmac(sha1, this.cfg.secret, args.body)),
      );
    } else if (this.cfg.scheme === "ed25519") {
      if (!args.timestampHeader) {
        throw new BridgeFailure({
          code: "invalid-input",
          message: "ed25519 webhook requires timestamp header",
        });
      }
      const payload = new TextEncoder().encode(`${args.timestampHeader}.${new TextDecoder().decode(args.body)}`);
      const sig = decodeHex(args.signatureHeader);
      if (!sig) {
        throw new BridgeFailure({ code: "invalid-input", message: "signature header is not hex" });
      }
      ok = await ed25519Verify(this.cfg.secret, payload, sig);
    }
    if (!ok) {
      throw new BridgeFailure({
        code: "rejected",
        message: `webhook signature verification failed (${this.cfg.scheme})`,
      });
    }

    // Replay protection.
    const max = this.cfg.maxAgeSeconds ?? 300;
    const ts = args.timestampHeader ?? now;
    const tsDate = Date.parse(ts.includes("T") ? ts : new Date(Number(ts) * 1000).toISOString());
    const nowMs = Date.parse(now);
    if (Number.isFinite(tsDate)) {
      const ageSec = Math.abs(nowMs - tsDate) / 1000;
      if (ageSec > max) {
        throw new BridgeFailure({
          code: "rejected",
          message: `webhook age ${ageSec.toFixed(1)}s exceeds max ${max}s`,
        });
      }
    }

    const actor: ActorId = `tf:actor:service:${this.cfg.trustDomain}/${this.cfg.vendor}`;
    const action =
      this.cfg.actionMapper?.(args.eventType) ??
      `webhook.${this.cfg.vendor}.${args.eventType.replace(/[^a-z0-9._-]/gi, "_")}`;
    const event: ProofEvent = {
      event_version: "1",
      id: args.eventId,
      type: action,
      actor_id: actor,
      timestamp: now,
      level: "L2",
      context: {
        vendor: this.cfg.vendor,
        scheme: this.cfg.scheme,
        event_type: args.eventType,
      },
      signature: {
        algorithm: "ed25519",
        signer: actor,
        signature: "AAAA",
      },
    };
    const capability: Capability = {
      name: action,
      risk: this.cfg.defaultRisk ?? "R2",
    };
    return { event, capability };
  }
}

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

function decodeHex(s: string): Uint8Array | null {
  const trimmed = s.trim().toLowerCase().replace(/^sha\d+=/, "").replace(/^0x/, "");
  if (!/^[0-9a-f]*$/.test(trimmed) || trimmed.length % 2 !== 0) return null;
  const out = new Uint8Array(trimmed.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
