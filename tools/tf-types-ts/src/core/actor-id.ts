import type { ActorType } from "../generated/_common.js";
import { sha256 } from "@noble/hashes/sha2";
import { toHex } from "./crypto.js";

export class ActorIdParseError extends Error {}

export const ACTOR_TYPES: readonly ActorType[] = [
  "human",
  "agent",
  "device",
  "service",
  "site",
  "organization",
  "relay",
  "plugin",
  "process",
  "tool",
  "model-provider",
  "policy-engine",
  "proof-anchor",
  "emergency-authority",
];

const ACTOR_TYPE_SET: ReadonlySet<string> = new Set<string>(ACTOR_TYPES);

export interface ParsedActorId {
  readonly type: ActorType;
  readonly path: string;
  readonly raw: string;
}

/**
 * Parse an actor URI of the form `tf:actor:<type>:<path>`.
 *
 * Per RFC 3986 the scheme is case-insensitive but we require the canonical
 * lower-case form; the colon-delimited type must be one of the 14 types
 * enumerated in TF-0002; the path segment is required and non-empty.
 */
export function parseActorId(s: string): ParsedActorId {
  if (typeof s !== "string") throw new ActorIdParseError(`expected string, got ${typeof s}`);
  const parts = splitScheme(s);
  if (!parts) throw new ActorIdParseError(`expected tf:actor:<type>:<path>, got ${JSON.stringify(s)}`);
  if (parts.kind !== "actor") {
    throw new ActorIdParseError(`expected scheme 'tf:actor:', got 'tf:${parts.kind}:'`);
  }
  if (!ACTOR_TYPE_SET.has(parts.typeSegment)) {
    throw new ActorIdParseError(`unknown actor type: ${parts.typeSegment}`);
  }
  if (parts.path.length === 0) throw new ActorIdParseError("actor id path is empty");
  return { type: parts.typeSegment as ActorType, path: parts.path, raw: s };
}

export function formatActorId(p: { type: ActorType; path: string }): string {
  if (!ACTOR_TYPE_SET.has(p.type)) throw new ActorIdParseError(`unknown actor type: ${p.type}`);
  if (!p.path) throw new ActorIdParseError("actor id path is empty");
  return `tf:actor:${p.type}:${p.path}`;
}

export function actorIdEquals(a: string, b: string): boolean {
  try {
    const pa = parseActorId(a);
    const pb = parseActorId(b);
    return pa.type === pb.type && pa.path === pb.path;
  } catch {
    return false;
  }
}

/**
 * Derive the canonical actor URI for a peer identified by an ed25519 public
 * key. The URI is bound to the key by construction: `tf:actor:process:key/<hex>`
 * where `<hex>` is the lowercase hex prefix of `sha256(ident_pub)` truncated
 * to 8 bytes (16 hex chars). This is the cryptographic identity the daemon
 * passes to AgentGuard; callers can additionally accept a `peer_hint` as a
 * self-claimed alias, but it is advisory only — never used for authority.
 */
export function derivePeerActor(identPub: Uint8Array): string {
  if (identPub.length !== 32) {
    throw new ActorIdParseError(`derivePeerActor expects 32-byte ed25519 public key, got ${identPub.length}`);
  }
  const digest = sha256(identPub);
  const thumbprint = toHex(digest.slice(0, 8));
  return `tf:actor:process:key/${thumbprint}`;
}

export function splitScheme(s: string): { kind: string; typeSegment: string; path: string } | null {
  if (!s.startsWith("tf:")) return null;
  const rest = s.slice(3);
  const firstColon = rest.indexOf(":");
  if (firstColon < 0) return null;
  const kind = rest.slice(0, firstColon);
  const remainder = rest.slice(firstColon + 1);
  const secondColon = remainder.indexOf(":");
  if (secondColon < 0) return null;
  const typeSegment = remainder.slice(0, secondColon);
  const path = remainder.slice(secondColon + 1);
  return { kind, typeSegment, path };
}
