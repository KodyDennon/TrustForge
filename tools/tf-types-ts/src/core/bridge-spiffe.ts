/**
 * SPIFFE bridge. Maps SPIFFE IDs (spiffe://<trust-domain>/<path>) into
 * TrustForge service actor URIs (tf:actor:service:<trust-domain>/<path>)
 * and back.
 */

import { BridgeFailure, type Bridge, type BridgeKind } from "./bridges.js";

export interface ParsedSpiffeId {
  trustDomain: string;
  path: string;
  raw: string;
}

export function parseSpiffeId(id: string): ParsedSpiffeId {
  if (typeof id !== "string" || id.length === 0) {
    throw new BridgeFailure({ code: "invalid-input", message: "empty SPIFFE ID" });
  }
  if (!id.startsWith("spiffe://")) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: `SPIFFE ID must start with spiffe://, got ${JSON.stringify(id)}`,
    });
  }
  const rest = id.slice("spiffe://".length);
  const slash = rest.indexOf("/");
  const trustDomain = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? "" : rest.slice(slash + 1);
  if (!trustDomain) {
    throw new BridgeFailure({ code: "invalid-input", message: "SPIFFE ID has no trust domain" });
  }
  if (!path) {
    throw new BridgeFailure({ code: "invalid-input", message: "SPIFFE ID has no path" });
  }
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(trustDomain)) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: `SPIFFE trust domain is not DNS-like: ${trustDomain}`,
    });
  }
  return { trustDomain, path, raw: id };
}

/** SPIFFE → TrustForge service actor URI. */
export function spiffeToActorId(id: string): string {
  const parsed = parseSpiffeId(id);
  return `tf:actor:service:${parsed.trustDomain}/${parsed.path}`;
}

/** TrustForge service actor URI → SPIFFE ID. Non-service actors are
 *  rejected with BridgeFailure { code: "unsupported" }. */
export function actorIdToSpiffe(actorId: string): string {
  const match = /^tf:actor:([^:]+):(.+)$/.exec(actorId);
  if (!match) {
    throw new BridgeFailure({ code: "invalid-input", message: `malformed actor URI: ${actorId}` });
  }
  const [, type, path] = match;
  if (type !== "service") {
    throw new BridgeFailure({
      code: "unsupported",
      message: `SPIFFE bridge only projects service actors, got ${type}`,
    });
  }
  const slash = path!.indexOf("/");
  if (slash < 0) {
    throw new BridgeFailure({
      code: "invalid-input",
      message: `service actor path must be <trust-domain>/<path>, got ${path}`,
    });
  }
  const trustDomain = path!.slice(0, slash);
  const tail = path!.slice(slash + 1);
  return `spiffe://${trustDomain}/${tail}`;
}

export class SpiffeBridge implements Bridge {
  readonly kind: BridgeKind = "spiffe";
  constructor(
    public readonly bridgeId: string,
    public readonly trustDomain: string,
  ) {}
  toActorId(spiffe: string): string {
    return spiffeToActorId(spiffe);
  }
  toSpiffe(actorId: string): string {
    return actorIdToSpiffe(actorId);
  }
}
