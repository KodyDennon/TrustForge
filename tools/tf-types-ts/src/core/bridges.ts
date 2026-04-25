/**
 * Common bridge framework. Concrete bridges (SPIFFE, WebAuthn, MCP) register
 * themselves with a BridgeRegistry so higher-level code can look up a bridge
 * by kind at runtime.
 */

export type BridgeKind =
  | "spiffe"
  | "webauthn"
  | "mcp"
  | "oauth"
  | "gnap"
  | "tls"
  | "did"
  | "matrix"
  | "webhook"
  | "grpc"
  | "service-mesh"
  | "a2a";

export interface BridgeError {
  code: "unsupported" | "invalid-input" | "rejected" | "internal";
  message: string;
}

export class BridgeFailure extends Error {
  readonly code: BridgeError["code"];
  constructor(err: BridgeError) {
    super(`${err.code}: ${err.message}`);
    this.code = err.code;
  }
}

export interface Bridge {
  readonly bridgeId: string;
  readonly kind: BridgeKind;
  readonly trustDomain: string;
}

export class BridgeRegistry {
  private bridges: Bridge[] = [];

  register(bridge: Bridge): void {
    this.bridges.push(bridge);
  }

  get<T extends Bridge>(kind: BridgeKind): T | undefined {
    return this.bridges.find((b) => b.kind === kind) as T | undefined;
  }

  list(): Bridge[] {
    return [...this.bridges];
  }
}
