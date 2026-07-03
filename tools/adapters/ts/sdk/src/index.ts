/**
 * @trustforge-protocol/sdk — thin TypeScript client over the tf-daemon HTTP API.
 *
 * Wire format is pinned by `conformance/decide-protocol-vectors.yaml` and
 * MUST stay byte-compatible with every other language adapter. This module
 * deliberately keeps zero non-bun runtime dependencies (uses global `fetch`).
 */

// ---------------------------------------------------------------------------
// Wire types — DecideRequest / DecideResponse
// ---------------------------------------------------------------------------

/** Adapter-side mode flag. `enforce` blocks on deny/approval; `observe-only`
 *  forwards everything but still records the decision for proof + audit. */
export type AdapterMode = "enforce" | "observe-only";

export type DecisionVerb =
  | "allow"
  | "deny"
  | "escalate"
  | "approval-required"
  | "log-only";

export type AuthorityMode = "layered" | "co-equal" | "replace";

/** Host-token kinds recognised by tf-daemon (matches B1 / decide vectors).
 *
 * Vendor-specific kinds (e.g. `firebase-id-token`, `auth0-jwt`, `kinde-jwt`,
 * etc.) are accepted as plain strings — `(string & {})` keeps the autocomplete
 * for the well-known cases while still admitting new bridges added by adapters
 * without an SDK release. */
export type HostTokenKind =
  | "auto"
  | "oauth-jwt"
  | "clerk-session"
  | "next-auth-jwt"
  | "better-auth-session"
  | "webauthn-assertion"
  | "mtls-cert-pem"
  | "spiffe-svid"
  | "session-cookie"
  | "bearer-opaque"
  | "firebase-id-token"
  | "supabase-jwt"
  | "workos-jwt"
  | "auth0-jwt"
  | "stack-auth"
  | "kinde-jwt"
  | "logto-jwt"
  // eslint-disable-next-line @typescript-eslint/ban-types
  | (string & {});

export interface DecideRequest {
  /** TrustForge actor URI; pass null and use host_token to ask the daemon to resolve. */
  actor: string | null;
  /** Host-side credential (OAuth JWT, Clerk session id, etc.) — daemon resolves to actor. */
  host_token?: string;
  /** Hint for which credential bridge to apply. `auto` = daemon auto-detects. */
  host_token_kind?: HostTokenKind;
  /** Dotted action name (`fs.read`, `shell.exec`, ...). */
  action: string;
  /** Optional target (path / URL / actor URI / arbitrary string). */
  target: string | null;
  /** Free-form context bag forwarded to policy evaluation. */
  context: Record<string, unknown>;
  /** Caller-generated trace identifier; daemon echoes it back via proof_id. */
  trace_id: string;
}

export interface DecideResponse {
  decision: DecisionVerb;
  reason: string;
  approval_id: string | null;
  proof_id: string;
  actor_resolved: string;
  trust_level: string;
  authority_mode: AuthorityMode;
  danger_tags: string[];
}

// ---------------------------------------------------------------------------
// Credential / proof helper types
// ---------------------------------------------------------------------------

export interface ImportCredentialRequest {
  kind: HostTokenKind | string;
  token: string;
  actor_hint?: string;
}

export interface ImportCredentialResponse {
  actor: string;
  credential_id: string;
  trust_level: string;
}

export interface ProofEvent {
  kind: string;
  actor: string;
  trace_id: string;
  payload?: Record<string, unknown>;
}

export interface SignedProofEvent extends ProofEvent {
  event_hash: string;
  signature: string;
}

export interface VerifyProofResponse {
  ok: boolean;
  signer_actor: string;
  trust_level: string;
}

// ---------------------------------------------------------------------------
// SDK class
// ---------------------------------------------------------------------------

export interface TrustForgeOptions {
  /** Base URL of the tf-daemon HTTP endpoint, e.g. `http://127.0.0.1:7616`. */
  daemonUrl: string;
  /** Optional admin bearer token for daemon-side auth. */
  adminToken?: string;
  /** Optional fetch override (for tests). Defaults to global `fetch`. */
  fetchImpl?: typeof fetch;
  /** Optional per-request timeout (ms). Default: 5000. */
  timeoutMs?: number;
}

export class TrustForgeError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly body?: unknown,
  ) {
    super(message);
    this.name = "TrustForgeError";
  }
}

export class TrustForge {
  readonly daemonUrl: string;
  readonly adminToken?: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: TrustForgeOptions) {
    if (!opts.daemonUrl) {
      throw new Error("TrustForge: daemonUrl is required");
    }
    this.daemonUrl = opts.daemonUrl.replace(/\/$/, "");
    this.adminToken = opts.adminToken;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 5000;
  }

  /** POST /v1/decide */
  async decide(req: DecideRequest): Promise<DecideResponse> {
    return await this.post<DecideResponse>("/v1/decide", req);
  }

  /** POST /v1/credentials/import */
  async importCredential(
    cred: ImportCredentialRequest,
  ): Promise<ImportCredentialResponse> {
    return await this.post<ImportCredentialResponse>(
      "/v1/credentials/import",
      cred,
    );
  }

  /** POST /v1/proofs/sign */
  async signProof(
    event: ProofEvent,
  ): Promise<{ event_hash: string; signature: string }> {
    return await this.post<{ event_hash: string; signature: string }>(
      "/v1/proofs/sign",
      event,
    );
  }

  /** POST /v1/proofs/verify */
  async verifyProof(event: SignedProofEvent): Promise<VerifyProofResponse> {
    return await this.post<VerifyProofResponse>("/v1/proofs/verify", {
      event: {
        kind: event.kind,
        actor: event.actor,
        trace_id: event.trace_id,
        payload: event.payload ?? {},
      },
      signature: event.signature,
      event_hash: event.event_hash,
    });
  }

  // ---------------------------------------------------------------------
  // internals
  // ---------------------------------------------------------------------

  private async post<T>(path: string, body: unknown): Promise<T> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json",
    };
    if (this.adminToken) {
      headers["authorization"] = `Bearer ${this.adminToken}`;
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(`${this.daemonUrl}${path}`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
      const text = await res.text();
      let parsed: unknown = undefined;
      if (text.length > 0) {
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = text;
        }
      }
      if (!res.ok) {
        throw new TrustForgeError(
          `TrustForge daemon ${path} returned ${res.status}`,
          res.status,
          parsed,
        );
      }
      return parsed as T;
    } finally {
      clearTimeout(timer);
    }
  }
}

export default TrustForge;
