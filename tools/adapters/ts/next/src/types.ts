// Shared type contract for the TrustForge SDK.
//
// We intentionally define a structural interface here rather than importing
// the SDK directly so this adapter can be type-checked and tested even when
// `@trustforge/sdk` isn't fully built yet, and so consumers can inject a
// mock client (useful for tests + observe-only mode).

export type TfDecisionVerdict =
  | "allow"
  | "deny"
  | "escalate"
  | "approval-required"
  | "log-only";

export type TfTrustLevel =
  | "T0"
  | "T1"
  | "T2"
  | "T3"
  | "T4"
  | "T5"
  | "T6"
  | "T7";

export type TfAuthorityMode = "layered" | "replace" | "co-equal";

export type TfHostTokenKind =
  | "oauth-jwt"
  | "clerk-session"
  | "next-auth-jwt"
  | "better-auth-session"
  | "webauthn-assertion"
  | "mtls-cert-pem"
  | "spiffe-svid"
  | "session-cookie";

export interface TfDecideRequest {
  actor?: string | null;
  host_token?: string | null;
  host_token_kind?: TfHostTokenKind | null;
  action: string;
  target?: string | null;
  context?: Record<string, unknown>;
  trace_id?: string;
}

export interface TfDecision {
  decision: TfDecisionVerdict;
  reason: string;
  approval_id: string | null;
  proof_id: string;
  actor_resolved: string;
  trust_level: TfTrustLevel;
  authority_mode: TfAuthorityMode;
  danger_tags: string[];
}

/**
 * Minimal contract every TrustForge SDK instance must satisfy.
 * Real SDK: `import { TrustForge } from "@trustforge/sdk"` returns one of these.
 */
export interface TrustForgeLike {
  decide(req: TfDecideRequest): Promise<TfDecision>;
}

export type TfMode = "enforce" | "observe-only";

export interface TfAdapterOptions {
  /** URL of the tf-daemon `/v1/decide` endpoint, e.g. `http://127.0.0.1:8642`. */
  daemonUrl?: string;
  /** Bearer token for the daemon's admin API. */
  adminToken?: string;
  /**
   * Pre-instantiated SDK client. If provided, `daemonUrl`/`adminToken` are
   * ignored. Useful for tests and for sharing a single SDK across adapters.
   */
  tf?: TrustForgeLike;
  /** Profile name forwarded to the daemon (home/enterprise/constrained/...). */
  profile?: string;
  /**
   * `enforce`  — deny/approval-required verdicts short-circuit the request.
   * `observe-only` — every verdict is logged but the request is forwarded.
   */
  mode?: TfMode;
  /**
   * Map a request to the action string. Defaults to `${method.toLowerCase()}.${pathSegment}`.
   */
  resolveAction?: (req: TfRequestLike) => string | Promise<string>;
  /**
   * Extract a host token + kind from the incoming request (cookies, Authorization header, etc.).
   * Default extractor handles `Authorization: Bearer ...`, `__Secure-next-auth.session-token`,
   * and `sess_` / `auth_` cookies.
   */
  resolveCredential?: (
    req: TfRequestLike,
  ) =>
    | {
        host_token?: string | null;
        host_token_kind?: TfHostTokenKind | null;
        actor?: string | null;
      }
    | Promise<{
        host_token?: string | null;
        host_token_kind?: TfHostTokenKind | null;
        actor?: string | null;
      }>;
  /** Build the trace id for the decide request; defaults to `crypto.randomUUID()`. */
  resolveTraceId?: (req: TfRequestLike) => string;
  /** Extra context fields to merge into every decide call. */
  resolveContext?: (
    req: TfRequestLike,
  ) => Record<string, unknown> | Promise<Record<string, unknown>>;
  /** Routes to skip entirely (regex or string prefix match). */
  skip?: (path: string) => boolean;
}

/**
 * Subset of fields adapters can rely on across both web `Request` and
 * Next.js's `NextRequest`.
 */
export interface TfRequestLike {
  method: string;
  url: string;
  headers: Headers;
  cookies?: { get(name: string): { value: string } | undefined };
  nextUrl?: { pathname: string };
}
