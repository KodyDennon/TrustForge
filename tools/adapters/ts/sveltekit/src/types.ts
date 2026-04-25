// Same structural contract as the Next.js adapter — duplicated here so each
// adapter is independently buildable and the SDK can ship later without
// breaking type-checks.

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

export interface TrustForgeLike {
  decide(req: TfDecideRequest): Promise<TfDecision>;
}

export type TfMode = "enforce" | "observe-only";

/**
 * Subset of SvelteKit's `RequestEvent` we touch. Defined structurally so the
 * adapter compiles without `@sveltejs/kit` installed.
 */
export interface SvelteRequestEventLike {
  request: Request;
  url: URL;
  cookies: { get(name: string): string | undefined };
  locals: Record<string, unknown>;
  // SvelteKit also has `getClientAddress`, `params`, `route`, `platform`,
  // `setHeaders`, `isDataRequest`, `isSubRequest` — we don't need them.
}

export type SvelteResolve = (
  event: SvelteRequestEventLike,
) => Promise<Response> | Response;

export type SvelteHandle = (input: {
  event: SvelteRequestEventLike;
  resolve: SvelteResolve;
}) => Promise<Response> | Response;

export interface TfSvelteOptions {
  daemonUrl?: string;
  adminToken?: string;
  tf?: TrustForgeLike;
  profile?: string;
  mode?: TfMode;
  resolveAction?: (event: SvelteRequestEventLike) => string | Promise<string>;
  resolveCredential?: (
    event: SvelteRequestEventLike,
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
  resolveTraceId?: (event: SvelteRequestEventLike) => string;
  resolveContext?: (
    event: SvelteRequestEventLike,
  ) => Record<string, unknown> | Promise<Record<string, unknown>>;
  skip?: (path: string) => boolean;
}
