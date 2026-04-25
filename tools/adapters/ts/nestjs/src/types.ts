// TrustForge SDK shape (structural).

export type TfDecisionVerdict =
  | "allow"
  | "deny"
  | "escalate"
  | "approval-required"
  | "log-only";

export type TfTrustLevel =
  | "T0" | "T1" | "T2" | "T3" | "T4" | "T5" | "T6" | "T7";

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
 * Subset of Express's `Request` we actually need. NestJS HTTP adapters expose
 * the underlying request via `ExecutionContext.switchToHttp().getRequest()`.
 */
export interface NestHttpReqLike {
  method?: string;
  url?: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  cookies?: Record<string, string>;
  // Where we attach the decision so subsequent handlers can read it.
  tfActor?: string;
  tfDecision?: TfDecision;
  tfProofId?: string;
}

/** Minimal NestJS ExecutionContext shape — enough for the guard. */
export interface NestExecutionContextLike {
  switchToHttp(): { getRequest<T = NestHttpReqLike>(): T };
  getHandler(): Function;
  getClass(): Function;
}

export interface TfNestOptions {
  daemonUrl?: string;
  adminToken?: string;
  tf?: TrustForgeLike;
  profile?: string;
  mode?: TfMode;
  /** Default action when no `@TrustForgeRequire("...")` annotation is present. */
  defaultAction?: string;
  resolveAction?: (req: NestHttpReqLike) => string | Promise<string>;
  resolveCredential?: (
    req: NestHttpReqLike,
  ) => {
    host_token?: string | null;
    host_token_kind?: TfHostTokenKind | null;
    actor?: string | null;
  };
  resolveTraceId?: (req: NestHttpReqLike) => string;
  resolveContext?: (req: NestHttpReqLike) => Record<string, unknown>;
  skip?: (path: string) => boolean;
}
