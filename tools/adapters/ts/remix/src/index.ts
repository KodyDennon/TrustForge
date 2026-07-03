// Remix adapter for TrustForge.
//
// Public surface:
//   - trustforgeRemixHandle(opts) — install on `entry.server.tsx` to gate
//     every request (document loads + data fetches).
//   - withTrustForgeLoader(action, loader, opts) — wrap a loader so the
//     action is checked before the loader runs.
//   - withTrustForgeAction(action, action_fn, opts) — same for actions.
//   - tfRequire(action, opts) — generic wrapper that works for both
//     loaders and actions.

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

export interface TfRemixOptions {
  daemonUrl?: string;
  adminToken?: string;
  tf?: TrustForgeLike;
  profile?: string;
  mode?: TfMode;
  resolveAction?: (req: Request) => string | Promise<string>;
  resolveCredential?: (req: Request) => {
    host_token?: string | null;
    host_token_kind?: TfHostTokenKind | null;
    actor?: string | null;
  };
  resolveTraceId?: (req: Request) => string;
  resolveContext?: (req: Request) => Record<string, unknown>;
  skip?: (path: string) => boolean;
}

async function getClient(opts: TfRemixOptions): Promise<TrustForgeLike> {
  if (opts.tf) return opts.tf;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mod: any = await import("@trustforge-protocol/sdk").catch(() => null);
  if (!mod?.TrustForge) {
    throw new Error(
      "@trustforge-protocol/remix: @trustforge-protocol/sdk is not installed. " +
        "Pass `tf:` to the wrapper for testing.",
    );
  }
  return new mod.TrustForge({ daemonUrl: opts.daemonUrl, adminToken: opts.adminToken });
}

function defaultResolveAction(req: Request): string {
  const url = new URL(req.url);
  const segs = url.pathname.split("/").filter(Boolean);
  const first = segs[0] ?? "root";
  return `${req.method.toLowerCase()}.${first.replace(/[^a-z0-9_]/gi, "_").toLowerCase()}`;
}

function defaultResolveCredential(req: Request): {
  host_token: string | null;
  host_token_kind: TfHostTokenKind | null;
} {
  const auth = req.headers.get("authorization");
  if (auth?.toLowerCase().startsWith("bearer ")) {
    return { host_token: auth.slice(7).trim(), host_token_kind: "oauth-jwt" };
  }
  const cookie = req.headers.get("cookie") ?? "";
  const cookies: Record<string, string> = {};
  for (const part of cookie.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k) cookies[k] = rest.join("=");
  }
  const nextAuth =
    cookies["__Secure-next-auth.session-token"] ?? cookies["next-auth.session-token"];
  if (nextAuth) return { host_token: nextAuth, host_token_kind: "next-auth-jwt" };
  for (const name of ["session", "auth", "tf-session", "_session", "__session"]) {
    const v = cookies[name];
    if (!v) continue;
    if (v.startsWith("sess_")) return { host_token: v, host_token_kind: "clerk-session" };
    if (v.startsWith("auth_"))
      return { host_token: v, host_token_kind: "better-auth-session" };
  }
  return { host_token: null, host_token_kind: null };
}

function defaultResolveTraceId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `tf-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

async function buildDecideRequest(
  req: Request,
  opts: TfRemixOptions,
  forcedAction?: string,
): Promise<TfDecideRequest> {
  const cred = (opts.resolveCredential ?? defaultResolveCredential)(req);
  const action =
    forcedAction ??
    (await (opts.resolveAction ?? defaultResolveAction)(req));
  const trace_id = (opts.resolveTraceId ?? defaultResolveTraceId)(req);
  const extraCtx = opts.resolveContext?.(req) ?? {};
  const url = new URL(req.url);

  return {
    actor: "actor" in cred ? cred.actor ?? null : null,
    host_token: cred.host_token ?? null,
    host_token_kind: cred.host_token_kind ?? null,
    action,
    target: url.pathname + (url.search || ""),
    context: { method: req.method, ...extraCtx },
    trace_id,
  };
}

interface DecisionOutcome {
  allowed: boolean;
  decision: TfDecision;
  response?: Response;
}

async function evaluate(
  req: Request,
  opts: TfRemixOptions,
  forcedAction?: string,
): Promise<DecisionOutcome> {
  const client = await getClient(opts);
  const decideReq = await buildDecideRequest(req, opts, forcedAction);
  const decision = await client.decide(decideReq);

  const headers: Record<string, string> = {
    "x-tf-decision": decision.decision,
    "x-tf-proof-id": decision.proof_id,
    "x-tf-actor": decision.actor_resolved,
    "x-tf-trust-level": decision.trust_level,
  };

  if (opts.mode === "observe-only") {
    return { allowed: true, decision };
  }

  if (decision.decision === "allow" || decision.decision === "log-only") {
    return { allowed: true, decision };
  }

  const status = decision.decision === "approval-required" ? 202 : 403;
  const body =
    decision.decision === "approval-required"
      ? {
          decision: decision.decision,
          reason: decision.reason,
          approval_id: decision.approval_id,
        }
      : {
          decision: decision.decision,
          reason: decision.reason,
          danger_tags: decision.danger_tags,
        };

  const responseHeaders: Record<string, string> = {
    "content-type": "application/json",
    ...headers,
  };
  if (status === 202 && decision.approval_id) {
    responseHeaders.location = `/tf/approval/${decision.approval_id}`;
  } else if (status === 403) {
    responseHeaders["www-authenticate"] = `TrustForge realm="${decision.decision}"`;
  }

  return {
    allowed: false,
    decision,
    response: new Response(JSON.stringify(body), {
      status,
      headers: responseHeaders,
    }),
  };
}

// -------------------- Remix loader/action wrappers --------------------

/** Generic Remix loader/action argument shape. */
export interface RemixDataArgs {
  request: Request;
  params: Record<string, string | undefined>;
  context?: unknown;
}

/**
 * Wrap a Remix `loader` so the named action is checked first. Receives a
 * `decision` extension on the args so the loader can read the resolved actor.
 */
export function withTrustForgeLoader<T>(
  action: string,
  loader: (args: RemixDataArgs & { decision: TfDecision }) => Promise<T> | T,
  opts: TfRemixOptions = {},
): (args: RemixDataArgs) => Promise<T | Response> {
  return async (args) => {
    const outcome = await evaluate(args.request, opts, action);
    if (!outcome.allowed && outcome.response) return outcome.response;
    return loader({ ...args, decision: outcome.decision });
  };
}

/** Same shape as `withTrustForgeLoader` but for Remix actions. */
export function withTrustForgeAction<T>(
  action: string,
  fn: (args: RemixDataArgs & { decision: TfDecision }) => Promise<T> | T,
  opts: TfRemixOptions = {},
): (args: RemixDataArgs) => Promise<T | Response> {
  return async (args) => {
    const outcome = await evaluate(args.request, opts, action);
    if (!outcome.allowed && outcome.response) return outcome.response;
    return fn({ ...args, decision: outcome.decision });
  };
}

/** Alias readers may prefer. */
export const tfRequire = withTrustForgeAction;

// -------------------- entry.server handle --------------------

/**
 * Build the Remix `handle` shape used in `entry.server.tsx`. Wraps the Remix
 * request handler with a TrustForge pre-check.
 *
 * Usage:
 *
 *   import { createRequestHandler } from "@remix-run/server-runtime";
 *   import { trustforgeRemixHandle } from "@trustforge-protocol/remix";
 *
 *   const remixHandler = createRequestHandler(build, process.env.NODE_ENV);
 *   export const handler = trustforgeRemixHandle({ daemonUrl: "..." })(remixHandler);
 */
export function trustforgeRemixHandle(opts: TfRemixOptions = {}): (
  next: (req: Request, loadContext?: unknown) => Promise<Response>,
) => (req: Request, loadContext?: unknown) => Promise<Response> {
  return (next) => async (req, loadContext) => {
    const url = new URL(req.url);
    if (opts.skip?.(url.pathname)) return next(req, loadContext);

    const outcome = await evaluate(req, opts);
    if (!outcome.allowed && outcome.response) return outcome.response;

    const res = await next(req, loadContext);
    // Annotate the outgoing response.
    res.headers.set("x-tf-decision", outcome.decision.decision);
    res.headers.set("x-tf-proof-id", outcome.decision.proof_id);
    res.headers.set("x-tf-actor", outcome.decision.actor_resolved);
    res.headers.set("x-tf-trust-level", outcome.decision.trust_level);
    return res;
  };
}
