/**
 * @trustforge/auth0 — verifies an Auth0 access / id token (RS256, JWKS) via
 * `jose` (loaded dynamically) and projects the resolved `sub` into a
 * TrustForge decide call with `host_token_kind: "auth0-jwt"`.
 *
 * Usage (Express):
 *   import { trustforgeAuth0 } from "@trustforge/auth0";
 *   app.use(trustforgeAuth0({
 *     daemonUrl: "...",
 *     domain: "my-tenant.us.auth0.com",
 *     audience: "https://api.example.com",
 *   }));
 *
 * Tests can inject a `verifyToken` callback to skip JWKS entirely.
 */
import {
  TrustForge,
  type AdapterMode,
  type DecideResponse,
} from "@trustforge/sdk";

export interface Auth0Claims {
  sub: string;
  aud?: string | string[];
  iss?: string;
  scope?: string;
  permissions?: string[];
  email?: string;
  [k: string]: unknown;
}

export type Auth0Verifier = (token: string) => Promise<Auth0Claims>;

export interface TfAuth0Options {
  daemonUrl: string;
  adminToken?: string;
  /** Auth0 tenant domain (e.g. `my-tenant.us.auth0.com`). */
  domain?: string;
  /** API audience. */
  audience?: string;
  /** Issuer override. Default: `https://<domain>/`. */
  issuer?: string;
  /** Inject a verifier directly (tests, custom verification). */
  verifyToken?: Auth0Verifier;
  client?: TrustForge;
  mode?: AdapterMode;
  defaultAction?: string;
}

interface JoseLike {
  createRemoteJWKSet: (url: URL) => unknown;
  jwtVerify: (
    token: string,
    keyset: unknown,
    opts: { issuer?: string; audience?: string },
  ) => Promise<{ payload: Auth0Claims }>;
}

let cachedKeyset: unknown = null;

async function defaultVerifier(
  token: string,
  opts: TfAuth0Options,
): Promise<Auth0Claims> {
  if (!opts.domain) {
    throw new Error("auth0: `domain` option is required when no verifyToken is provided");
  }
  const moduleName = "jose";
  const mod: unknown = await import(/* @vite-ignore */ moduleName);
  const jose = mod as JoseLike;
  if (!cachedKeyset) {
    cachedKeyset = jose.createRemoteJWKSet(
      new URL(`https://${opts.domain}/.well-known/jwks.json`),
    );
  }
  const issuer = opts.issuer ?? `https://${opts.domain}/`;
  const { payload } = await jose.jwtVerify(token, cachedKeyset, {
    issuer,
    audience: opts.audience,
  });
  return payload;
}

function newTraceId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `tf-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

export async function decideForAuth0Token(
  token: string,
  opts: TfAuth0Options,
  ctx: {
    action?: string;
    target?: string | null;
    context?: Record<string, unknown>;
  } = {},
): Promise<{ decision: DecideResponse; claims: Auth0Claims }> {
  const verifier = opts.verifyToken ?? ((tok: string) => defaultVerifier(tok, opts));
  const claims = await verifier(token);
  if (!claims?.sub) {
    throw new Error("auth0: verified token has no `sub`");
  }
  const tf =
    opts.client ??
    new TrustForge({ daemonUrl: opts.daemonUrl, adminToken: opts.adminToken });
  const decision = await tf.decide({
    actor: null,
    host_token: token,
    host_token_kind: "auth0-jwt",
    action: ctx.action ?? opts.defaultAction ?? "http.request",
    target: ctx.target ?? null,
    context: {
      sub: claims.sub,
      ...(claims.email ? { email: claims.email } : {}),
      ...(claims.scope ? { scope: claims.scope } : {}),
      ...(claims.permissions ? { permissions: claims.permissions } : {}),
      ...(ctx.context ?? {}),
    },
    trace_id: newTraceId(),
  });
  return { decision, claims };
}

interface ExpressLikeReq {
  headers: Record<string, string | string[] | undefined>;
  url?: string;
  originalUrl?: string;
  method?: string;
  tfActor?: string;
  tfDecision?: DecideResponse;
  tfProofId?: string;
  tfAuth0Sub?: string;
}
interface ExpressLikeRes {
  status: (code: number) => ExpressLikeRes;
  json: (body: unknown) => ExpressLikeRes;
  setHeader: (name: string, value: string) => void;
}
type NextFn = (err?: unknown) => void;

export function trustforgeAuth0(opts: TfAuth0Options) {
  const mode = opts.mode ?? "enforce";
  return async function trustforgeAuth0Mw(
    req: ExpressLikeReq,
    res: ExpressLikeRes,
    next: NextFn,
  ): Promise<void> {
    const auth = (req.headers["authorization"] as string | undefined) ?? "";
    if (!auth.toLowerCase().startsWith("bearer ")) {
      if (mode === "observe-only") return next();
      res.status(401).json({ error: "missing-bearer-token" });
      return;
    }
    const token = auth.slice(7).trim();
    let outcome: { decision: DecideResponse; claims: Auth0Claims };
    try {
      outcome = await decideForAuth0Token(token, opts, {
        target: req.originalUrl ?? req.url ?? null,
        context: { method: req.method },
      });
    } catch (err) {
      if (mode === "observe-only") return next();
      res.status(401).json({
        error: "auth0-verify-failed",
        detail: (err as Error).message,
      });
      return;
    }
    req.tfActor = outcome.decision.actor_resolved;
    req.tfDecision = outcome.decision;
    req.tfProofId = outcome.decision.proof_id;
    req.tfAuth0Sub = outcome.claims.sub;
    res.setHeader("x-tf-proof-id", outcome.decision.proof_id);
    if (mode === "observe-only") return next();
    return dispatch(outcome.decision, res, next);
  };
}

function dispatch(
  decision: DecideResponse,
  res: ExpressLikeRes,
  next: NextFn,
): void {
  switch (decision.decision) {
    case "allow":
    case "log-only":
      return next();
    case "deny":
    case "escalate":
      res.status(403).json({
        error: "forbidden",
        decision: decision.decision,
        reason: decision.reason,
        proof_id: decision.proof_id,
        danger_tags: decision.danger_tags,
      });
      return;
    case "approval-required":
      if (decision.approval_id) {
        res.setHeader("location", `/approvals/${decision.approval_id}`);
      }
      res.status(202).json({
        decision: "approval-required",
        approval_id: decision.approval_id,
        reason: decision.reason,
        proof_id: decision.proof_id,
      });
      return;
    default:
      res.status(500).json({
        error: "unknown-decision",
        decision: decision.decision,
      });
  }
}

export type { DecideResponse } from "@trustforge/sdk";
