/**
 * @trustforge-protocol/logto — verifies a Logto access token (JWT, RS256) via
 * `jose` against Logto's OIDC JWKS endpoint, then projects the resolved
 * `sub` into a TrustForge decide call with `host_token_kind: "logto-jwt"`.
 *
 * Usage (Express):
 *   import { trustforgeLogto } from "@trustforge-protocol/logto";
 *   app.use(trustforgeLogto({
 *     daemonUrl: "...",
 *     endpoint: "https://my-logto.app",
 *     audience: "https://api.example.com",
 *   }));
 *
 * Tests can inject a `verifyToken` callback to skip JWKS entirely.
 */
import {
  TrustForge,
  type AdapterMode,
  type DecideResponse,
} from "@trustforge-protocol/sdk";

export interface LogtoClaims {
  sub: string;
  aud?: string | string[];
  iss?: string;
  scope?: string;
  client_id?: string;
  email?: string;
  username?: string;
  [k: string]: unknown;
}

export type LogtoVerifier = (token: string) => Promise<LogtoClaims>;

export interface TfLogtoOptions {
  daemonUrl: string;
  adminToken?: string;
  /** Logto endpoint, e.g. `https://my-logto.app`. */
  endpoint?: string;
  /** Resource indicator (audience). */
  audience?: string;
  /** Issuer override. Default: `<endpoint>/oidc`. */
  issuer?: string;
  /** Tests / advanced callers: inject a verifier directly. */
  verifyToken?: LogtoVerifier;
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
  ) => Promise<{ payload: LogtoClaims }>;
}

let cachedKeyset: unknown = null;

async function defaultVerifier(
  token: string,
  opts: TfLogtoOptions,
): Promise<LogtoClaims> {
  if (!opts.endpoint) {
    throw new Error("logto: `endpoint` is required when no verifyToken is provided");
  }
  const moduleName = "jose";
  const mod: unknown = await import(/* @vite-ignore */ moduleName);
  const jose = mod as JoseLike;
  const base = opts.endpoint.replace(/\/$/, "");
  if (!cachedKeyset) {
    cachedKeyset = jose.createRemoteJWKSet(new URL(`${base}/oidc/jwks`));
  }
  const issuer = opts.issuer ?? `${base}/oidc`;
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

export async function decideForLogtoToken(
  token: string,
  opts: TfLogtoOptions,
  ctx: {
    action?: string;
    target?: string | null;
    context?: Record<string, unknown>;
  } = {},
): Promise<{ decision: DecideResponse; claims: LogtoClaims }> {
  const verifier = opts.verifyToken ?? ((tok: string) => defaultVerifier(tok, opts));
  const claims = await verifier(token);
  if (!claims?.sub) {
    throw new Error("logto: verified token has no `sub`");
  }
  const tf =
    opts.client ??
    new TrustForge({ daemonUrl: opts.daemonUrl, adminToken: opts.adminToken });
  const decision = await tf.decide({
    actor: null,
    host_token: token,
    host_token_kind: "logto-jwt",
    action: ctx.action ?? opts.defaultAction ?? "http.request",
    target: ctx.target ?? null,
    context: {
      sub: claims.sub,
      ...(claims.email ? { email: claims.email } : {}),
      ...(claims.username ? { username: claims.username } : {}),
      ...(claims.scope ? { scope: claims.scope } : {}),
      ...(claims.client_id ? { client_id: claims.client_id } : {}),
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
  tfLogtoSub?: string;
}
interface ExpressLikeRes {
  status: (code: number) => ExpressLikeRes;
  json: (body: unknown) => ExpressLikeRes;
  setHeader: (name: string, value: string) => void;
}
type NextFn = (err?: unknown) => void;

export function trustforgeLogto(opts: TfLogtoOptions) {
  const mode = opts.mode ?? "enforce";
  return async function trustforgeLogtoMw(
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
    let outcome: { decision: DecideResponse; claims: LogtoClaims };
    try {
      outcome = await decideForLogtoToken(token, opts, {
        target: req.originalUrl ?? req.url ?? null,
        context: { method: req.method },
      });
    } catch (err) {
      if (mode === "observe-only") return next();
      res.status(401).json({
        error: "logto-verify-failed",
        detail: (err as Error).message,
      });
      return;
    }
    req.tfActor = outcome.decision.actor_resolved;
    req.tfDecision = outcome.decision;
    req.tfProofId = outcome.decision.proof_id;
    req.tfLogtoSub = outcome.claims.sub;
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

export type { DecideResponse } from "@trustforge-protocol/sdk";
