/**
 * @trustforge-protocol/kinde — verifies a Kinde access / id JWT via
 * `@kinde-oss/kinde-typescript-sdk` (loaded dynamically) or directly via
 * `jose` against Kinde's JWKS endpoint, then projects the `sub` into a
 * TrustForge decide call with `host_token_kind: "kinde-jwt"`.
 *
 * Usage (Express):
 *   import { trustforgeKinde } from "@trustforge-protocol/kinde";
 *   app.use(trustforgeKinde({
 *     daemonUrl: "...",
 *     issuerUrl: "https://my-org.kinde.com",
 *   }));
 *
 * Tests can inject a `verifyToken` callback to skip JWKS entirely.
 */
import {
  TrustForge,
  type AdapterMode,
  type DecideResponse,
} from "@trustforge-protocol/sdk";

export interface KindeClaims {
  sub: string;
  aud?: string | string[];
  iss?: string;
  scope?: string;
  permissions?: string[];
  email?: string;
  org_code?: string;
  [k: string]: unknown;
}

export type KindeVerifier = (token: string) => Promise<KindeClaims>;

export interface TfKindeOptions {
  daemonUrl: string;
  adminToken?: string;
  /** Kinde issuer URL, e.g. `https://my-org.kinde.com`. */
  issuerUrl?: string;
  /** API audience (optional). */
  audience?: string;
  /** Tests / advanced callers: inject a verifier directly. */
  verifyToken?: KindeVerifier;
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
  ) => Promise<{ payload: KindeClaims }>;
}

let cachedKeyset: unknown = null;

async function defaultVerifier(
  token: string,
  opts: TfKindeOptions,
): Promise<KindeClaims> {
  if (!opts.issuerUrl) {
    throw new Error("kinde: `issuerUrl` is required when no verifyToken is provided");
  }
  const moduleName = "jose";
  const mod: unknown = await import(/* @vite-ignore */ moduleName);
  const jose = mod as JoseLike;
  if (!cachedKeyset) {
    cachedKeyset = jose.createRemoteJWKSet(
      new URL(`${opts.issuerUrl.replace(/\/$/, "")}/.well-known/jwks.json`),
    );
  }
  const { payload } = await jose.jwtVerify(token, cachedKeyset, {
    issuer: opts.issuerUrl,
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

export async function decideForKindeToken(
  token: string,
  opts: TfKindeOptions,
  ctx: {
    action?: string;
    target?: string | null;
    context?: Record<string, unknown>;
  } = {},
): Promise<{ decision: DecideResponse; claims: KindeClaims }> {
  const verifier = opts.verifyToken ?? ((tok: string) => defaultVerifier(tok, opts));
  const claims = await verifier(token);
  if (!claims?.sub) {
    throw new Error("kinde: verified token has no `sub`");
  }
  const tf =
    opts.client ??
    new TrustForge({ daemonUrl: opts.daemonUrl, adminToken: opts.adminToken });
  const decision = await tf.decide({
    actor: null,
    host_token: token,
    host_token_kind: "kinde-jwt",
    action: ctx.action ?? opts.defaultAction ?? "http.request",
    target: ctx.target ?? null,
    context: {
      sub: claims.sub,
      ...(claims.email ? { email: claims.email } : {}),
      ...(claims.org_code ? { org_code: claims.org_code } : {}),
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
  tfKindeSub?: string;
}
interface ExpressLikeRes {
  status: (code: number) => ExpressLikeRes;
  json: (body: unknown) => ExpressLikeRes;
  setHeader: (name: string, value: string) => void;
}
type NextFn = (err?: unknown) => void;

export function trustforgeKinde(opts: TfKindeOptions) {
  const mode = opts.mode ?? "enforce";
  return async function trustforgeKindeMw(
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
    let outcome: { decision: DecideResponse; claims: KindeClaims };
    try {
      outcome = await decideForKindeToken(token, opts, {
        target: req.originalUrl ?? req.url ?? null,
        context: { method: req.method },
      });
    } catch (err) {
      if (mode === "observe-only") return next();
      res.status(401).json({
        error: "kinde-verify-failed",
        detail: (err as Error).message,
      });
      return;
    }
    req.tfActor = outcome.decision.actor_resolved;
    req.tfDecision = outcome.decision;
    req.tfProofId = outcome.decision.proof_id;
    req.tfKindeSub = outcome.claims.sub;
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
