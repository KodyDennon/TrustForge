/**
 * @trustforge/stack-auth — verifies a Stack Auth session token via
 * `@stackframe/stack` (loaded dynamically) and projects the resolved user id
 * into a TrustForge decide call with `host_token_kind: "stack-auth"`.
 *
 * Usage (Express):
 *   import { trustforgeStackAuth } from "@trustforge/stack-auth";
 *   app.use(trustforgeStackAuth({
 *     daemonUrl: "...",
 *     projectId: process.env.STACK_PROJECT_ID!,
 *     publishableClientKey: process.env.STACK_PUBLISHABLE_CLIENT_KEY!,
 *     secretServerKey: process.env.STACK_SECRET_SERVER_KEY!,
 *   }));
 *
 * Tests can inject a `verifySession` callback to skip the SDK entirely.
 */
import {
  TrustForge,
  type AdapterMode,
  type DecideResponse,
} from "@trustforge/sdk";

export interface StackAuthUser {
  id: string;
  primaryEmail?: string;
  displayName?: string;
  [k: string]: unknown;
}

export type StackAuthVerifier = (token: string) => Promise<StackAuthUser>;

export interface TfStackAuthOptions {
  daemonUrl: string;
  adminToken?: string;
  projectId?: string;
  publishableClientKey?: string;
  secretServerKey?: string;
  /** Tests / advanced callers: inject a verifier directly. */
  verifySession?: StackAuthVerifier;
  client?: TrustForge;
  mode?: AdapterMode;
  defaultAction?: string;
  /** Cookie name to read for the stack-auth session. Default: `stack-access`. */
  cookieName?: string;
}

interface StackServerAppLike {
  getUser: (
    arg: string | { tokenStore?: unknown },
  ) => Promise<StackAuthUser | null>;
}

let cachedApp: StackServerAppLike | null = null;

async function defaultVerifier(
  token: string,
  opts: TfStackAuthOptions,
): Promise<StackAuthUser> {
  if (!opts.projectId || !opts.publishableClientKey || !opts.secretServerKey) {
    throw new Error(
      "stack-auth: projectId, publishableClientKey and secretServerKey are required when no verifySession is provided",
    );
  }
  if (!cachedApp) {
    const moduleName = "@stackframe/stack";
    const mod: unknown = await import(/* @vite-ignore */ moduleName);
    const m = mod as {
      StackServerApp?: new (cfg: Record<string, unknown>) => StackServerAppLike;
    };
    if (!m.StackServerApp) {
      throw new Error("stack-auth: failed to load StackServerApp");
    }
    cachedApp = new m.StackServerApp({
      tokenStore: "memory",
      projectId: opts.projectId,
      publishableClientKey: opts.publishableClientKey,
      secretServerKey: opts.secretServerKey,
    });
  }
  const user = await cachedApp.getUser(token);
  if (!user) throw new Error("stack-auth: no user for session token");
  return user;
}

function newTraceId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `tf-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

export async function decideForStackAuthToken(
  token: string,
  opts: TfStackAuthOptions,
  ctx: {
    action?: string;
    target?: string | null;
    context?: Record<string, unknown>;
  } = {},
): Promise<{ decision: DecideResponse; user: StackAuthUser }> {
  const verifier = opts.verifySession ?? ((tok: string) => defaultVerifier(tok, opts));
  const user = await verifier(token);
  if (!user?.id) {
    throw new Error("stack-auth: verifier returned no user.id");
  }
  const tf =
    opts.client ??
    new TrustForge({ daemonUrl: opts.daemonUrl, adminToken: opts.adminToken });
  const decision = await tf.decide({
    actor: null,
    host_token: token,
    host_token_kind: "stack-auth",
    action: ctx.action ?? opts.defaultAction ?? "http.request",
    target: ctx.target ?? null,
    context: {
      user_id: user.id,
      ...(user.primaryEmail ? { email: user.primaryEmail } : {}),
      ...(ctx.context ?? {}),
    },
    trace_id: newTraceId(),
  });
  return { decision, user };
}

interface ExpressLikeReq {
  headers: Record<string, string | string[] | undefined>;
  cookies?: Record<string, string>;
  url?: string;
  originalUrl?: string;
  method?: string;
  tfActor?: string;
  tfDecision?: DecideResponse;
  tfProofId?: string;
  tfStackAuthUserId?: string;
}
interface ExpressLikeRes {
  status: (code: number) => ExpressLikeRes;
  json: (body: unknown) => ExpressLikeRes;
  setHeader: (name: string, value: string) => void;
}
type NextFn = (err?: unknown) => void;

function readToken(req: ExpressLikeReq, cookieName: string): string | undefined {
  if (req.cookies?.[cookieName]) return req.cookies[cookieName];
  const cookie = (req.headers["cookie"] as string | undefined) ?? "";
  for (const part of cookie.split(/;\s*/)) {
    const [name, ...rest] = part.split("=");
    if (name === cookieName && rest.length > 0) {
      return rest.join("=");
    }
  }
  const auth = (req.headers["authorization"] as string | undefined) ?? "";
  if (auth.toLowerCase().startsWith("bearer ")) return auth.slice(7).trim();
  return undefined;
}

export function trustforgeStackAuth(opts: TfStackAuthOptions) {
  const mode = opts.mode ?? "enforce";
  const cookieName = opts.cookieName ?? "stack-access";
  return async function trustforgeStackAuthMw(
    req: ExpressLikeReq,
    res: ExpressLikeRes,
    next: NextFn,
  ): Promise<void> {
    const token = readToken(req, cookieName);
    if (!token) {
      if (mode === "observe-only") return next();
      res.status(401).json({ error: "missing-stack-auth-token" });
      return;
    }
    let outcome: { decision: DecideResponse; user: StackAuthUser };
    try {
      outcome = await decideForStackAuthToken(token, opts, {
        target: req.originalUrl ?? req.url ?? null,
        context: { method: req.method },
      });
    } catch (err) {
      if (mode === "observe-only") return next();
      res.status(401).json({
        error: "stack-auth-verify-failed",
        detail: (err as Error).message,
      });
      return;
    }
    req.tfActor = outcome.decision.actor_resolved;
    req.tfDecision = outcome.decision;
    req.tfProofId = outcome.decision.proof_id;
    req.tfStackAuthUserId = outcome.user.id;
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
