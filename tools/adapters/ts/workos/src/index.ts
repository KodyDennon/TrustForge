/**
 * @trustforge/workos — verifies a WorkOS session via `@workos-inc/node`
 * (loaded dynamically) and projects the resolved user id + access token into
 * a TrustForge decide call with `host_token_kind: "workos-jwt"`.
 *
 * Usage (Express):
 *   import { trustforgeWorkOS } from "@trustforge/workos";
 *   app.use(trustforgeWorkOS({
 *     daemonUrl: "...",
 *     workosApiKey: process.env.WORKOS_API_KEY!,
 *     workosClientId: process.env.WORKOS_CLIENT_ID!,
 *   }));
 *
 * The verifier reads the WorkOS sealed session cookie or `Authorization`
 * Bearer header, runs `userManagement.authenticateWithSessionCookie` (or its
 * equivalent), and returns the access token + user. Tests can inject a
 * `verifySession` callback.
 */
import {
  TrustForge,
  type AdapterMode,
  type DecideResponse,
} from "@trustforge/sdk";

export interface WorkOSUser {
  id: string;
  email?: string;
  [k: string]: unknown;
}

export interface WorkOSVerifierResult {
  accessToken: string;
  user: WorkOSUser;
}

export type WorkOSVerifier = (
  sealedOrAccessToken: string,
) => Promise<WorkOSVerifierResult>;

export interface TfWorkOSOptions {
  daemonUrl: string;
  adminToken?: string;
  /** WorkOS API key (sk_…). */
  workosApiKey?: string;
  /** WorkOS client id (client_…). */
  workosClientId?: string;
  /** Cookie password used to seal sessions (only required when using sealed cookies). */
  cookiePassword?: string;
  /** Tests / advanced callers: inject a verifier directly. */
  verifySession?: WorkOSVerifier;
  client?: TrustForge;
  mode?: AdapterMode;
  defaultAction?: string;
  /** Cookie name to read for the WorkOS sealed session. Default: `wos-session`. */
  cookieName?: string;
}

interface WorkOSClientLike {
  userManagement: {
    authenticateWithSessionCookie?: (args: {
      sessionData: string;
      cookiePassword?: string;
    }) => Promise<{ user: WorkOSUser; accessToken: string }>;
    loadSealedSession?: (args: {
      sessionData: string;
      cookiePassword: string;
    }) => Promise<{ authenticate: () => Promise<{ user: WorkOSUser; accessToken: string }> }>;
  };
}

let cachedClient: WorkOSClientLike | null = null;

async function defaultVerifier(
  token: string,
  opts: TfWorkOSOptions,
): Promise<WorkOSVerifierResult> {
  if (!opts.workosApiKey || !opts.cookiePassword) {
    throw new Error(
      "workos: workosApiKey and cookiePassword are required when no verifySession is provided",
    );
  }
  if (!cachedClient) {
    const moduleName = "@workos-inc/node";
    const mod: unknown = await import(/* @vite-ignore */ moduleName);
    const m = mod as {
      WorkOS?: new (key: string, opts?: { clientId?: string }) => WorkOSClientLike;
      default?: new (key: string, opts?: { clientId?: string }) => WorkOSClientLike;
    };
    const Ctor = m.WorkOS ?? m.default;
    if (!Ctor) throw new Error("workos: failed to load WorkOS constructor");
    cachedClient = new Ctor(opts.workosApiKey, { clientId: opts.workosClientId });
  }
  const um = cachedClient.userManagement;
  if (um.loadSealedSession) {
    const sess = await um.loadSealedSession({
      sessionData: token,
      cookiePassword: opts.cookiePassword,
    });
    return sess.authenticate();
  }
  if (um.authenticateWithSessionCookie) {
    return um.authenticateWithSessionCookie({
      sessionData: token,
      cookiePassword: opts.cookiePassword,
    });
  }
  throw new Error("workos: SDK is missing both loadSealedSession and authenticateWithSessionCookie");
}

function newTraceId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `tf-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

export async function decideForWorkOSToken(
  sessionToken: string,
  opts: TfWorkOSOptions,
  ctx: {
    action?: string;
    target?: string | null;
    context?: Record<string, unknown>;
  } = {},
): Promise<{ decision: DecideResponse; user: WorkOSUser; accessToken: string }> {
  const verifier =
    opts.verifySession ?? ((tok: string) => defaultVerifier(tok, opts));
  const result = await verifier(sessionToken);
  if (!result?.user?.id) {
    throw new Error("workos: verifier returned no user.id");
  }
  const tf =
    opts.client ??
    new TrustForge({ daemonUrl: opts.daemonUrl, adminToken: opts.adminToken });
  const decision = await tf.decide({
    actor: null,
    host_token: result.accessToken,
    host_token_kind: "workos-jwt",
    action: ctx.action ?? opts.defaultAction ?? "http.request",
    target: ctx.target ?? null,
    context: {
      user_id: result.user.id,
      ...(result.user.email ? { email: result.user.email } : {}),
      ...(ctx.context ?? {}),
    },
    trace_id: newTraceId(),
  });
  return { decision, user: result.user, accessToken: result.accessToken };
}

interface ExpressLikeReq {
  headers: Record<string, string | string[] | undefined>;
  url?: string;
  originalUrl?: string;
  method?: string;
  cookies?: Record<string, string>;
  tfActor?: string;
  tfDecision?: DecideResponse;
  tfProofId?: string;
  tfWorkOSUserId?: string;
}
interface ExpressLikeRes {
  status: (code: number) => ExpressLikeRes;
  json: (body: unknown) => ExpressLikeRes;
  setHeader: (name: string, value: string) => void;
}
type NextFn = (err?: unknown) => void;

function readSessionToken(
  req: ExpressLikeReq,
  cookieName: string,
): string | undefined {
  if (req.cookies?.[cookieName]) return req.cookies[cookieName];
  const cookie = (req.headers["cookie"] as string | undefined) ?? "";
  for (const part of cookie.split(/;\s*/)) {
    const [name, ...rest] = part.split("=");
    if (name === cookieName && rest.length > 0) {
      return rest.join("=");
    }
  }
  const auth = (req.headers["authorization"] as string | undefined) ?? "";
  if (auth.toLowerCase().startsWith("bearer ")) {
    return auth.slice(7).trim();
  }
  return undefined;
}

export function trustforgeWorkOS(opts: TfWorkOSOptions) {
  const mode = opts.mode ?? "enforce";
  const cookieName = opts.cookieName ?? "wos-session";
  return async function trustforgeWorkOSMw(
    req: ExpressLikeReq,
    res: ExpressLikeRes,
    next: NextFn,
  ): Promise<void> {
    const token = readSessionToken(req, cookieName);
    if (!token) {
      if (mode === "observe-only") return next();
      res.status(401).json({ error: "missing-workos-session" });
      return;
    }
    let outcome: { decision: DecideResponse; user: WorkOSUser };
    try {
      outcome = await decideForWorkOSToken(token, opts, {
        target: req.originalUrl ?? req.url ?? null,
        context: { method: req.method },
      });
    } catch (err) {
      if (mode === "observe-only") return next();
      res.status(401).json({
        error: "workos-verify-failed",
        detail: (err as Error).message,
      });
      return;
    }
    req.tfActor = outcome.decision.actor_resolved;
    req.tfDecision = outcome.decision;
    req.tfProofId = outcome.decision.proof_id;
    req.tfWorkOSUserId = outcome.user.id;
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
