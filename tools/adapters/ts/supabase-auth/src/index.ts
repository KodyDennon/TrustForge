/**
 * @trustforge-protocol/supabase-auth — verifies a Supabase access token via the
 * Supabase admin JS client (loaded dynamically) and projects the resolved
 * user id into a TrustForge decide call with `host_token_kind: "supabase-jwt"`.
 *
 * Usage (Express):
 *   import { trustforgeSupabase } from "@trustforge-protocol/supabase-auth";
 *   app.use(trustforgeSupabase({
 *     daemonUrl: "...",
 *     supabaseUrl: process.env.SUPABASE_URL!,
 *     serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY!,
 *   }));
 *
 * The supabase-js dependency is loaded via `await import(...)` only when the
 * built-in verifier runs; tests can inject a `verifyAccessToken` callback to
 * skip the real client entirely.
 */
import {
  TrustForge,
  type AdapterMode,
  type DecideResponse,
} from "@trustforge-protocol/sdk";

export interface SupabaseUser {
  id: string;
  email?: string;
  [k: string]: unknown;
}

export type SupabaseVerifier = (accessToken: string) => Promise<SupabaseUser>;

export interface TfSupabaseOptions {
  daemonUrl: string;
  adminToken?: string;
  /** Supabase project URL (e.g. https://xyz.supabase.co). */
  supabaseUrl?: string;
  /** Service-role key (server-side only). */
  serviceRoleKey?: string;
  /** Optional verifier override (used by tests). */
  verifyAccessToken?: SupabaseVerifier;
  client?: TrustForge;
  mode?: AdapterMode;
  defaultAction?: string;
}

interface SupabaseClientLike {
  auth: {
    getUser: (
      jwt: string,
    ) => Promise<{
      data: { user: SupabaseUser | null };
      error: { message: string } | null;
    }>;
  };
}

let cachedClient: SupabaseClientLike | null = null;

async function defaultVerifier(
  token: string,
  url: string | undefined,
  key: string | undefined,
): Promise<SupabaseUser> {
  if (!url || !key) {
    throw new Error(
      "supabase-auth: supabaseUrl and serviceRoleKey are required when no verifyAccessToken is provided",
    );
  }
  if (!cachedClient) {
    const moduleName = "@supabase/supabase-js";
    const mod: unknown = await import(/* @vite-ignore */ moduleName);
    const createClient = (mod as { createClient: (u: string, k: string) => SupabaseClientLike })
      .createClient;
    cachedClient = createClient(url, key);
  }
  const { data, error } = await cachedClient.auth.getUser(token);
  if (error) throw new Error(`supabase-auth: ${error.message}`);
  if (!data.user) throw new Error("supabase-auth: no user returned");
  return data.user;
}

function newTraceId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `tf-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

export async function decideForSupabaseToken(
  accessToken: string,
  opts: TfSupabaseOptions,
  ctx: {
    action?: string;
    target?: string | null;
    context?: Record<string, unknown>;
  } = {},
): Promise<{ decision: DecideResponse; user: SupabaseUser }> {
  const verifier =
    opts.verifyAccessToken ??
    ((tok: string) =>
      defaultVerifier(tok, opts.supabaseUrl, opts.serviceRoleKey));
  const user = await verifier(accessToken);
  if (!user?.id) {
    throw new Error("supabase-auth: verifier returned no user.id");
  }
  const tf =
    opts.client ??
    new TrustForge({ daemonUrl: opts.daemonUrl, adminToken: opts.adminToken });
  const decision = await tf.decide({
    actor: null,
    host_token: accessToken,
    host_token_kind: "supabase-jwt",
    action: ctx.action ?? opts.defaultAction ?? "http.request",
    target: ctx.target ?? null,
    context: {
      user_id: user.id,
      ...(user.email ? { email: user.email } : {}),
      ...(ctx.context ?? {}),
    },
    trace_id: newTraceId(),
  });
  return { decision, user };
}

interface ExpressLikeReq {
  headers: Record<string, string | string[] | undefined>;
  url?: string;
  originalUrl?: string;
  method?: string;
  tfActor?: string;
  tfDecision?: DecideResponse;
  tfProofId?: string;
  tfSupabaseUserId?: string;
}
interface ExpressLikeRes {
  status: (code: number) => ExpressLikeRes;
  json: (body: unknown) => ExpressLikeRes;
  setHeader: (name: string, value: string) => void;
}
type NextFn = (err?: unknown) => void;

export function trustforgeSupabase(opts: TfSupabaseOptions) {
  const mode = opts.mode ?? "enforce";
  return async function trustforgeSupabaseMw(
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
    let outcome: { decision: DecideResponse; user: SupabaseUser };
    try {
      outcome = await decideForSupabaseToken(token, opts, {
        target: req.originalUrl ?? req.url ?? null,
        context: { method: req.method },
      });
    } catch (err) {
      if (mode === "observe-only") return next();
      res.status(401).json({
        error: "supabase-verify-failed",
        detail: (err as Error).message,
      });
      return;
    }
    req.tfActor = outcome.decision.actor_resolved;
    req.tfDecision = outcome.decision;
    req.tfProofId = outcome.decision.proof_id;
    req.tfSupabaseUserId = outcome.user.id;
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
