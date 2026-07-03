/**
 * @trustforge-protocol/koa — Koa 2/3 middleware that gates every incoming request
 * through tf-daemon /v1/decide.
 *
 * Usage:
 *   import Koa from "koa";
 *   import { trustforge } from "@trustforge-protocol/koa";
 *
 *   const app = new Koa();
 *   app.use(trustforge({ daemonUrl: "http://127.0.0.1:7616" }));
 *   app.use(async (ctx) => {
 *     ctx.body = { ok: true, actor: ctx.state.tfDecision?.actor_resolved };
 *   });
 */
import {
  TrustForge,
  type AdapterMode,
  type DecideResponse,
  type HostTokenKind,
} from "@trustforge-protocol/sdk";

// We type Koa structurally so the package can be installed without `koa`
// present at type-check time.
export interface KoaContextLike {
  request: { headers?: Record<string, string | string[] | undefined> };
  req?: { headers?: Record<string, string | string[] | undefined> };
  method: string;
  url: string;
  originalUrl?: string;
  ip?: string;
  state: Record<string, unknown> & {
    tfActor?: string;
    tfDecision?: DecideResponse;
    tfProofId?: string;
  };
  status: number;
  body: unknown;
  set: (field: string, value: string) => void;
  get: (field: string) => string;
}

export type KoaMiddleware = (
  ctx: KoaContextLike,
  next: () => Promise<unknown>,
) => Promise<void>;

export interface TfKoaOptions {
  daemonUrl: string;
  adminToken?: string;
  profile?: string;
  mode?: AdapterMode;
  defaultAction?: string;
  extractHostToken?: (ctx: KoaContextLike) => {
    token?: string;
    kind?: HostTokenKind;
  };
  client?: TrustForge;
}

function defaultExtractHostToken(ctx: KoaContextLike): {
  token?: string;
  kind?: HostTokenKind;
} {
  const headers =
    ctx.request.headers ?? ctx.req?.headers ?? {};
  const auth = (headers["authorization"] as string | undefined) ?? "";
  if (auth.toLowerCase().startsWith("bearer ")) {
    return { token: auth.slice(7).trim(), kind: "auto" };
  }
  const cookie = (headers["cookie"] as string | undefined) ?? "";
  for (const part of cookie.split(/;\s*/)) {
    const [name, ...rest] = part.split("=");
    const value = rest.join("=");
    if (!name || !value) continue;
    if (name === "__session" || name === "next-auth.session-token") {
      return { token: value, kind: "auto" };
    }
  }
  return {};
}

function newTraceId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `tf-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

interface ResolvedConfig {
  client: TrustForge;
  mode: AdapterMode;
  profile?: string;
  defaultAction: string;
  extract: (ctx: KoaContextLike) => { token?: string; kind?: HostTokenKind };
}

function resolveConfig(opts: TfKoaOptions): ResolvedConfig {
  return {
    client:
      opts.client ??
      new TrustForge({
        daemonUrl: opts.daemonUrl,
        adminToken: opts.adminToken,
      }),
    mode: opts.mode ?? "enforce",
    profile: opts.profile,
    defaultAction: opts.defaultAction ?? "http.request",
    extract: opts.extractHostToken ?? defaultExtractHostToken,
  };
}

/**
 * Koa middleware factory. On allow, the resolved decision is attached to
 * `ctx.state.tfDecision` (and `ctx.state.tfActor`, `ctx.state.tfProofId`).
 */
export function trustforge(opts: TfKoaOptions): KoaMiddleware {
  const cfg = resolveConfig(opts);
  return makeMiddleware(cfg);
}

function makeMiddleware(cfg: ResolvedConfig): KoaMiddleware {
  return async function trustforgeKoa(ctx, next) {
    const { token, kind } = cfg.extract(ctx);
    const trace_id = newTraceId();

    let decision: DecideResponse;
    try {
      decision = await cfg.client.decide({
        actor: null,
        host_token: token,
        host_token_kind: kind ?? "auto",
        action: cfg.defaultAction,
        target: ctx.originalUrl ?? ctx.url,
        context: {
          method: ctx.method,
          ...(ctx.ip ? { ip: ctx.ip } : {}),
          ...(cfg.profile ? { profile: cfg.profile } : {}),
        },
        trace_id,
      });
    } catch (err) {
      if (cfg.mode === "observe-only") {
        await next();
        return;
      }
      ctx.status = 502;
      ctx.body = {
        error: "tf-daemon unreachable",
        detail: (err as Error).message,
      };
      return;
    }

    ctx.state.tfActor = decision.actor_resolved;
    ctx.state.tfDecision = decision;
    ctx.state.tfProofId = decision.proof_id;
    ctx.set("x-tf-proof-id", decision.proof_id);

    if (cfg.mode === "observe-only") {
      await next();
      return;
    }

    switch (decision.decision) {
      case "allow":
      case "log-only":
        await next();
        return;
      case "deny":
      case "escalate":
        ctx.status = 403;
        ctx.body = {
          error: "forbidden",
          decision: decision.decision,
          reason: decision.reason,
          proof_id: decision.proof_id,
          danger_tags: decision.danger_tags,
        };
        return;
      case "approval-required":
        ctx.status = 202;
        if (decision.approval_id) {
          ctx.set("location", `/approvals/${decision.approval_id}`);
        }
        ctx.body = {
          decision: "approval-required",
          approval_id: decision.approval_id,
          reason: decision.reason,
          proof_id: decision.proof_id,
        };
        return;
      default:
        ctx.status = 500;
        ctx.body = {
          error: "unknown-decision",
          decision: decision.decision,
        };
    }
  };
}

/**
 * Per-route action-pinned guard. Attach before the global `trustforge`
 * middleware to override the default action for this route.
 */
export function tfRequire(action: string, opts: TfKoaOptions): KoaMiddleware {
  return makeMiddleware({ ...resolveConfig(opts), defaultAction: action });
}

export type { DecideResponse } from "@trustforge-protocol/sdk";
