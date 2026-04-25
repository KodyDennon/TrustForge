/**
 * @trustforge/express — Express 4/5 middleware that gates every incoming
 * request through tf-daemon's /v1/decide endpoint.
 *
 * Usage:
 *   import express from "express";
 *   import { tfExpress, tfRequire } from "@trustforge/express";
 *
 *   const app = express();
 *   app.use(tfExpress({ daemonUrl: "http://127.0.0.1:7616", mode: "enforce" }));
 *   app.post("/billing/charge", tfRequire("billing.charge"), handler);
 */

import type { NextFunction, Request, RequestHandler, Response } from "express";
import {
  TrustForge,
  type AdapterMode,
  type DecideResponse,
  type HostTokenKind,
} from "@trustforge/sdk";

declare module "express-serve-static-core" {
  interface Request {
    tfActor?: string;
    tfDecision?: DecideResponse;
    tfProofId?: string;
  }
}

export interface TfExpressOptions {
  daemonUrl: string;
  adminToken?: string;
  /** Deployment profile name forwarded as context. */
  profile?: string;
  /** `enforce` blocks deny/approval; `observe-only` always forwards. */
  mode?: AdapterMode;
  /** Default action used when a route doesn't pin one via tfRequire(). */
  defaultAction?: string;
  /** Override host-token extraction. Default: Authorization Bearer + cookies. */
  extractHostToken?: (req: Request) => {
    token?: string;
    kind?: HostTokenKind;
  };
  /** Override the SDK instance (mostly for tests). */
  client?: TrustForge;
}

const DEFAULT_ACTION_HEADER = "x-tf-action";

/** Best-effort host-token extractor: Authorization: Bearer first, then session cookies. */
function defaultExtractHostToken(req: Request): {
  token?: string;
  kind?: HostTokenKind;
} {
  const auth = (req.headers["authorization"] as string | undefined) ?? "";
  if (auth.toLowerCase().startsWith("bearer ")) {
    return { token: auth.slice(7).trim(), kind: "auto" };
  }
  // Cookie-based session sniffing.
  const cookie = (req.headers["cookie"] as string | undefined) ?? "";
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

/** Per-request unique trace id (RFC4122-ish, OK for adapter tracing). */
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
  extract: (req: Request) => { token?: string; kind?: HostTokenKind };
}

function resolveConfig(opts: TfExpressOptions): ResolvedConfig {
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

/** Module-level default config registered by the most-recent tfExpress() call.
 *  Lets `tfRequire(action)` work without a per-call opts object. Apps that
 *  need multiple TrustForge clients should use `tfRequireWith(action, opts)`. */
let lastConfig: ResolvedConfig | undefined;

export function tfExpress(opts: TfExpressOptions): RequestHandler {
  const cfg = resolveConfig(opts);
  lastConfig = cfg;
  return makeHandler(cfg);
}

function makeHandler(cfg: ResolvedConfig): RequestHandler {
  const { client, mode, profile, defaultAction, extract } = cfg;
  return async function trustforgeMiddlewareInner(
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> {
    // Allow tfRequire() to override the action via res.locals before the
    // outer middleware fires. In normal Express ordering, tfRequire is a
    // route handler so this middleware runs first; route handlers re-check.
    const action =
      ((res.locals as Record<string, unknown>).tfAction as string | undefined) ??
      (req.headers[DEFAULT_ACTION_HEADER] as string | undefined) ??
      defaultAction;
    const { token, kind } = extract(req);
    const trace_id = newTraceId();

    let decision: DecideResponse;
    try {
      decision = await client.decide({
        actor: null,
        host_token: token,
        host_token_kind: kind ?? "auto",
        action,
        target: req.originalUrl ?? req.url,
        context: {
          method: req.method,
          ip: req.ip,
          ...(profile ? { profile } : {}),
        },
        trace_id,
      });
    } catch (err) {
      if (mode === "observe-only") {
        next();
        return;
      }
      res.status(502).json({
        error: "tf-daemon unreachable",
        detail: (err as Error).message,
      });
      return;
    }

    req.tfActor = decision.actor_resolved;
    req.tfDecision = decision;
    req.tfProofId = decision.proof_id;
    res.setHeader("x-tf-proof-id", decision.proof_id);

    if (mode === "observe-only") {
      next();
      return;
    }

    switch (decision.decision) {
      case "allow":
      case "log-only":
        next();
        return;
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
  };
}

/** Route guard. Performs a per-route /v1/decide call pinned to a specific
 *  action name. Requires that `tfExpress({...})` was previously mounted
 *  on the same app (it stashes the resolved config on `app.locals.tfConfig`).
 *
 *  Usage:
 *    app.use(tfExpress({ daemonUrl, adminToken, mode }));
 *    app.post("/charge", tfRequire("billing.charge"), handler);
 *
 *  When mounted as a route-level guard *before* the global tfExpress fires,
 *  the guard performs its own action-pinned decide call and short-circuits
 *  the same way the global middleware does. The global middleware then
 *  sees `req.tfDecision` already set and forwards without re-deciding. */
export function tfRequire(action: string): RequestHandler {
  return async function tfRequireMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> {
    if (req.tfDecision) {
      next();
      return;
    }
    if (!lastConfig) {
      res.status(500).json({
        error: "tf-config-missing",
        detail:
          "tfRequire() called but tfExpress() has not been initialised. Call tfExpress({...}) once before defining routes.",
      });
      return;
    }
    const pinned = makeHandler({ ...lastConfig, defaultAction: action });
    return pinned(req, res, next);
  };
}

/** Variant that takes its own opts (multi-app deployments). */
export function tfRequireWith(
  action: string,
  opts: TfExpressOptions,
): RequestHandler {
  return makeHandler({ ...resolveConfig(opts), defaultAction: action });
}

export type { DecideResponse } from "@trustforge/sdk";
