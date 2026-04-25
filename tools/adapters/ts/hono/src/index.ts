/**
 * @trustforge/hono — Hono middleware that gates every request via
 * tf-daemon /v1/decide.
 *
 * Usage:
 *   import { Hono } from "hono";
 *   import { trustforgeMiddleware, tfRequire } from "@trustforge/hono";
 *
 *   const app = new Hono();
 *   app.use("*", trustforgeMiddleware({ daemonUrl: "..." }));
 *   app.post("/charge", tfRequire("billing.charge"), (c) => c.json({ ok: true }));
 */

import type { Context, MiddlewareHandler } from "hono";
import {
  TrustForge,
  type AdapterMode,
  type DecideResponse,
  type HostTokenKind,
} from "@trustforge/sdk";

export interface TfHonoOptions {
  daemonUrl: string;
  adminToken?: string;
  profile?: string;
  mode?: AdapterMode;
  defaultAction?: string;
  extractHostToken?: (c: Context) => {
    token?: string;
    kind?: HostTokenKind;
  };
  client?: TrustForge;
}

function defaultExtractHostToken(c: Context): {
  token?: string;
  kind?: HostTokenKind;
} {
  const auth = c.req.header("authorization") ?? "";
  if (auth.toLowerCase().startsWith("bearer ")) {
    return { token: auth.slice(7).trim(), kind: "auto" };
  }
  const cookie = c.req.header("cookie") ?? "";
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
  extract: (c: Context) => { token?: string; kind?: HostTokenKind };
}

function resolveConfig(opts: TfHonoOptions): ResolvedConfig {
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

function makeMiddleware(cfg: ResolvedConfig): MiddlewareHandler {
  const { client, mode, profile, defaultAction, extract } = cfg;
  return async function trustforgeMiddleware(c, next) {
    const { token, kind } = extract(c);
    const trace_id = newTraceId();
    let decision: DecideResponse;
    try {
      decision = await client.decide({
        actor: null,
        host_token: token,
        host_token_kind: kind ?? "auto",
        action: defaultAction,
        target: c.req.url,
        context: {
          method: c.req.method,
          ...(profile ? { profile } : {}),
        },
        trace_id,
      });
    } catch (err) {
      if (mode === "observe-only") {
        await next();
        return;
      }
      return c.json(
        {
          error: "tf-daemon unreachable",
          detail: (err as Error).message,
        },
        502,
      );
    }

    c.set("tfActor", decision.actor_resolved);
    c.set("tfDecision", decision);
    c.set("tfProofId", decision.proof_id);
    c.header("x-tf-proof-id", decision.proof_id);

    if (mode === "observe-only") {
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
        return c.json(
          {
            error: "forbidden",
            decision: decision.decision,
            reason: decision.reason,
            proof_id: decision.proof_id,
            danger_tags: decision.danger_tags,
          },
          403,
        );
      case "approval-required": {
        if (decision.approval_id) {
          c.header("location", `/approvals/${decision.approval_id}`);
        }
        return c.json(
          {
            decision: "approval-required",
            approval_id: decision.approval_id,
            reason: decision.reason,
            proof_id: decision.proof_id,
          },
          202,
        );
      }
      default:
        return c.json(
          {
            error: "unknown-decision",
            decision: decision.decision,
          },
          500,
        );
    }
  };
}

export function trustforgeMiddleware(opts: TfHonoOptions): MiddlewareHandler {
  return makeMiddleware(resolveConfig(opts));
}

/** Per-route action-pinned guard. Pass the same opts you'd pass to
 *  `trustforgeMiddleware()` (or omit them and rely on a previously-mounted
 *  global middleware to handle gating). */
export function tfRequire(
  action: string,
  opts?: TfHonoOptions,
): MiddlewareHandler {
  if (opts) {
    return makeMiddleware({ ...resolveConfig(opts), defaultAction: action });
  }
  // No opts — assume a global middleware is already mounted; this guard
  // simply records the pinned action for downstream handlers.
  return async function tfRequireMarker(c, next) {
    c.set("tfRequiredAction", action);
    await next();
  };
}

export type { DecideResponse } from "@trustforge/sdk";
