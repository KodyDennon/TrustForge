/**
 * @trustforge/h3 — h3 / Nitro / Nuxt event handler middleware.
 *
 * Usage:
 *   import { createApp } from "h3";
 *   import { trustforgeHandler } from "@trustforge/h3";
 *
 *   const app = createApp();
 *   app.use(trustforgeHandler({ daemonUrl: "http://127.0.0.1:7616" }));
 *
 * Implementation note: h3 is loaded via dynamic import to keep the package
 * importable in environments where h3 isn't installed (mostly tests). The
 * resulting handler is a function that takes an h3 `H3Event`-shaped object.
 */
import {
  TrustForge,
  type AdapterMode,
  type DecideResponse,
  type HostTokenKind,
} from "@trustforge/sdk";

/** Subset of h3's H3Event we depend on, typed structurally. */
export interface H3EventLike {
  node?: {
    req?: {
      url?: string;
      method?: string;
      headers?: Record<string, string | string[] | undefined>;
      socket?: { remoteAddress?: string };
    };
    res?: {
      statusCode?: number;
      setHeader?: (name: string, value: string) => void;
    };
  };
  context: Record<string, unknown> & {
    tfActor?: string;
    tfDecision?: DecideResponse;
    tfProofId?: string;
  };
  path?: string;
  method?: string;
  /** When present, h3's `getRequestHeader` reads this. */
  headers?: Headers;
}

export type H3EventHandler = (
  event: H3EventLike,
) => Promise<unknown> | unknown;

export interface TfH3Options {
  daemonUrl: string;
  adminToken?: string;
  profile?: string;
  mode?: AdapterMode;
  defaultAction?: string;
  extractHostToken?: (event: H3EventLike) => {
    token?: string;
    kind?: HostTokenKind;
  };
  client?: TrustForge;
}

function getRequestHeader(
  event: H3EventLike,
  name: string,
): string | undefined {
  const lower = name.toLowerCase();
  // Web Headers (h3 v1.11+ also sets event.headers)
  if (event.headers && typeof event.headers.get === "function") {
    const v = event.headers.get(name);
    if (v != null) return v;
  }
  const nodeHeaders = event.node?.req?.headers;
  if (nodeHeaders) {
    const raw = nodeHeaders[lower];
    if (Array.isArray(raw)) return raw[0];
    if (typeof raw === "string") return raw;
  }
  return undefined;
}

function defaultExtractHostToken(event: H3EventLike): {
  token?: string;
  kind?: HostTokenKind;
} {
  const auth = getRequestHeader(event, "authorization") ?? "";
  if (auth.toLowerCase().startsWith("bearer ")) {
    return { token: auth.slice(7).trim(), kind: "auto" };
  }
  const cookie = getRequestHeader(event, "cookie") ?? "";
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
  extract: (event: H3EventLike) => {
    token?: string;
    kind?: HostTokenKind;
  };
}

function resolveConfig(opts: TfH3Options): ResolvedConfig {
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

/** Outcome surface for callers who want to drive the decision themselves. */
export interface TfH3Outcome {
  allowed: boolean;
  decision: DecideResponse | null;
  status: number;
  body?: unknown;
  proofId?: string;
  approvalLocation?: string;
}

/**
 * Core decision routine. Exposed for advanced callers and used by both the
 * h3 handler and tests (which don't always have h3 installed).
 */
export async function evaluateEvent(
  event: H3EventLike,
  opts: TfH3Options,
): Promise<TfH3Outcome> {
  const cfg = resolveConfig(opts);
  const { token, kind } = cfg.extract(event);
  const trace_id = newTraceId();
  const target = event.path ?? event.node?.req?.url ?? "/";
  const method = event.method ?? event.node?.req?.method ?? "GET";

  let decision: DecideResponse;
  try {
    decision = await cfg.client.decide({
      actor: null,
      host_token: token,
      host_token_kind: kind ?? "auto",
      action: cfg.defaultAction,
      target,
      context: {
        method,
        ...(cfg.profile ? { profile: cfg.profile } : {}),
      },
      trace_id,
    });
  } catch (err) {
    if (cfg.mode === "observe-only") {
      return { allowed: true, decision: null, status: 200 };
    }
    return {
      allowed: false,
      decision: null,
      status: 502,
      body: {
        error: "tf-daemon unreachable",
        detail: (err as Error).message,
      },
    };
  }

  event.context.tfActor = decision.actor_resolved;
  event.context.tfDecision = decision;
  event.context.tfProofId = decision.proof_id;
  event.node?.res?.setHeader?.("x-tf-proof-id", decision.proof_id);

  if (cfg.mode === "observe-only") {
    return { allowed: true, decision, status: 200, proofId: decision.proof_id };
  }

  switch (decision.decision) {
    case "allow":
    case "log-only":
      return {
        allowed: true,
        decision,
        status: 200,
        proofId: decision.proof_id,
      };
    case "deny":
    case "escalate":
      return {
        allowed: false,
        decision,
        status: 403,
        proofId: decision.proof_id,
        body: {
          error: "forbidden",
          decision: decision.decision,
          reason: decision.reason,
          proof_id: decision.proof_id,
          danger_tags: decision.danger_tags,
        },
      };
    case "approval-required":
      return {
        allowed: false,
        decision,
        status: 202,
        proofId: decision.proof_id,
        approvalLocation: decision.approval_id
          ? `/approvals/${decision.approval_id}`
          : undefined,
        body: {
          decision: "approval-required",
          approval_id: decision.approval_id,
          reason: decision.reason,
          proof_id: decision.proof_id,
        },
      };
    default:
      return {
        allowed: false,
        decision,
        status: 500,
        body: { error: "unknown-decision", decision: decision.decision },
      };
  }
}

/**
 * h3 event handler. Equivalent to `defineEventHandler` over the gating logic.
 *
 * In production, you should pass this to `app.use(...)`. The handler returns
 * `undefined` on allow (h3 then continues to subsequent handlers) and a JSON
 * body / status code on deny / approval-required.
 */
export function trustforgeHandler(opts: TfH3Options): H3EventHandler {
  return async function trustforgeH3(event) {
    const outcome = await evaluateEvent(event, opts);
    if (outcome.allowed) {
      return undefined;
    }
    if (event.node?.res) {
      event.node.res.statusCode = outcome.status;
      if (outcome.approvalLocation) {
        event.node.res.setHeader?.("location", outcome.approvalLocation);
      }
    }
    return outcome.body;
  };
}

/**
 * Async variant intended for h3's `defineEventHandler({ onRequest: [...] })`
 * — you can mount it as an onRequest hook and the body will only be set
 * when the decision is non-allow.
 */
export function tfRequire(
  action: string,
  opts: TfH3Options,
): H3EventHandler {
  return trustforgeHandler({ ...opts, defaultAction: action });
}

export type { DecideResponse } from "@trustforge/sdk";
