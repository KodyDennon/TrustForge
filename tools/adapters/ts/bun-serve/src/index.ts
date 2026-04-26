/**
 * @trustforge/bun-serve — wraps a Bun.serve({ fetch }) handler so that every
 * request is gated through tf-daemon /v1/decide before the user handler runs.
 *
 * Usage:
 *   import { withTrustforge } from "@trustforge/bun-serve";
 *   Bun.serve({
 *     fetch: withTrustforge(async (req) => new Response("hi"), {
 *       daemonUrl: "http://127.0.0.1:7616",
 *     }),
 *   });
 *
 * The wrapper:
 *  - extracts a host token from `Authorization: Bearer ...` or session cookies,
 *  - calls /v1/decide,
 *  - on `allow` / `log-only` runs the user handler (with the resolved decision
 *    surfaced via the `tfRequestContext` WeakMap and `x-tf-proof-id` response
 *    header),
 *  - on `deny` / `escalate` returns a 403 JSON response,
 *  - on `approval-required` returns a 202 JSON response with a Location header,
 *  - on daemon failure either fails open (observe-only) or returns 502.
 */
import {
  TrustForge,
  type AdapterMode,
  type DecideResponse,
  type HostTokenKind,
} from "@trustforge/sdk";

export type BunFetchHandler = (
  request: Request,
  server?: unknown,
) => Response | Promise<Response>;

export interface TfBunServeOptions {
  daemonUrl: string;
  adminToken?: string;
  profile?: string;
  mode?: AdapterMode;
  defaultAction?: string;
  /** Override host-token extraction. Default: Authorization Bearer + session cookies. */
  extractHostToken?: (req: Request) => {
    token?: string;
    kind?: HostTokenKind;
  };
  /** Override the SDK instance (mostly for tests). */
  client?: TrustForge;
  /** Skip gating for paths that match this predicate. */
  skip?: (url: URL) => boolean;
}

/** Per-request decision surface, addressable from the user handler. */
export interface TfRequestDecision {
  actor: string;
  decision: DecideResponse;
  proofId: string;
}

const decisionMap = new WeakMap<Request, TfRequestDecision>();

/** Read the TrustForge decision recorded for a request inside the user handler. */
export function tfRequestContext(req: Request): TfRequestDecision | undefined {
  return decisionMap.get(req);
}

function defaultExtractHostToken(req: Request): {
  token?: string;
  kind?: HostTokenKind;
} {
  const auth = req.headers.get("authorization") ?? "";
  if (auth.toLowerCase().startsWith("bearer ")) {
    return { token: auth.slice(7).trim(), kind: "auto" };
  }
  const cookie = req.headers.get("cookie") ?? "";
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
  extract: (req: Request) => { token?: string; kind?: HostTokenKind };
  skip?: (url: URL) => boolean;
}

function resolveConfig(opts: TfBunServeOptions): ResolvedConfig {
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
    skip: opts.skip,
  };
}

/**
 * Wrap a Bun.serve fetch handler with TrustForge gating.
 */
export function withTrustforge(
  handler: BunFetchHandler,
  opts: TfBunServeOptions,
): BunFetchHandler {
  const cfg = resolveConfig(opts);
  return async function trustforgeFetch(req, server) {
    const url = new URL(req.url);
    if (cfg.skip?.(url)) {
      return handler(req, server);
    }

    const { token, kind } = cfg.extract(req);
    const trace_id = newTraceId();

    let decision: DecideResponse;
    try {
      decision = await cfg.client.decide({
        actor: null,
        host_token: token,
        host_token_kind: kind ?? "auto",
        action: cfg.defaultAction,
        target: url.pathname + url.search,
        context: {
          method: req.method,
          ...(cfg.profile ? { profile: cfg.profile } : {}),
        },
        trace_id,
      });
    } catch (err) {
      if (cfg.mode === "observe-only") {
        return handler(req, server);
      }
      return jsonResponse(
        {
          error: "tf-daemon unreachable",
          detail: (err as Error).message,
        },
        502,
      );
    }

    decisionMap.set(req, {
      actor: decision.actor_resolved,
      decision,
      proofId: decision.proof_id,
    });

    if (cfg.mode === "observe-only") {
      const res = await handler(req, server);
      return withProofHeader(res, decision.proof_id);
    }

    switch (decision.decision) {
      case "allow":
      case "log-only": {
        const res = await handler(req, server);
        return withProofHeader(res, decision.proof_id);
      }
      case "deny":
      case "escalate":
        return jsonResponse(
          {
            error: "forbidden",
            decision: decision.decision,
            reason: decision.reason,
            proof_id: decision.proof_id,
            danger_tags: decision.danger_tags,
          },
          403,
          { "x-tf-proof-id": decision.proof_id },
        );
      case "approval-required":
        return jsonResponse(
          {
            decision: "approval-required",
            approval_id: decision.approval_id,
            reason: decision.reason,
            proof_id: decision.proof_id,
          },
          202,
          {
            "x-tf-proof-id": decision.proof_id,
            ...(decision.approval_id
              ? { location: `/approvals/${decision.approval_id}` }
              : {}),
          },
        );
      default:
        return jsonResponse(
          {
            error: "unknown-decision",
            decision: decision.decision,
          },
          500,
        );
    }
  };
}

function jsonResponse(
  body: unknown,
  status: number,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      ...extraHeaders,
    },
  });
}

function withProofHeader(res: Response, proofId: string): Response {
  // Mutate headers if possible; otherwise clone the response.
  try {
    res.headers.set("x-tf-proof-id", proofId);
    return res;
  } catch {
    const headers = new Headers(res.headers);
    headers.set("x-tf-proof-id", proofId);
    return new Response(res.body, {
      status: res.status,
      statusText: res.statusText,
      headers,
    });
  }
}

export type { DecideResponse } from "@trustforge/sdk";
