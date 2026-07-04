// Shared helpers for the Next.js adapter's middleware + server entry points.
//
// Kept separate so it can be reused by both Edge and Node runtimes without
// pulling in any framework-specific types.

import type {
  TfAdapterOptions,
  TfDecideRequest,
  TfDecision,
  TfHostTokenKind,
  TfRequestLike,
  TrustForgeLike,
} from "./types.ts";

/**
 * Lazy SDK loader. We import dynamically so the adapter is usable even if the
 * SDK isn't installed during a partial workspace setup. When the SDK ships,
 * the import succeeds and we get the real `TrustForge` class.
 */
async function importSdk(): Promise<{
  TrustForge: new (config: {
    daemonUrl?: string;
    adminToken?: string;
  }) => TrustForgeLike;
}> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mod: any = await import("@trustforge-protocol/sdk").catch(() => null);
  if (!mod || !mod.TrustForge) {
    throw new Error(
      "@trustforge-protocol/next: @trustforge-protocol/sdk is not installed. " +
        "Either install it or pass `tf:` to the adapter options.",
    );
  }
  return mod;
}

/**
 * Resolve which `TrustForgeLike` instance to use. If the caller passed `tf`,
 * use it; otherwise lazily instantiate the real SDK.
 */
export async function getClient(opts: TfAdapterOptions): Promise<TrustForgeLike> {
  if (opts.tf) return opts.tf;
  const { TrustForge } = await importSdk();
  return new TrustForge({
    daemonUrl: opts.daemonUrl,
    adminToken: opts.adminToken,
  });
}

/** Default extractor — covers the host_token kinds the daemon recognizes. */
export function defaultResolveCredential(req: TfRequestLike): {
  host_token: string | null;
  host_token_kind: TfHostTokenKind | null;
} {
  // Authorization: Bearer ...
  const auth = req.headers.get("authorization");
  if (auth && auth.toLowerCase().startsWith("bearer ")) {
    const token = auth.slice(7).trim();
    if (token.startsWith("eyJ")) {
      return { host_token: token, host_token_kind: "oauth-jwt" };
    }
    if (token.length > 0) {
      return { host_token: token, host_token_kind: "oauth-jwt" };
    }
  }

  // Cookie-based credentials. NextRequest exposes `.cookies.get`; raw fetch
  // Requests give us the `cookie` header. Try both.
  const tryCookie = (
    name: string,
  ): string | undefined => {
    const v = req.cookies?.get(name)?.value;
    if (v) return v;
    const raw = req.headers.get("cookie");
    if (!raw) return undefined;
    for (const part of raw.split(";")) {
      const [k, ...rest] = part.trim().split("=");
      if (k === name) return rest.join("=");
    }
    return undefined;
  };

  const nextAuth = tryCookie("__Secure-next-auth.session-token") ??
    tryCookie("next-auth.session-token");
  if (nextAuth) {
    return { host_token: nextAuth, host_token_kind: "next-auth-jwt" };
  }

  // Generic prefix-based detection on common cookie names.
  for (const name of ["session", "auth", "@trustforge-protocol/session"]) {
    const v = tryCookie(name);
    if (!v) continue;
    if (v.startsWith("sess_")) {
      return { host_token: v, host_token_kind: "clerk-session" };
    }
    if (v.startsWith("auth_")) {
      return { host_token: v, host_token_kind: "better-auth-session" };
    }
  }

  return { host_token: null, host_token_kind: null };
}

/** Default action resolver: `${method}.${first non-empty path segment}` lowercased + dotted. */
export function defaultResolveAction(req: TfRequestLike): string {
  const url = new URL(req.url, "http://localhost");
  const segs = url.pathname.split("/").filter(Boolean);
  const first = segs[0] ?? "root";
  return `${req.method.toLowerCase()}.${first.replace(/[^a-z0-9_]/gi, "_").toLowerCase()}`;
}

export function defaultResolveTraceId(): string {
  // crypto.randomUUID is universally available on Edge + Node 19+.
  return globalThis.crypto?.randomUUID?.() ?? `tf-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

/**
 * Build the canonical decide request envelope from an incoming HTTP request.
 * Consumers can override any field via the adapter options.
 */
export async function buildDecideRequest(
  req: TfRequestLike,
  opts: TfAdapterOptions,
): Promise<TfDecideRequest> {
  const cred = await (opts.resolveCredential ?? defaultResolveCredential)(req);
  const action = await (opts.resolveAction ?? defaultResolveAction)(req);
  const trace_id = (opts.resolveTraceId ?? defaultResolveTraceId)(req);
  const extraCtx = opts.resolveContext ? await opts.resolveContext(req) : {};

  const url = new URL(req.url, "http://localhost");
  const target = url.pathname + (url.search || "");

  return {
    actor: "actor" in cred ? cred.actor ?? null : null,
    host_token: cred.host_token ?? null,
    host_token_kind: cred.host_token_kind ?? null,
    action,
    target,
    context: {
      method: req.method,
      ...extraCtx,
    },
    trace_id,
  };
}

/**
 * Return a structured outcome the framework-specific code can translate into
 * its native response type.
 */
export interface TfOutcome {
  allowed: boolean;
  decision: TfDecision;
  /** HTTP status to use when `allowed === false` (403/202/etc). */
  status: number;
  /** JSON body to return when `allowed === false`. */
  body: Record<string, unknown>;
  /** Headers to set on the outgoing response (allow or deny). */
  headers: Record<string, string>;
}

export async function evaluateRequest(
  req: TfRequestLike,
  opts: TfAdapterOptions,
): Promise<TfOutcome> {
  const client = await getClient(opts);
  const decideReq = await buildDecideRequest(req, opts);
  const decision = await client.decide(decideReq);

  const headers: Record<string, string> = {
    "x-tf-decision": decision.decision,
    "x-tf-proof-id": decision.proof_id,
    "x-tf-actor": decision.actor_resolved,
    "x-tf-trust-level": decision.trust_level,
  };

  // observe-only: never block, just annotate.
  if (opts.mode === "observe-only") {
    return { allowed: true, decision, status: 200, body: {}, headers };
  }

  switch (decision.decision) {
    case "allow":
    case "log-only":
      return { allowed: true, decision, status: 200, body: {}, headers };
    case "approval-required":
      return {
        allowed: false,
        decision,
        status: 202,
        headers: {
          ...headers,
          location: `/tf/approval/${decision.approval_id ?? ""}`,
        },
        body: {
          decision: decision.decision,
          reason: decision.reason,
          approval_id: decision.approval_id,
        },
      };
    case "escalate":
      return {
        allowed: false,
        decision,
        status: 403,
        headers: {
          ...headers,
          "www-authenticate": 'TrustForge realm="escalate"',
        },
        body: {
          decision: decision.decision,
          reason: decision.reason,
          danger_tags: decision.danger_tags,
        },
      };
    case "deny":
    default:
      return {
        allowed: false,
        decision,
        status: 403,
        headers: {
          ...headers,
          "www-authenticate": 'TrustForge realm="deny"',
        },
        body: {
          decision: "deny",
          reason: decision.reason,
          danger_tags: decision.danger_tags,
        },
      };
  }
}
