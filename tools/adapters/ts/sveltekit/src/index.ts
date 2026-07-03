// SvelteKit `handle` hook adapter.
//
// Wires into `src/hooks.server.ts`:
//
//   import { trustforgeHandle } from "@trustforge-protocol/sveltekit";
//   export const handle = trustforgeHandle({ daemonUrl: "..." });
//
// Sets `event.locals.tfActor`, `event.locals.tfDecision` on allow.

import type {
  SvelteHandle,
  SvelteRequestEventLike,
  TfDecideRequest,
  TfDecision,
  TfHostTokenKind,
  TfSvelteOptions,
  TrustForgeLike,
} from "./types.ts";

async function importSdk(): Promise<{
  TrustForge: new (cfg: { daemonUrl?: string; adminToken?: string }) => TrustForgeLike;
}> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mod: any = await import("@trustforge-protocol/sdk").catch(() => null);
  if (!mod?.TrustForge) {
    throw new Error(
      "@trustforge-protocol/sveltekit: @trustforge-protocol/sdk is not installed. " +
        "Either install it or pass `tf:` to trustforgeHandle().",
    );
  }
  return mod;
}

async function getClient(opts: TfSvelteOptions): Promise<TrustForgeLike> {
  if (opts.tf) return opts.tf;
  const { TrustForge } = await importSdk();
  return new TrustForge({ daemonUrl: opts.daemonUrl, adminToken: opts.adminToken });
}

function defaultResolveAction(event: SvelteRequestEventLike): string {
  const segs = event.url.pathname.split("/").filter(Boolean);
  const first = segs[0] ?? "root";
  return `${event.request.method.toLowerCase()}.${first
    .replace(/[^a-z0-9_]/gi, "_")
    .toLowerCase()}`;
}

function defaultResolveCredential(event: SvelteRequestEventLike): {
  host_token: string | null;
  host_token_kind: TfHostTokenKind | null;
} {
  const auth = event.request.headers.get("authorization");
  if (auth?.toLowerCase().startsWith("bearer ")) {
    return { host_token: auth.slice(7).trim(), host_token_kind: "oauth-jwt" };
  }

  const nextAuth =
    event.cookies.get("__Secure-next-auth.session-token") ??
    event.cookies.get("next-auth.session-token");
  if (nextAuth) return { host_token: nextAuth, host_token_kind: "next-auth-jwt" };

  for (const name of ["session", "auth", "tf-session"]) {
    const v = event.cookies.get(name);
    if (!v) continue;
    if (v.startsWith("sess_")) return { host_token: v, host_token_kind: "clerk-session" };
    if (v.startsWith("auth_"))
      return { host_token: v, host_token_kind: "better-auth-session" };
  }

  return { host_token: null, host_token_kind: null };
}

function defaultResolveTraceId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `tf-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

async function buildDecideRequest(
  event: SvelteRequestEventLike,
  opts: TfSvelteOptions,
): Promise<TfDecideRequest> {
  const cred = await (opts.resolveCredential ?? defaultResolveCredential)(event);
  const action = await (opts.resolveAction ?? defaultResolveAction)(event);
  const trace_id = (opts.resolveTraceId ?? defaultResolveTraceId)(event);
  const extraCtx = opts.resolveContext ? await opts.resolveContext(event) : {};

  return {
    actor: "actor" in cred ? cred.actor ?? null : null,
    host_token: cred.host_token ?? null,
    host_token_kind: cred.host_token_kind ?? null,
    action,
    target: event.url.pathname + (event.url.search || ""),
    context: { method: event.request.method, ...extraCtx },
    trace_id,
  };
}

export function trustforgeHandle(opts: TfSvelteOptions = {}): SvelteHandle {
  return async function handle({ event, resolve }) {
    if (opts.skip?.(event.url.pathname)) return resolve(event);

    const client = await getClient(opts);
    const decideReq = await buildDecideRequest(event, opts);
    const decision = await client.decide(decideReq);

    // Always set locals so downstream handlers can read decision metadata.
    event.locals.tfActor = decision.actor_resolved;
    event.locals.tfDecision = decision;
    event.locals.tfProofId = decision.proof_id;

    if (opts.mode === "observe-only") {
      const res = await resolve(event);
      annotate(res, decision);
      return res;
    }

    if (decision.decision === "allow" || decision.decision === "log-only") {
      const res = await resolve(event);
      annotate(res, decision);
      return res;
    }

    if (decision.decision === "approval-required") {
      return new Response(
        JSON.stringify({
          decision: decision.decision,
          reason: decision.reason,
          approval_id: decision.approval_id,
        }),
        {
          status: 202,
          headers: {
            "content-type": "application/json",
            location: `/tf/approval/${decision.approval_id ?? ""}`,
            ...metadataHeaders(decision),
          },
        },
      );
    }

    // deny / escalate
    return new Response(
      JSON.stringify({
        decision: decision.decision,
        reason: decision.reason,
        danger_tags: decision.danger_tags,
      }),
      {
        status: 403,
        headers: {
          "content-type": "application/json",
          "www-authenticate": `TrustForge realm="${decision.decision}"`,
          ...metadataHeaders(decision),
        },
      },
    );
  };
}

function metadataHeaders(d: TfDecision): Record<string, string> {
  return {
    "x-tf-decision": d.decision,
    "x-tf-proof-id": d.proof_id,
    "x-tf-actor": d.actor_resolved,
    "x-tf-trust-level": d.trust_level,
  };
}

function annotate(res: Response, d: TfDecision): void {
  for (const [k, v] of Object.entries(metadataHeaders(d))) {
    if (!res.headers.has(k)) res.headers.set(k, v);
  }
}

export type {
  TfDecideRequest,
  TfDecision,
  TfDecisionVerdict,
  TfTrustLevel,
  TfAuthorityMode,
  TfHostTokenKind,
  TfMode,
  TrustForgeLike,
  TfSvelteOptions,
  SvelteHandle,
  SvelteRequestEventLike,
} from "./types.ts";

// Re-export under the canonical SvelteKit name so users can do
//   `export const handle: Handle = trustforgeHandle({...});`
// without importing types from this package.
