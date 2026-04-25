/**
 * Mock tf-daemon for TS adapter tests.
 *
 * Boots a Bun.serve instance that:
 *  - exposes POST /v1/decide
 *  - exposes POST /v1/credentials/import (echo)
 *  - exposes POST /v1/proofs/sign (deterministic fake)
 *  - exposes POST /v1/proofs/verify (deterministic fake)
 *  - validates `Authorization: Bearer <adminToken>` when one is configured.
 *
 * Adapters can supply a `decide` callback to override the default
 * "allow everything" behaviour to test deny / approval-required / log-only
 * paths without standing up a real daemon.
 */

export interface DecideRequestBody {
  actor: string | null;
  host_token?: string;
  host_token_kind?: string;
  action: string;
  target: string | null;
  context: Record<string, unknown>;
  trace_id: string;
}

export interface DecideResponseBody {
  decision: "allow" | "deny" | "escalate" | "approval-required" | "log-only";
  reason: string;
  approval_id: string | null;
  proof_id: string;
  actor_resolved: string;
  trust_level: string;
  authority_mode: string;
  danger_tags: string[];
}

export interface MockDaemonOptions {
  /** Optional admin token. When set, requests must send `Authorization: Bearer <token>`. */
  adminToken?: string;
  /** Override decide behaviour. Default: allow everything. */
  decide?: (req: DecideRequestBody) => DecideResponseBody | Promise<DecideResponseBody>;
  /** Spy callback invoked on every /v1/decide request before the response is computed. */
  onDecide?: (req: DecideRequestBody) => void;
}

export interface MockDaemonHandle {
  url: string;
  port: number;
  /** Number of /v1/decide calls received. */
  callCount(): number;
  /** Captured request bodies in order of arrival. */
  calls(): DecideRequestBody[];
  stop(): Promise<void>;
}

export function defaultAllow(req: DecideRequestBody): DecideResponseBody {
  return {
    decision: "allow",
    reason: "mock-daemon: default allow",
    approval_id: null,
    proof_id: `sha256:mock-${req.trace_id}`,
    actor_resolved: req.actor ?? "tf:actor:agent:mock.example/host",
    trust_level: "T2",
    authority_mode: "layered",
    danger_tags: [],
  };
}

export function startMockDaemon(opts: MockDaemonOptions = {}): MockDaemonHandle {
  const decide = opts.decide ?? defaultAllow;
  const calls: DecideRequestBody[] = [];

  const server = Bun.serve({
    port: 0, // ephemeral
    hostname: "127.0.0.1",
    async fetch(req) {
      // Auth check (optional)
      if (opts.adminToken) {
        const auth = req.headers.get("authorization") ?? "";
        if (auth !== `Bearer ${opts.adminToken}`) {
          return new Response(JSON.stringify({ error: "unauthorized" }), {
            status: 401,
            headers: { "content-type": "application/json" },
          });
        }
      }

      const url = new URL(req.url);
      if (url.pathname === "/v1/decide" && req.method === "POST") {
        const body = (await req.json()) as DecideRequestBody;
        calls.push(body);
        opts.onDecide?.(body);
        const resp = await decide(body);
        return new Response(JSON.stringify(resp), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      if (url.pathname === "/v1/credentials/import" && req.method === "POST") {
        const body = (await req.json()) as Record<string, unknown>;
        return new Response(
          JSON.stringify({
            actor: body.actor ?? "tf:actor:agent:mock.example/imported",
            credential_id: "cred-mock-1",
            trust_level: "T2",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      if (url.pathname === "/v1/proofs/sign" && req.method === "POST") {
        const body = (await req.json()) as Record<string, unknown>;
        const traceId = (body.trace_id as string | undefined) ?? "no-trace";
        return new Response(
          JSON.stringify({
            event_hash: `sha256:fake-${traceId}`,
            signature: `ed25519:fake-sig-${traceId}`,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      if (url.pathname === "/v1/proofs/verify" && req.method === "POST") {
        const body = (await req.json()) as Record<string, unknown>;
        const ev = body.event as Record<string, unknown> | undefined;
        const sig = body.signature as string | undefined;
        const ok = typeof sig === "string" && sig.startsWith("ed25519:");
        return new Response(
          JSON.stringify({
            ok,
            signer_actor: (ev?.actor as string | undefined) ?? "tf:actor:unknown",
            trust_level: ok ? "T2" : "T0",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      return new Response("not found", { status: 404 });
    },
  });

  const port = server.port;
  return {
    url: `http://127.0.0.1:${port}`,
    port,
    callCount: () => calls.length,
    calls: () => calls.slice(),
    async stop() {
      await server.stop(true);
    },
  };
}
