/**
 * @trustforge-protocol/fastify — Fastify 4/5 plugin that gates every request via
 * tf-daemon /v1/decide.
 *
 * Usage:
 *   import Fastify from "fastify";
 *   import { fastifyTrustForge } from "@trustforge-protocol/fastify";
 *
 *   const app = Fastify();
 *   await app.register(fastifyTrustForge, {
 *     daemonUrl: "http://127.0.0.1:7616",
 *     adminToken: process.env.TF_ADMIN_TOKEN,
 *     mode: "enforce",
 *   });
 *
 *   app.post("/charge", { preHandler: app.tfRequire("billing.charge") }, handler);
 */

import type {
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
  preHandlerHookHandler,
} from "fastify";
import fp from "fastify-plugin";
import {
  TrustForge,
  type AdapterMode,
  type DecideResponse,
  type HostTokenKind,
} from "@trustforge-protocol/sdk";

declare module "fastify" {
  interface FastifyRequest {
    tfActor?: string;
    tfDecision?: DecideResponse;
    tfProofId?: string;
  }
  interface FastifyInstance {
    tfRequire(action: string): preHandlerHookHandler;
  }
}

export interface TfFastifyOptions {
  daemonUrl: string;
  adminToken?: string;
  profile?: string;
  mode?: AdapterMode;
  defaultAction?: string;
  extractHostToken?: (req: FastifyRequest) => {
    token?: string;
    kind?: HostTokenKind;
  };
  client?: TrustForge;
}

function defaultExtractHostToken(req: FastifyRequest): {
  token?: string;
  kind?: HostTokenKind;
} {
  const auth =
    (req.headers["authorization"] as string | undefined) ?? "";
  if (auth.toLowerCase().startsWith("bearer ")) {
    return { token: auth.slice(7).trim(), kind: "auto" };
  }
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
  extract: (req: FastifyRequest) => { token?: string; kind?: HostTokenKind };
}

function resolveConfig(opts: TfFastifyOptions): ResolvedConfig {
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

function makeHook(cfg: ResolvedConfig): preHandlerHookHandler {
  const { client, mode, profile, defaultAction, extract } = cfg;
  return function tfPreHandler(
    req: FastifyRequest,
    reply: FastifyReply,
    done,
  ) {
    void (async () => {
      const { token, kind } = extract(req);
      const trace_id = newTraceId();
      let decision: DecideResponse;
      try {
        decision = await client.decide({
          actor: null,
          host_token: token,
          host_token_kind: kind ?? "auto",
          action: defaultAction,
          target: req.url,
          context: {
            method: req.method,
            ip: req.ip,
            ...(profile ? { profile } : {}),
          },
          trace_id,
        });
      } catch (err) {
        if (mode === "observe-only") {
          done();
          return;
        }
        reply.code(502).send({
          error: "tf-daemon unreachable",
          detail: (err as Error).message,
        });
        return;
      }

      req.tfActor = decision.actor_resolved;
      req.tfDecision = decision;
      req.tfProofId = decision.proof_id;
      reply.header("x-tf-proof-id", decision.proof_id);

      if (mode === "observe-only") {
        done();
        return;
      }

      switch (decision.decision) {
        case "allow":
        case "log-only":
          done();
          return;
        case "deny":
        case "escalate":
          reply.code(403).send({
            error: "forbidden",
            decision: decision.decision,
            reason: decision.reason,
            proof_id: decision.proof_id,
            danger_tags: decision.danger_tags,
          });
          return;
        case "approval-required":
          if (decision.approval_id) {
            reply.header("location", `/approvals/${decision.approval_id}`);
          }
          reply.code(202).send({
            decision: "approval-required",
            approval_id: decision.approval_id,
            reason: decision.reason,
            proof_id: decision.proof_id,
          });
          return;
        default:
          reply.code(500).send({
            error: "unknown-decision",
            decision: decision.decision,
          });
      }
    })().catch((err) => done(err));
  };
}

const trustforgePlugin: FastifyPluginAsync<
  TfFastifyOptions & { gateGlobally?: boolean }
> = async (fastify, opts) => {
  const cfg = resolveConfig(opts);
  // Default to gating every request. Set `gateGlobally: false` for
  // route-only gating via `fastify.tfRequire("action.name")`.
  const gateGlobally = opts.gateGlobally !== false;
  if (gateGlobally) {
    fastify.addHook("preHandler", makeHook(cfg));
  }
  fastify.decorate("tfRequire", (action: string) =>
    makeHook({ ...cfg, defaultAction: action }),
  );
};

export const fastifyTrustForge = fp(trustforgePlugin, {
  fastify: ">=4.0.0",
  name: "@trustforge-protocol/fastify",
});

export default fastifyTrustForge;
export type { DecideResponse } from "@trustforge-protocol/sdk";
