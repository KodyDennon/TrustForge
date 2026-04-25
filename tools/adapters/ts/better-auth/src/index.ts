/**
 * @trustforge/better-auth — Better Auth plugin that projects resolved
 * sessions into TrustForge actors / capabilities.
 *
 * Usage:
 *   import { betterAuth } from "better-auth";
 *   import { trustforgePlugin } from "@trustforge/better-auth";
 *   const auth = betterAuth({
 *     plugins: [trustforgePlugin({ daemonUrl, adminToken })],
 *   });
 *
 * The plugin registers a `session.fetch` hook (Better Auth's "I just resolved
 * a session" callback). Each resolved session is forwarded to
 * `tf.importCredential` so the daemon can mint or refresh the corresponding
 * TF actor + capabilities, which are then stashed on the session context as
 * `tfActor` and `tfCapabilities`.
 *
 * The plugin emits a `bridge.better_auth.session_resolved` log line; the
 * daemon emits the *signed* proof event when /v1/credentials/import runs.
 */

import { TrustForge, type TrustForgeOptions } from "@trustforge/sdk";

export interface TrustForgePluginOptions extends TrustForgeOptions {
  /** Hint forwarded to `tf.importCredential`. Default: "better-auth". */
  hint?: string;
  /** Suppress console log line on every resolved session. Default: false. */
  quiet?: boolean;
  /** Optional logger override. */
  logger?: (msg: string, meta?: Record<string, unknown>) => void;
}

export interface TFAttachedContext {
  tfActor: string;
  tfCapabilities: string[];
  tfTrustLevel: string;
  tfCredentialId: string;
}

export interface BetterAuthSessionLike {
  id?: string;
  token?: string;
  userId?: string;
  user?: { id?: string };
}

export interface BetterAuthHookContextLike {
  session?: BetterAuthSessionLike | null;
  context?: Record<string, unknown>;
  // These fields are commonly attached to the request scope by Better Auth.
  tfActor?: string;
  tfCapabilities?: string[];
  tfTrustLevel?: string;
  tfCredentialId?: string;
}

/**
 * The Better Auth Plugin object. Better Auth's plugin system loads any object
 * with `id` + a `hooks` map at registration time. We mirror that contract here
 * without taking a hard dependency on the package's internal types.
 */
export interface BetterAuthPluginShape {
  id: string;
  /**
   * Better Auth hooks.
   * `session.fetch` runs after a session is resolved and lets us project the
   * session into TF actor / capabilities.
   */
  hooks: {
    session: {
      fetch: (
        ctx: BetterAuthHookContextLike,
      ) => Promise<BetterAuthHookContextLike>;
    };
  };
  /** Helper exposed so app code can require a TF action per route. */
  tfRequire: (
    action: string,
    target?: string | null,
  ) => (
    ctx: BetterAuthHookContextLike,
  ) => Promise<{ allowed: boolean; reason: string; proofId: string }>;
}

/**
 * Create a Better Auth plugin that attaches TrustForge actor + capabilities
 * to every resolved session.
 */
export function trustforgePlugin(
  opts: TrustForgePluginOptions,
): BetterAuthPluginShape {
  const tf = new TrustForge(opts);
  const hint = opts.hint ?? "better-auth";
  const log =
    opts.logger ??
    ((msg: string, meta?: Record<string, unknown>) => {
      if (opts.quiet) return;
      // eslint-disable-next-line no-console
      console.log(msg, meta ?? {});
    });

  return {
    id: "trustforge",
    hooks: {
      session: {
        async fetch(ctx) {
          const session = ctx.session;
          if (!session) return ctx;

          // Prefer an opaque session id; fall back to internal token.
          const credential = session.id ?? session.token;
          if (!credential) {
            log(
              "bridge.better_auth.session_resolved skip=no-credential",
              {},
            );
            return ctx;
          }

          try {
            const resp = await tf.importCredential({
              kind: hint,
              token: credential,
              actor_hint: session.userId ?? session.user?.id,
            });
            ctx.tfActor = resp.actor;
            ctx.tfCredentialId = resp.credential_id;
            ctx.tfTrustLevel = resp.trust_level;
            // Capabilities are not part of /v1/credentials/import in the
            // wire spec yet — they are populated lazily per-decide. We expose
            // an empty array placeholder so downstream code can rely on the
            // field being present.
            ctx.tfCapabilities = [];

            log("bridge.better_auth.session_resolved", {
              actor: resp.actor,
              trust_level: resp.trust_level,
              credential_id: resp.credential_id,
            });
          } catch (err) {
            log("bridge.better_auth.session_resolved error", {
              error: (err as Error).message,
            });
          }

          return ctx;
        },
      },
    },

    tfRequire(action, target = null) {
      return async (ctx) => {
        const traceId = `ba-${Date.now().toString(36)}-${Math.random()
          .toString(36)
          .slice(2, 8)}`;
        const resp = await tf.decide({
          actor: ctx.tfActor ?? null,
          action,
          target,
          context: { source: "better-auth" },
          trace_id: traceId,
        });
        return {
          allowed: resp.decision === "allow",
          reason: resp.reason,
          proofId: resp.proof_id,
        };
      };
    },
  };
}

export default trustforgePlugin;
