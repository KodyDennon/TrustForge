/**
 * @trustforge-protocol/lucia — Lucia v3 session-validation hook.
 *
 * Lucia exposes `Lucia.validateSession(sessionId)` which returns a
 * `{ session, user }` pair. We wrap that call so every successful validation
 * also projects the session id into a TrustForge actor.
 *
 *   import { Lucia } from "lucia";
 *   import { trustforgeForLucia } from "@trustforge-protocol/lucia";
 *
 *   const lucia = new Lucia(adapter, { ... });
 *   export const tfLucia = trustforgeForLucia(lucia, {
 *     daemonUrl: "http://127.0.0.1:7616",
 *   });
 *
 *   const result = await tfLucia.validateSession(sessionId);
 *   // result.tfActor / result.tfCapabilities are now populated.
 */

import { TrustForge, type TrustForgeOptions } from "@trustforge-protocol/sdk";

export interface TrustForgeLuciaOptions extends TrustForgeOptions {
  hint?: string;
  quiet?: boolean;
  logger?: (msg: string, meta?: Record<string, unknown>) => void;
}

export interface LuciaValidationResult {
  session: { id: string; userId?: string } | null;
  user: { id: string } | null;
}

export interface LuciaLike {
  validateSession(
    sessionId: string,
  ): Promise<LuciaValidationResult> | LuciaValidationResult;
}

export interface TFLuciaResult extends LuciaValidationResult {
  tfActor?: string;
  tfCredentialId?: string;
  tfTrustLevel?: string;
  tfCapabilities?: string[];
}

export interface TFLuciaWrapper {
  validateSession(sessionId: string): Promise<TFLuciaResult>;
  tfRequire(
    action: string,
    target?: string | null,
  ): (
    res: TFLuciaResult,
  ) => Promise<{ allowed: boolean; reason: string; proofId: string }>;
}

export function trustforgeForLucia(
  lucia: LuciaLike,
  opts: TrustForgeLuciaOptions,
): TFLuciaWrapper {
  const tf = new TrustForge(opts);
  const hint = opts.hint ?? "lucia-session";
  const log =
    opts.logger ??
    ((msg: string, meta?: Record<string, unknown>) => {
      if (opts.quiet) return;
      // eslint-disable-next-line no-console
      console.log(msg, meta ?? {});
    });

  return {
    async validateSession(sessionId: string) {
      const inner = await lucia.validateSession(sessionId);
      const out: TFLuciaResult = { ...inner };
      if (!inner.session) return out;

      try {
        const resp = await tf.importCredential({
          kind: hint,
          token: inner.session.id,
          actor_hint: inner.user?.id ?? inner.session.userId,
        });
        out.tfActor = resp.actor;
        out.tfCredentialId = resp.credential_id;
        out.tfTrustLevel = resp.trust_level;
        out.tfCapabilities = [];
        log("bridge.lucia.session_resolved", {
          actor: resp.actor,
          session_id: inner.session.id,
        });
      } catch (err) {
        log("bridge.lucia.session_resolved error", {
          error: (err as Error).message,
        });
      }
      return out;
    },

    tfRequire(action, target = null) {
      return async (res: TFLuciaResult) => {
        const traceId = `lucia-${Date.now().toString(36)}-${Math.random()
          .toString(36)
          .slice(2, 8)}`;
        const decision = await tf.decide({
          actor: res.tfActor ?? null,
          action,
          target,
          context: { source: "lucia" },
          trace_id: traceId,
        });
        return {
          allowed: decision.decision === "allow",
          reason: decision.reason,
          proofId: decision.proof_id,
        };
      };
    },
  };
}

export default trustforgeForLucia;
