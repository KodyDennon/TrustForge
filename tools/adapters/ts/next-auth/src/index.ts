/**
 * @trustforge/next-auth — NextAuth / Auth.js callbacks that project the
 * resolved JWT / session into a TrustForge actor + capabilities.
 *
 * Usage:
 *   import NextAuth from "next-auth";
 *   import { trustforgeCallbacks } from "@trustforge/next-auth";
 *   export const { handlers, auth } = NextAuth({
 *     callbacks: trustforgeCallbacks({ daemonUrl, adminToken }),
 *   });
 *
 * The callbacks intentionally mirror NextAuth's `jwt`, `session`, `signIn`,
 * `signOut` shape so they can be merged into an existing config:
 *   callbacks: { ...trustforgeCallbacks({...}), ...myCallbacks }
 */

import { TrustForge, type TrustForgeOptions } from "@trustforge/sdk";

export interface TrustForgeCallbacksOptions extends TrustForgeOptions {
  /** Hint forwarded to `tf.importCredential`. Default: "next-auth". */
  hint?: string;
  /** Suppress console log line on every resolved session. Default: false. */
  quiet?: boolean;
  logger?: (msg: string, meta?: Record<string, unknown>) => void;
}

export interface NextAuthJWT {
  sub?: string;
  [key: string]: unknown;
}

export interface NextAuthSession {
  user?: { id?: string; email?: string };
  expires?: string;
  [key: string]: unknown;
}

export interface NextAuthCallbacks {
  jwt: (params: {
    token: NextAuthJWT;
    user?: { id?: string };
    account?: { access_token?: string; provider?: string };
  }) => Promise<NextAuthJWT>;
  session: (params: {
    session: NextAuthSession;
    token: NextAuthJWT;
  }) => Promise<NextAuthSession>;
  signIn: (params: {
    user?: { id?: string };
    account?: { provider?: string };
  }) => Promise<boolean>;
  signOut: (params: { token?: NextAuthJWT }) => Promise<void>;
}

/**
 * Build the four NextAuth callbacks. They are independent of each other and
 * can be spread alongside user-provided callbacks.
 */
export function trustforgeCallbacks(
  opts: TrustForgeCallbacksOptions,
): NextAuthCallbacks {
  const tf = new TrustForge(opts);
  const hint = opts.hint ?? "next-auth";
  const log =
    opts.logger ??
    ((msg: string, meta?: Record<string, unknown>) => {
      if (opts.quiet) return;
      // eslint-disable-next-line no-console
      console.log(msg, meta ?? {});
    });

  return {
    async jwt({ token, user, account }) {
      // Run on initial sign-in (when `user` is present) and on every
      // subsequent token refresh. We attach the TF actor onto the token so
      // it survives the JWT round-trip and is available in `session()`.
      const credential =
        account?.access_token ??
        (typeof token.sub === "string" ? token.sub : undefined);
      if (!credential) return token;

      try {
        const resp = await tf.importCredential({
          kind: hint,
          token: credential,
          actor_hint: user?.id ?? token.sub,
        });
        token.tfActor = resp.actor;
        token.tfCredentialId = resp.credential_id;
        token.tfTrustLevel = resp.trust_level;
        log("bridge.next_auth.session_resolved", {
          actor: resp.actor,
          phase: "jwt",
        });
      } catch (err) {
        log("bridge.next_auth.session_resolved error", {
          error: (err as Error).message,
          phase: "jwt",
        });
      }
      return token;
    },

    async session({ session, token }) {
      // Mirror the TF fields from the JWT onto the public session object.
      if (token.tfActor) session.tfActor = token.tfActor as string;
      if (token.tfCredentialId)
        session.tfCredentialId = token.tfCredentialId as string;
      if (token.tfTrustLevel)
        session.tfTrustLevel = token.tfTrustLevel as string;
      session.tfCapabilities = [];
      return session;
    },

    async signIn({ user, account }) {
      // Best-effort early import so that even routes that read directly from
      // the DB session see a TF actor on the very first authenticated request.
      const accountToken = (account as { access_token?: string } | null | undefined)?.access_token;
      const credential =
        accountToken ?? (user?.id ? `user:${user.id}` : undefined);
      if (!credential) return true;
      try {
        await tf.importCredential({
          kind: hint,
          token: credential,
          actor_hint: user?.id,
        });
        log("bridge.next_auth.session_resolved", {
          phase: "signIn",
          provider: account?.provider,
        });
      } catch (err) {
        log("bridge.next_auth.session_resolved error", {
          error: (err as Error).message,
          phase: "signIn",
        });
      }
      return true;
    },

    async signOut({ token }) {
      // We don't have a wire endpoint to revoke yet; just record the event.
      log("bridge.next_auth.session_resolved", {
        phase: "signOut",
        actor: token?.tfActor,
      });
    },
  };
}

/**
 * Per-route guard helper. Returns a function that, given a NextAuth session
 * (or any object with `tfActor`), runs `tf.decide` for the given action.
 */
export function tfRequire(
  opts: TrustForgeCallbacksOptions,
  action: string,
  target: string | null = null,
) {
  const tf = new TrustForge(opts);
  return async (sessionLike: { tfActor?: string } | null | undefined) => {
    const traceId = `na-${Date.now().toString(36)}-${Math.random()
      .toString(36)
      .slice(2, 8)}`;
    const resp = await tf.decide({
      actor: sessionLike?.tfActor ?? null,
      action,
      target,
      context: { source: "next-auth" },
      trace_id: traceId,
    });
    return {
      allowed: resp.decision === "allow",
      reason: resp.reason,
      proofId: resp.proof_id,
    };
  };
}

export default trustforgeCallbacks;
