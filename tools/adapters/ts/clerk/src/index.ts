/**
 * @trustforge/clerk — Clerk integration for Next.js + Express.
 *
 * Two entry points are exported:
 *
 * 1. `withTrustForge(clerkMiddleware())` — wrap Clerk's Next.js middleware.
 *    The wrapper runs Clerk first, then captures `auth().sessionId` and
 *    projects it into a TrustForge actor.
 *
 * 2. `trustforgeClerk({...})` — Express middleware that runs *after*
 *    `ClerkExpressRequireAuth()` and stashes the TF actor on `req`.
 */

import { TrustForge, type TrustForgeOptions } from "@trustforge/sdk";

export interface TrustForgeClerkOptions extends TrustForgeOptions {
  hint?: string;
  quiet?: boolean;
  logger?: (msg: string, meta?: Record<string, unknown>) => void;
}

interface ClerkAuthLike {
  sessionId?: string | null;
  userId?: string | null;
}

/**
 * Wrap a Clerk Next.js middleware (e.g. the result of `clerkMiddleware(...)`)
 * so that after Clerk runs, the resolved Clerk session id is projected into
 * a TrustForge actor and stashed on the request.
 */
export function withTrustForge<TMiddleware extends (...args: any[]) => any>(
  clerkMiddleware: TMiddleware,
  opts: TrustForgeClerkOptions = { daemonUrl: "http://127.0.0.1:7616" },
): TMiddleware {
  const tf = new TrustForge(opts);
  const hint = opts.hint ?? "clerk-session";
  const log = makeLogger(opts);

  const wrapped = (async (req: any, evt: any) => {
    const result = await clerkMiddleware(req, evt);
    // Best-effort capture: Clerk attaches `auth` on the request scope.
    const auth: ClerkAuthLike | undefined =
      typeof req?.auth === "function" ? req.auth() : req?.auth;
    const sessionId = auth?.sessionId ?? null;
    const userId = auth?.userId ?? undefined;
    if (sessionId) {
      try {
        const resp = await tf.importCredential({
          kind: hint,
          token: sessionId,
          actor_hint: userId ?? undefined,
        });
        if (req) {
          req.tfActor = resp.actor;
          req.tfCredentialId = resp.credential_id;
          req.tfTrustLevel = resp.trust_level;
          req.tfCapabilities = [];
        }
        log("bridge.clerk.session_resolved", {
          actor: resp.actor,
          session_id: sessionId,
        });
      } catch (err) {
        log("bridge.clerk.session_resolved error", {
          error: (err as Error).message,
        });
      }
    }
    return result;
  }) as TMiddleware;

  return wrapped;
}

/**
 * Express-style middleware. Runs after `ClerkExpressRequireAuth()` (or any
 * middleware that populates `req.auth.sessionId`) and stashes the TF actor.
 */
export function trustforgeClerk(opts: TrustForgeClerkOptions) {
  const tf = new TrustForge(opts);
  const hint = opts.hint ?? "clerk-session";
  const log = makeLogger(opts);

  return async (
    req: any,
    _res: any,
    next: (err?: unknown) => void,
  ): Promise<void> => {
    const auth: ClerkAuthLike | undefined =
      typeof req?.auth === "function" ? req.auth() : req?.auth;
    const sessionId = auth?.sessionId ?? null;
    if (!sessionId) {
      next();
      return;
    }
    try {
      const resp = await tf.importCredential({
        kind: hint,
        token: sessionId,
        actor_hint: auth?.userId ?? undefined,
      });
      req.tfActor = resp.actor;
      req.tfCredentialId = resp.credential_id;
      req.tfTrustLevel = resp.trust_level;
      req.tfCapabilities = [];
      log("bridge.clerk.session_resolved", {
        actor: resp.actor,
        session_id: sessionId,
      });
      next();
    } catch (err) {
      log("bridge.clerk.session_resolved error", {
        error: (err as Error).message,
      });
      next(err);
    }
  };
}

export function tfRequireClerk(
  opts: TrustForgeClerkOptions,
  action: string,
  target: string | null = null,
) {
  const tf = new TrustForge(opts);
  return async (req: { tfActor?: string }) => {
    const traceId = `clerk-${Date.now().toString(36)}-${Math.random()
      .toString(36)
      .slice(2, 8)}`;
    const resp = await tf.decide({
      actor: req.tfActor ?? null,
      action,
      target,
      context: { source: "clerk" },
      trace_id: traceId,
    });
    return {
      allowed: resp.decision === "allow",
      reason: resp.reason,
      proofId: resp.proof_id,
    };
  };
}

function makeLogger(opts: TrustForgeClerkOptions) {
  return (
    opts.logger ??
    ((msg: string, meta?: Record<string, unknown>) => {
      if (opts.quiet) return;
      // eslint-disable-next-line no-console
      console.log(msg, meta ?? {});
    })
  );
}
