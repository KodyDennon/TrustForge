/**
 * @trustforge/iron-session — wraps `getIronSession` so every read of the
 * cookie-backed session also projects the session into a TrustForge actor.
 *
 *   import { trustforgeForIronSession } from "@trustforge/iron-session";
 *   const getSession = trustforgeForIronSession(getIronSession, {
 *     daemonUrl: "http://127.0.0.1:7616",
 *     sessionOptions: { cookieName: "app", password: "..." },
 *   });
 *   const session = await getSession(req, res);
 *   // session.tfActor / session.tfCapabilities are populated.
 */

import { TrustForge, type TrustForgeOptions } from "@trustforge/sdk";

export interface TrustForgeIronOptions extends TrustForgeOptions {
  hint?: string;
  quiet?: boolean;
  /** Property name on the iron-session payload that uniquely identifies the user.
   *  Default: "userId". */
  identityField?: string;
  /** Optional separate field that holds an opaque session id. Default: "id". */
  sessionIdField?: string;
  logger?: (msg: string, meta?: Record<string, unknown>) => void;
}

export type IronSession<T extends object = Record<string, unknown>> = T & {
  save(): Promise<void>;
  destroy(): Promise<void>;
  tfActor?: string;
  tfCredentialId?: string;
  tfTrustLevel?: string;
  tfCapabilities?: string[];
};

export type GetIronSessionFn<T extends object = Record<string, unknown>> = (
  req: unknown,
  res: unknown,
  options?: unknown,
) => Promise<IronSession<T>>;

export function trustforgeForIronSession<
  T extends object = Record<string, unknown>,
>(
  getIronSession: GetIronSessionFn<T>,
  opts: TrustForgeIronOptions & { sessionOptions?: unknown },
): GetIronSessionFn<T> {
  const tf = new TrustForge(opts);
  const hint = opts.hint ?? "iron-session";
  const idField = opts.sessionIdField ?? "id";
  const userField = opts.identityField ?? "userId";
  const log =
    opts.logger ??
    ((msg: string, meta?: Record<string, unknown>) => {
      if (opts.quiet) return;
      // eslint-disable-next-line no-console
      console.log(msg, meta ?? {});
    });

  return async (req, res, sessionOptions) => {
    const session = await getIronSession(
      req,
      res,
      sessionOptions ?? opts.sessionOptions,
    );
    const payload = session as unknown as Record<string, unknown>;
    const sid = (payload[idField] ?? payload[userField]) as string | undefined;
    if (!sid) return session;

    try {
      const resp = await tf.importCredential({
        kind: hint,
        token: String(sid),
        actor_hint: payload[userField] as string | undefined,
      });
      session.tfActor = resp.actor;
      session.tfCredentialId = resp.credential_id;
      session.tfTrustLevel = resp.trust_level;
      session.tfCapabilities = [];
      log("bridge.iron_session.session_resolved", {
        actor: resp.actor,
      });
    } catch (err) {
      log("bridge.iron_session.session_resolved error", {
        error: (err as Error).message,
      });
    }
    return session;
  };
}

export function tfRequireIron(
  opts: TrustForgeIronOptions,
  action: string,
  target: string | null = null,
) {
  const tf = new TrustForge(opts);
  return async (session: { tfActor?: string }) => {
    const traceId = `iron-${Date.now().toString(36)}-${Math.random()
      .toString(36)
      .slice(2, 8)}`;
    const resp = await tf.decide({
      actor: session.tfActor ?? null,
      action,
      target,
      context: { source: "iron-session" },
      trace_id: traceId,
    });
    return {
      allowed: resp.decision === "allow",
      reason: resp.reason,
      proofId: resp.proof_id,
    };
  };
}

export default trustforgeForIronSession;
