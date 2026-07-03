/**
 * @trustforge-protocol/passport — Passport strategy that verifies an inbound
 * credential (typically a bearer token, opaque session id, or signed cookie)
 * by handing it to the TrustForge daemon, then surfaces the resolved TF
 * actor as the authenticated `req.user`.
 *
 *   import passport from "passport";
 *   import { TrustForgeStrategy } from "@trustforge-protocol/passport";
 *   passport.use(new TrustForgeStrategy({ daemonUrl: "..." }));
 *   app.use(passport.authenticate("trustforge", { session: false }));
 *
 * The strategy duck-types the standard Passport base contract. We do not
 * import `passport-strategy` at runtime; we expose the same shape so it works
 * when the host registers the instance with `passport.use(...)`.
 */

import { TrustForge, type TrustForgeOptions } from "@trustforge-protocol/sdk";

export interface TrustForgeStrategyOptions extends TrustForgeOptions {
  hint?: string;
  /** Where to look for the credential. Default: "auth-bearer" (Bearer header). */
  source?: "auth-bearer" | "cookie" | "custom";
  /** Cookie name when `source = "cookie"`. */
  cookieName?: string;
  /** Custom extractor. Required when `source = "custom"`. */
  extract?: (req: any) => string | null | undefined;
  /** Hook to map a TF importCredential response into the user object. */
  toUser?: (resp: {
    actor: string;
    credential_id: string;
    trust_level: string;
  }) => any;
  quiet?: boolean;
  logger?: (msg: string, meta?: Record<string, unknown>) => void;
}

/**
 * Passport-style strategy.
 *
 * `passport.authenticate("trustforge")` will call `authenticate(req, opts)` on
 * the registered instance. Passport's runtime injects helper methods
 * (`success`, `fail`, `error`, `pass`) via prototype chain at call time; we
 * type those here so TypeScript stays honest while remaining compatible.
 */
export class TrustForgeStrategy {
  /** Strategy identifier used by `passport.authenticate("trustforge")`. */
  public readonly name = "trustforge";

  // Filled in by Passport at runtime.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public success!: (user: any, info?: any) => void;
  public fail!: (challenge?: string | number, status?: number) => void;
  public error!: (err: Error) => void;
  public pass!: () => void;

  private readonly tf: TrustForge;
  private readonly opts: TrustForgeStrategyOptions;

  constructor(opts: TrustForgeStrategyOptions) {
    this.tf = new TrustForge(opts);
    this.opts = opts;
  }

  async authenticate(req: any, _options?: unknown): Promise<void> {
    const credential = this.extract(req);
    if (!credential) {
      this.fail?.("missing-credential", 401);
      return;
    }
    try {
      const resp = await this.tf.importCredential({
        kind: this.opts.hint ?? "passport-bearer",
        token: credential,
      });
      const user = this.opts.toUser
        ? this.opts.toUser(resp)
        : {
            tfActor: resp.actor,
            tfCredentialId: resp.credential_id,
            tfTrustLevel: resp.trust_level,
            tfCapabilities: [],
          };
      this.log("bridge.passport.session_resolved", { actor: resp.actor });
      this.success?.(user);
    } catch (err) {
      this.log("bridge.passport.session_resolved error", {
        error: (err as Error).message,
      });
      this.error?.(err as Error);
    }
  }

  private extract(req: any): string | null {
    const src = this.opts.source ?? "auth-bearer";
    if (src === "auth-bearer") {
      const h: string | undefined =
        req?.headers?.authorization ?? req?.headers?.Authorization;
      if (!h) return null;
      const m = /^Bearer\s+(.+)$/i.exec(h);
      return m?.[1] ?? null;
    }
    if (src === "cookie") {
      const cookies = (req?.cookies ?? {}) as Record<string, string>;
      const name = this.opts.cookieName ?? "session";
      return cookies[name] ?? null;
    }
    if (src === "custom" && this.opts.extract) {
      const v = this.opts.extract(req);
      return typeof v === "string" && v.length > 0 ? v : null;
    }
    return null;
  }

  private log(msg: string, meta?: Record<string, unknown>) {
    const fn =
      this.opts.logger ??
      ((m: string, mm?: Record<string, unknown>) => {
        if (this.opts.quiet) return;
        // eslint-disable-next-line no-console
        console.log(m, mm ?? {});
      });
    fn(msg, meta);
  }
}

export default TrustForgeStrategy;
