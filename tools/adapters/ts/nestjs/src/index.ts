// NestJS adapter for TrustForge.
//
// Public API:
//   - TrustForgeService — Injectable wrapper around the SDK.
//   - TrustForgeGuard — implements `CanActivate`; consults the daemon and
//     either allows the request through, or throws an HttpException with the
//     correct status.
//   - @TrustForgeRequire("action.name") — method/class decorator that pins
//     the action string for that route.
//   - TrustForgeModule.forRoot(opts) — dynamic module that wires the
//     service + guard with global config.
//
// We don't import from `@nestjs/common` at the top level because it brings
// reflect-metadata side-effects. Instead we lazy-require it and fall back
// to plain factories so the module is testable in isolation.

import type {
  NestExecutionContextLike,
  NestHttpReqLike,
  TfDecideRequest,
  TfDecision,
  TfHostTokenKind,
  TfNestOptions,
  TrustForgeLike,
} from "./types.ts";

const ACTION_METADATA_KEY = "trustforge:required-action";

// -------------------- decorator --------------------

/**
 * Mark a controller method (or whole class) as requiring a specific
 * TrustForge action. The guard reads this with `Reflect.getMetadata`.
 *
 *   @Controller("users")
 *   class UsersController {
 *     @TrustForgeRequire("user.create")
 *     @Post()
 *     create(@Body() body: any) { ... }
 *   }
 */
export function TrustForgeRequire(action: string): MethodDecorator & ClassDecorator {
  return (target: object, key?: string | symbol, descriptor?: PropertyDescriptor) => {
    if (descriptor && key !== undefined) {
      // Method decorator path.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const r = (globalThis as any).Reflect;
      r?.defineMetadata?.(ACTION_METADATA_KEY, action, descriptor.value);
      r?.defineMetadata?.(ACTION_METADATA_KEY, action, target, key);
    } else {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const r = (globalThis as any).Reflect;
      r?.defineMetadata?.(ACTION_METADATA_KEY, action, target);
    }
  };
}

/**
 * Read the action name set by `@TrustForgeRequire(...)` from a NestJS
 * execution context. Returns undefined if no decorator was applied.
 */
export function getRequiredAction(ctx: NestExecutionContextLike): string | undefined {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const r = (globalThis as any).Reflect;
  if (!r?.getMetadata) return undefined;
  return (
    r.getMetadata(ACTION_METADATA_KEY, ctx.getHandler()) ??
    r.getMetadata(ACTION_METADATA_KEY, ctx.getClass())
  );
}

// -------------------- service --------------------

/**
 * Injectable wrapper around the SDK. NestJS DI users get this via:
 *
 *   constructor(private readonly tf: TrustForgeService) {}
 *
 * In tests, instantiate it directly with a mock client:
 *
 *   const svc = new TrustForgeService({ tf: mockClient });
 */
export class TrustForgeService {
  private clientPromise: Promise<TrustForgeLike> | undefined;

  constructor(public readonly opts: TfNestOptions) {}

  async getClient(): Promise<TrustForgeLike> {
    if (this.opts.tf) return this.opts.tf;
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const mod: any = await import("@trustforge-protocol/sdk").catch(() => null);
        if (!mod?.TrustForge) {
          throw new Error(
            "@trustforge-protocol/nestjs: @trustforge-protocol/sdk is not installed. " +
              "Pass `tf:` to TrustForgeModule.forRoot({...}) for testing.",
          );
        }
        return new mod.TrustForge({
          daemonUrl: this.opts.daemonUrl,
          adminToken: this.opts.adminToken,
        });
      })();
    }
    return this.clientPromise;
  }

  async decide(req: TfDecideRequest): Promise<TfDecision> {
    const client = await this.getClient();
    return client.decide(req);
  }
}

// -------------------- guard --------------------

function defaultResolveCredential(req: NestHttpReqLike): {
  host_token: string | null;
  host_token_kind: TfHostTokenKind | null;
} {
  const auth = readHeader(req, "authorization");
  if (auth?.toLowerCase().startsWith("bearer ")) {
    return { host_token: auth.slice(7).trim(), host_token_kind: "oauth-jwt" };
  }

  const cookies = req.cookies ?? parseCookies(readHeader(req, "cookie"));
  const nextAuth =
    cookies["__Secure-next-auth.session-token"] ??
    cookies["next-auth.session-token"];
  if (nextAuth) return { host_token: nextAuth, host_token_kind: "next-auth-jwt" };

  for (const name of ["session", "auth", "tf-session"]) {
    const v = cookies[name];
    if (!v) continue;
    if (v.startsWith("sess_")) return { host_token: v, host_token_kind: "clerk-session" };
    if (v.startsWith("auth_"))
      return { host_token: v, host_token_kind: "better-auth-session" };
  }

  return { host_token: null, host_token_kind: null };
}

function readHeader(req: NestHttpReqLike, name: string): string | undefined {
  const h = req.headers[name] ?? req.headers[name.toLowerCase()];
  if (Array.isArray(h)) return h[0];
  return h;
}

function parseCookies(raw: string | undefined): Record<string, string> {
  if (!raw) return {};
  const out: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k) out[k] = rest.join("=");
  }
  return out;
}

function defaultResolveAction(req: NestHttpReqLike): string {
  const path = req.originalUrl ?? req.url ?? "/";
  const segs = path.split("?")[0]!.split("/").filter(Boolean);
  const first = segs[0] ?? "root";
  return `${(req.method ?? "GET").toLowerCase()}.${first
    .replace(/[^a-z0-9_]/gi, "_")
    .toLowerCase()}`;
}

/**
 * Mirror of NestJS's `HttpException`. We don't import the real one because
 * it depends on `@nestjs/common`; instead we throw a structurally-compatible
 * error that NestJS's exception filter handles identically.
 */
export class TrustForgeHttpException extends Error {
  public readonly response: Record<string, unknown>;
  public readonly status: number;
  constructor(response: Record<string, unknown>, status: number) {
    super(typeof response.reason === "string" ? response.reason : "TrustForge denied");
    this.name = "TrustForgeHttpException";
    this.response = response;
    this.status = status;
  }
  getStatus(): number {
    return this.status;
  }
  getResponse(): Record<string, unknown> {
    return this.response;
  }
}

/**
 * NestJS guard. Implements `CanActivate` structurally:
 *   `canActivate(context: ExecutionContext): Promise<boolean>`.
 */
export class TrustForgeGuardImpl {
  constructor(
    private readonly service: TrustForgeService,
    private readonly opts: TfNestOptions = {},
  ) {}

  async canActivate(context: NestExecutionContextLike): Promise<boolean> {
    const req = context.switchToHttp().getRequest<NestHttpReqLike>();

    const path = (req.originalUrl ?? req.url ?? "/").split("?")[0]!;
    if (this.opts.skip?.(path)) return true;

    const decoratorAction = getRequiredAction(context);
    const action =
      decoratorAction ??
      (this.opts.resolveAction ? await this.opts.resolveAction(req) : undefined) ??
      this.opts.defaultAction ??
      defaultResolveAction(req);

    const cred = (this.opts.resolveCredential ?? defaultResolveCredential)(req);
    const trace_id =
      this.opts.resolveTraceId?.(req) ??
      globalThis.crypto?.randomUUID?.() ??
      `tf-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const extraCtx = this.opts.resolveContext?.(req) ?? {};

    const decision = await this.service.decide({
      actor: "actor" in cred ? cred.actor ?? null : null,
      host_token: cred.host_token ?? null,
      host_token_kind: cred.host_token_kind ?? null,
      action,
      target: path,
      context: { method: req.method, ...extraCtx },
      trace_id,
    });

    req.tfActor = decision.actor_resolved;
    req.tfDecision = decision;
    req.tfProofId = decision.proof_id;

    if (this.opts.mode === "observe-only") return true;

    if (decision.decision === "allow" || decision.decision === "log-only") {
      return true;
    }

    const status =
      decision.decision === "approval-required" ? 202 : 403;
    throw new TrustForgeHttpException(
      {
        decision: decision.decision,
        reason: decision.reason,
        approval_id: decision.approval_id,
        danger_tags: decision.danger_tags,
        proof_id: decision.proof_id,
      },
      status,
    );
  }
}

/**
 * Decorator-shaped factory so users can write either
 *   `@UseGuards(TrustForgeGuard)`
 * (where the guard is provided via the module's DI), or, when constructing
 * by hand:
 *   `@UseGuards(new TrustForgeGuard(service, opts))`.
 *
 * NestJS uses class identity for guard registration, so we return a class.
 */
export const TrustForgeGuard = TrustForgeGuardImpl;

// -------------------- module --------------------

export interface TrustForgeModuleConfig extends TfNestOptions {}

/**
 * Dynamic NestJS module. Returns the metadata object NestJS expects from
 * `forRoot`. We don't import `@nestjs/common`'s `Module` decorator because
 * it would force the dependency at type-check time; instead consumers import
 * `TrustForgeModule.forRoot({...})` and Nest accepts the plain metadata.
 */
export class TrustForgeModule {
  static forRoot(config: TrustForgeModuleConfig = {}): {
    module: typeof TrustForgeModule;
    providers: Array<unknown>;
    exports: Array<unknown>;
    global: boolean;
  } {
    const TF_OPTIONS_TOKEN = "TRUSTFORGE_OPTIONS";

    return {
      module: TrustForgeModule,
      global: true,
      providers: [
        { provide: TF_OPTIONS_TOKEN, useValue: config },
        {
          provide: TrustForgeService,
          useFactory: () => new TrustForgeService(config),
        },
        {
          provide: TrustForgeGuard,
          useFactory: (svc: TrustForgeService) => new TrustForgeGuardImpl(svc, config),
          inject: [TrustForgeService],
        },
      ],
      exports: [TrustForgeService, TrustForgeGuard],
    };
  }
}

// -------------------- re-exports --------------------

export type {
  TfDecideRequest,
  TfDecision,
  TfDecisionVerdict,
  TfTrustLevel,
  TfAuthorityMode,
  TfHostTokenKind,
  TfMode,
  TrustForgeLike,
  TfNestOptions,
  NestExecutionContextLike,
  NestHttpReqLike,
} from "./types.ts";
