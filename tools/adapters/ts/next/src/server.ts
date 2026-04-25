// Next.js route-handler wrapper for both App Router and Pages Router.
//
// App Router (app/api/users/route.ts):
//
//   import { tfRequire } from "@trustforge/next/server";
//   export const POST = tfRequire("user.create")(async (req) => {
//     return Response.json({ ok: true });
//   });
//
// Pages Router (pages/api/users.ts):
//
//   import { tfRequireApi } from "@trustforge/next/server";
//   export default tfRequireApi("user.create")(async (req, res) => {
//     res.json({ ok: true });
//   });

import { evaluateRequest } from "./internal.ts";
import type { TfAdapterOptions, TfRequestLike, TfDecision } from "./types.ts";

export interface RouteContext {
  decision: TfDecision;
}

/** App-router-style handler. Receives a Web `Request`. */
export type AppRouteHandler = (
  req: Request,
  ctx?: RouteContext,
) => Response | Promise<Response>;

/**
 * Wrap an App Router route handler so the action is gated by TrustForge.
 * The action string is forced to `action`; we don't infer it from the path.
 */
export function tfRequire(
  action: string,
  opts: TfAdapterOptions = {},
): (handler: AppRouteHandler) => AppRouteHandler {
  return (handler) => async (req) => {
    const reqLike = req as unknown as TfRequestLike;
    const outcome = await evaluateRequest(reqLike, {
      ...opts,
      resolveAction: () => action,
    });

    if (!outcome.allowed) {
      return new Response(JSON.stringify(outcome.body), {
        status: outcome.status,
        headers: {
          "content-type": "application/json",
          ...outcome.headers,
        },
      });
    }

    const res = await handler(req, { decision: outcome.decision });
    // Annotate the outgoing response with proof metadata for observability.
    for (const [k, v] of Object.entries(outcome.headers)) {
      if (!res.headers.has(k)) res.headers.set(k, v);
    }
    return res;
  };
}

// -------------------------- Pages Router shim --------------------------

/**
 * Minimal NextApiRequest-like type. We only use `method`, `url`, and `headers`
 * — exactly the cross-router contract.
 */
export interface NextApiReqLike {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  cookies?: Record<string, string>;
}

/** Minimal NextApiResponse-like sink. */
export interface NextApiResLike {
  status(code: number): NextApiResLike;
  setHeader(k: string, v: string): NextApiResLike;
  json(body: unknown): NextApiResLike;
  end(body?: unknown): NextApiResLike;
}

export type ApiRouteHandler = (
  req: NextApiReqLike,
  res: NextApiResLike,
) => unknown | Promise<unknown>;

/** Pages Router wrapper. */
export function tfRequireApi(
  action: string,
  opts: TfAdapterOptions = {},
): (handler: ApiRouteHandler) => ApiRouteHandler {
  return (handler) => async (req, res) => {
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (Array.isArray(v)) headers.set(k, v.join(", "));
      else if (typeof v === "string") headers.set(k, v);
    }

    const reqLike: TfRequestLike = {
      method: req.method ?? "GET",
      url: req.url ?? "/",
      headers,
      cookies: req.cookies
        ? {
            get(name) {
              const val = req.cookies?.[name];
              return val ? { value: val } : undefined;
            },
          }
        : undefined,
    };

    const outcome = await evaluateRequest(reqLike, {
      ...opts,
      resolveAction: () => action,
    });

    for (const [k, v] of Object.entries(outcome.headers)) {
      res.setHeader(k, v);
    }

    if (!outcome.allowed) {
      res.status(outcome.status).json(outcome.body);
      return;
    }

    return handler(req, res);
  };
}
