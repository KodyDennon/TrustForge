// Next.js Edge / Node middleware entry point.
//
// Usage (in a Next.js project's `middleware.ts`):
//
//   import { withTrustForge } from "@trustforge-protocol/next/middleware";
//   export default withTrustForge({ daemonUrl: "http://127.0.0.1:8642" });
//   export const config = { matcher: ["/((?!_next|favicon.ico).*)"] };
//
// Works on both the Edge runtime (`export const runtime = "edge"`) and the
// Node runtime, because we only use Web-standard `Request`/`Response`/`Headers`.

import { evaluateRequest } from "./internal.ts";
import type { TfAdapterOptions, TfRequestLike } from "./types.ts";

/**
 * Shape of the Next.js middleware function. We deliberately keep this typed
 * structurally rather than importing `NextResponse` so the package can be
 * installed without `next` present at type-check time.
 */
export type NextMiddleware = (
  req: TfRequestLike,
) => Promise<NextMiddlewareResponse> | NextMiddlewareResponse;

export type NextMiddlewareResponse = Response;

/**
 * Build a Next.js-compatible middleware function. Pass the result as the
 * default export of `middleware.ts`.
 */
export function withTrustForge(opts: TfAdapterOptions = {}): NextMiddleware {
  return async function trustForgeMiddleware(req) {
    // Allow the user to skip routes (e.g. health checks, public assets).
    const url = new URL(req.url, "http://localhost");
    if (opts.skip?.(url.pathname)) {
      return passthrough();
    }

    const outcome = await evaluateRequest(req, opts);

    if (outcome.allowed) {
      // NextResponse.next() — represented as a header-only Response that
      // Next.js's runtime treats as "continue to the route handler".
      return passthrough(outcome.headers);
    }

    return new Response(JSON.stringify(outcome.body), {
      status: outcome.status,
      headers: {
        "content-type": "application/json",
        ...outcome.headers,
      },
    });
  };
}

function passthrough(extra: Record<string, string> = {}): Response {
  // Next.js detects the special `x-middleware-next: 1` header as a "continue"
  // signal. We also mirror our own decision metadata so downstream handlers
  // can read it.
  return new Response(null, {
    status: 200,
    headers: {
      "x-middleware-next": "1",
      ...extra,
    },
  });
}

/**
 * Recommended config the consumer should re-export from their `middleware.ts`.
 * We can't auto-export `config` (Next.js needs a literal), but a stable
 * default is convenient.
 */
export const recommendedMatcher = [
  "/((?!_next/static|_next/image|favicon.ico).*)",
];
