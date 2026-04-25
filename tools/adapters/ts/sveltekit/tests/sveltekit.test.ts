import { describe, expect, test } from "bun:test";
import { trustforgeHandle } from "../src/index.ts";
import type {
  SvelteRequestEventLike,
  TfDecideRequest,
  TfDecision,
  TrustForgeLike,
} from "../src/types.ts";

function mockClient(
  decisionFor: (req: TfDecideRequest) => TfDecision,
): TrustForgeLike & { calls: TfDecideRequest[] } {
  const calls: TfDecideRequest[] = [];
  return {
    calls,
    async decide(req) {
      calls.push(req);
      return decisionFor(req);
    },
  };
}

function makeEvent(opts: {
  method?: string;
  path?: string;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
} = {}): SvelteRequestEventLike & { locals: Record<string, unknown> } {
  const url = new URL(opts.path ?? "/api/users", "https://example.com");
  return {
    request: new Request(url, {
      method: opts.method ?? "GET",
      headers: opts.headers,
    }),
    url,
    cookies: {
      get(name: string) {
        return opts.cookies?.[name];
      },
    },
    locals: {},
  };
}

const allow: TfDecision = {
  decision: "allow",
  reason: "ok",
  approval_id: null,
  proof_id: "sha256:allow",
  actor_resolved: "tf:actor:user:example.com/alice",
  trust_level: "T2",
  authority_mode: "layered",
  danger_tags: [],
};

const deny: TfDecision = {
  ...allow,
  decision: "deny",
  reason: "policy",
  proof_id: "sha256:deny",
  danger_tags: ["forbidden"],
};

const approvalReq: TfDecision = {
  ...allow,
  decision: "approval-required",
  reason: "needs human review",
  approval_id: "approval-42",
  proof_id: "sha256:approval",
};

describe("@trustforge/sveltekit", () => {
  test("on allow, calls resolve(event), sets event.locals.tfActor + tfDecision", async () => {
    const tf = mockClient(() => allow);
    const handle = trustforgeHandle({ tf });

    const event = makeEvent({
      headers: { authorization: "Bearer eyJtest.tok.sig" },
    });
    let resolved = false;
    const res = await handle({
      event,
      resolve: async (e) => {
        // SvelteKit guarantees the handler runs after `handle`. Locals must
        // already be populated.
        resolved = true;
        expect(e.locals.tfActor).toBe("tf:actor:user:example.com/alice");
        expect((e.locals.tfDecision as TfDecision).decision).toBe("allow");
        return new Response("ok", { status: 200 });
      },
    });

    expect(resolved).toBe(true);
    expect(res.status).toBe(200);
    expect(res.headers.get("x-tf-decision")).toBe("allow");
    expect(res.headers.get("x-tf-proof-id")).toBe("sha256:allow");
    expect(tf.calls[0]?.host_token).toBe("eyJtest.tok.sig");
    expect(tf.calls[0]?.host_token_kind).toBe("oauth-jwt");
    expect(tf.calls[0]?.action).toBe("get.api");
  });

  test("on deny, returns 403 + WWW-Authenticate without invoking resolve", async () => {
    const tf = mockClient(() => deny);
    const handle = trustforgeHandle({ tf });

    let resolveCalled = false;
    const event = makeEvent({ method: "POST", path: "/admin/users" });
    const res = await handle({
      event,
      resolve: async () => {
        resolveCalled = true;
        return new Response("should not happen", { status: 200 });
      },
    });

    expect(resolveCalled).toBe(false);
    expect(res.status).toBe(403);
    expect(res.headers.get("www-authenticate")).toContain("TrustForge");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.decision).toBe("deny");
    expect(body.danger_tags).toEqual(["forbidden"]);
  });

  test("on approval-required, returns 202 + Location header", async () => {
    const tf = mockClient(() => approvalReq);
    const handle = trustforgeHandle({ tf });

    const event = makeEvent({ method: "DELETE", path: "/api/data/9" });
    const res = await handle({
      event,
      resolve: async () => new Response("never", { status: 200 }),
    });

    expect(res.status).toBe(202);
    expect(res.headers.get("location")).toBe("/tf/approval/approval-42");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.approval_id).toBe("approval-42");
  });

  test("observe-only mode forwards even on deny and still sets locals", async () => {
    const tf = mockClient(() => deny);
    const handle = trustforgeHandle({ tf, mode: "observe-only" });

    const event = makeEvent({
      cookies: { "__Secure-next-auth.session-token": "eyJpayload" },
    });
    let resolved = false;
    const res = await handle({
      event,
      resolve: async (e) => {
        resolved = true;
        expect((e.locals.tfDecision as TfDecision).decision).toBe("deny");
        return new Response("served-anyway", { status: 200 });
      },
    });

    expect(resolved).toBe(true);
    expect(res.status).toBe(200);
    expect(res.headers.get("x-tf-decision")).toBe("deny");
    expect(tf.calls[0]?.host_token).toBe("eyJpayload");
    expect(tf.calls[0]?.host_token_kind).toBe("next-auth-jwt");
  });

  test("skip predicate bypasses the daemon entirely", async () => {
    const tf = mockClient(() => deny);
    const handle = trustforgeHandle({
      tf,
      skip: (p) => p.startsWith("/_app") || p.startsWith("/_health"),
    });

    const event = makeEvent({ path: "/_health/live" });
    let resolved = false;
    const res = await handle({
      event,
      resolve: async () => {
        resolved = true;
        return new Response("ok", { status: 200 });
      },
    });

    expect(resolved).toBe(true);
    expect(res.status).toBe(200);
    expect(tf.calls.length).toBe(0);
    expect(event.locals.tfDecision).toBeUndefined();
  });
});
