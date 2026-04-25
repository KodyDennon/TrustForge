// 6 cases: edge + node × app + pages router styles, plus observe-only
// and skip rule.

import { describe, expect, test } from "bun:test";
import { withTrustForge } from "../src/middleware.ts";
import { tfRequire, tfRequireApi } from "../src/server.ts";
import type {
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

const allow: TfDecision = {
  decision: "allow",
  reason: "ok",
  approval_id: null,
  proof_id: "sha256:allow",
  actor_resolved: "tf:actor:agent:example.com/x",
  trust_level: "T2",
  authority_mode: "layered",
  danger_tags: [],
};

const deny: TfDecision = {
  ...allow,
  decision: "deny",
  reason: "policy: forbidden",
  proof_id: "sha256:deny",
  danger_tags: ["filesystem-secret-read"],
};

const approvalReq: TfDecision = {
  ...allow,
  decision: "approval-required",
  reason: "needs human review",
  approval_id: "approval-9912",
  proof_id: "sha256:approval",
};

describe("@trustforge/next middleware (Edge runtime, App Router)", () => {
  test("forwards allow decisions with x-middleware-next + proof headers", async () => {
    const tf = mockClient(() => allow);
    const mw = withTrustForge({ tf });

    // Edge runtime: receives a NextRequest-shaped object with `cookies.get()`.
    const req = new Request("https://example.com/api/users");
    const res = await mw(req);

    expect(res.status).toBe(200);
    expect(res.headers.get("x-middleware-next")).toBe("1");
    expect(res.headers.get("x-tf-decision")).toBe("allow");
    expect(res.headers.get("x-tf-proof-id")).toBe("sha256:allow");
    expect(tf.calls.length).toBe(1);
    expect(tf.calls[0]?.action).toBe("get.api");
    expect(tf.calls[0]?.target).toBe("/api/users");
  });

  test("denies with 403 + WWW-Authenticate when verdict = deny", async () => {
    const tf = mockClient(() => deny);
    const mw = withTrustForge({ tf });

    const req = new Request("https://example.com/etc/passwd", {
      headers: { authorization: "Bearer eyJabc.def.ghi" },
    });
    const res = await mw(req);

    expect(res.status).toBe(403);
    expect(res.headers.get("www-authenticate")).toContain("TrustForge");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.decision).toBe("deny");
    expect(body.danger_tags).toEqual(["filesystem-secret-read"]);
    // The Authorization header must have been forwarded as a host_token.
    expect(tf.calls[0]?.host_token).toBe("eyJabc.def.ghi");
    expect(tf.calls[0]?.host_token_kind).toBe("oauth-jwt");
  });
});

describe("@trustforge/next middleware (Node runtime, observe-only + skip)", () => {
  test("observe-only mode never blocks even on deny", async () => {
    const tf = mockClient(() => deny);
    const mw = withTrustForge({ tf, mode: "observe-only" });

    const req = new Request("https://example.com/admin", {
      headers: { cookie: "session=sess_abc123" },
    });
    const res = await mw(req);

    expect(res.status).toBe(200);
    expect(res.headers.get("x-middleware-next")).toBe("1");
    expect(res.headers.get("x-tf-decision")).toBe("deny");
    // Cookie-based credential extraction (Clerk-style sess_).
    expect(tf.calls[0]?.host_token).toBe("sess_abc123");
    expect(tf.calls[0]?.host_token_kind).toBe("clerk-session");
  });

  test("skip predicate bypasses the daemon entirely", async () => {
    const tf = mockClient(() => deny);
    const mw = withTrustForge({
      tf,
      skip: (path) => path.startsWith("/_health"),
    });

    const req = new Request("https://example.com/_health/live");
    const res = await mw(req);

    expect(res.status).toBe(200);
    expect(res.headers.get("x-middleware-next")).toBe("1");
    // Skipped — no decide call.
    expect(tf.calls.length).toBe(0);
  });
});

describe("@trustforge/next App Router tfRequire", () => {
  test("denies with 403 short-circuit when decision = deny", async () => {
    const tf = mockClient(() => deny);
    const wrapped = tfRequire("user.create", { tf })(async () =>
      Response.json({ ok: true }),
    );

    const req = new Request("https://example.com/api/users", { method: "POST" });
    const res = await wrapped(req);

    expect(res.status).toBe(403);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.decision).toBe("deny");
    expect(tf.calls[0]?.action).toBe("user.create");
  });

  test("returns 202 + Location on approval-required", async () => {
    const tf = mockClient(() => approvalReq);
    const wrapped = tfRequire("data.delete", { tf })(async () =>
      Response.json({ ok: true }),
    );

    const req = new Request("https://example.com/api/data/9", { method: "DELETE" });
    const res = await wrapped(req);

    expect(res.status).toBe(202);
    expect(res.headers.get("location")).toBe("/tf/approval/approval-9912");
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.approval_id).toBe("approval-9912");
  });
});

describe("@trustforge/next Pages Router tfRequireApi", () => {
  test("forwards allow decisions and annotates response headers", async () => {
    const tf = mockClient(() => allow);
    let handlerCalled = false;
    const wrapped = tfRequireApi("user.read", { tf })(async (_req, res) => {
      handlerCalled = true;
      res.status(200).json({ ok: true });
    });

    let captured = { status: 0, headers: {} as Record<string, string>, body: undefined as unknown };
    const res = {
      status(code: number) {
        captured.status = code;
        return this;
      },
      setHeader(k: string, v: string) {
        captured.headers[k] = v;
        return this;
      },
      json(body: unknown) {
        captured.body = body;
        return this;
      },
      end() {
        return this;
      },
    };

    await wrapped(
      {
        method: "GET",
        url: "/api/users/42",
        headers: { authorization: "Bearer eyJjwt.test.tok" },
        cookies: {},
      },
      res,
    );

    expect(handlerCalled).toBe(true);
    expect(captured.status).toBe(200);
    expect(captured.headers["x-tf-decision"]).toBe("allow");
    expect(captured.headers["x-tf-proof-id"]).toBe("sha256:allow");
    expect(tf.calls[0]?.action).toBe("user.read");
    expect(tf.calls[0]?.host_token).toBe("eyJjwt.test.tok");
  });
});
