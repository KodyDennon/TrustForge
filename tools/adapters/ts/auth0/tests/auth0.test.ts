import { afterEach, describe, expect, test } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge/test-utils";
import {
  decideForAuth0Token,
  trustforgeAuth0,
  type Auth0Claims,
} from "../src/index.ts";

let daemon: MockDaemonHandle;

afterEach(async () => {
  await daemon.stop();
});

const fakeVerifier =
  (sub: string, scope = "read:foo", permissions: string[] = ["read:foo"]) =>
  async (token: string): Promise<Auth0Claims> => {
    if (token === "bad") throw new Error("invalid-auth0-jwt");
    return {
      sub,
      aud: "https://api.example.com",
      iss: "https://my-tenant.us.auth0.com/",
      scope,
      permissions,
      email: `${sub}@example.com`,
    };
  };

function makeRes() {
  const headers: Record<string, string> = {};
  const state: { status: number; body: unknown } = { status: 200, body: undefined };
  const res = {
    status(code: number) {
      state.status = code;
      return res;
    },
    json(body: unknown) {
      state.body = body;
      return res;
    },
    setHeader(name: string, value: string) {
      headers[name.toLowerCase()] = value;
    },
  };
  return {
    res,
    headers,
    get status() {
      return state.status;
    },
    get body() {
      return state.body;
    },
  };
}

describe("@trustforge/auth0", () => {
  test("decideForAuth0Token — verifies token and forwards sub + scope", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const out = await decideForAuth0Token("good-jwt", {
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyToken: fakeVerifier("auth0|123"),
    });
    expect(out.claims.sub).toBe("auth0|123");
    const captured = daemon.calls()[0]!;
    expect(captured.host_token).toBe("good-jwt");
    expect(captured.host_token_kind).toBe("auth0-jwt");
    expect((captured.context as { sub: string }).sub).toBe("auth0|123");
    expect((captured.context as { scope: string }).scope).toBe("read:foo");
  });

  test("decideForAuth0Token — propagates verifier error", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    await expect(
      decideForAuth0Token("bad", {
        daemonUrl: daemon.url,
        adminToken: "admin",
        verifyToken: fakeVerifier("auth0|x"),
      }),
    ).rejects.toThrow(/invalid-auth0-jwt/);
  });

  test("middleware — allow path attaches tfAuth0Sub", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeAuth0({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyToken: fakeVerifier("auth0|y"),
    });
    const req = {
      headers: { authorization: "Bearer ok" },
      url: "/x",
      method: "GET",
    } as Parameters<typeof mw>[0];
    let nexted = false;
    const r = makeRes();
    await mw(req, r.res, () => {
      nexted = true;
    });
    expect(nexted).toBe(true);
    expect(req.tfAuth0Sub).toBe("auth0|y");
    expect(r.headers["x-tf-proof-id"]).toMatch(/^sha256:/);
  });

  test("middleware — missing Bearer returns 401", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeAuth0({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyToken: fakeVerifier("u"),
    });
    const req = { headers: {}, method: "GET" } as Parameters<typeof mw>[0];
    const r = makeRes();
    await mw(req, r.res, () => {
      throw new Error("nope");
    });
    expect(r.status).toBe(401);
  });

  test("middleware — verifier failure returns 401", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeAuth0({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyToken: fakeVerifier("u"),
    });
    const req = {
      headers: { authorization: "Bearer bad" },
      method: "GET",
    } as Parameters<typeof mw>[0];
    const r = makeRes();
    await mw(req, r.res, () => {});
    expect(r.status).toBe(401);
    expect((r.body as { error: string }).error).toBe("auth0-verify-failed");
  });

  test("middleware — deny returns 403", async () => {
    daemon = startMockDaemon({
      adminToken: "admin",
      decide: () => ({
        decision: "deny",
        reason: "no",
        approval_id: null,
        proof_id: "sha256:auth0-deny",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const mw = trustforgeAuth0({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyToken: fakeVerifier("u"),
    });
    const req = {
      headers: { authorization: "Bearer ok" },
      method: "GET",
    } as Parameters<typeof mw>[0];
    const r = makeRes();
    await mw(req, r.res, () => {
      throw new Error("nope");
    });
    expect(r.status).toBe(403);
  });
});
