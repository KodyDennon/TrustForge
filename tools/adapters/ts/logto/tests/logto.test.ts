import { afterEach, describe, expect, test } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge-protocol/test-utils";
import {
  decideForLogtoToken,
  trustforgeLogto,
  type LogtoClaims,
} from "../src/index.ts";

let daemon: MockDaemonHandle;

afterEach(async () => {
  await daemon.stop();
});

const fakeVerifier =
  (sub: string) =>
  async (token: string): Promise<LogtoClaims> => {
    if (token === "bad") throw new Error("invalid-logto-jwt");
    return {
      sub,
      iss: "https://my-logto.app/oidc",
      aud: "https://api.example.com",
      scope: "read:foo",
      client_id: "abc",
      email: `${sub}@example.com`,
      username: sub,
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

describe("@trustforge-protocol/logto", () => {
  test("decideForLogtoToken — verifies and forwards sub + scope", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const out = await decideForLogtoToken("good-jwt", {
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyToken: fakeVerifier("user-x"),
    });
    expect(out.claims.sub).toBe("user-x");
    const captured = daemon.calls()[0]!;
    expect(captured.host_token).toBe("good-jwt");
    expect(captured.host_token_kind).toBe("logto-jwt");
    expect((captured.context as { sub: string }).sub).toBe("user-x");
    expect((captured.context as { scope: string }).scope).toBe("read:foo");
  });

  test("decideForLogtoToken — propagates verifier error", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    await expect(
      decideForLogtoToken("bad", {
        daemonUrl: daemon.url,
        adminToken: "admin",
        verifyToken: fakeVerifier("u"),
      }),
    ).rejects.toThrow(/invalid-logto-jwt/);
  });

  test("middleware — allow path attaches tfLogtoSub", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeLogto({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyToken: fakeVerifier("user-y"),
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
    expect(req.tfLogtoSub).toBe("user-y");
  });

  test("middleware — missing Bearer returns 401", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeLogto({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyToken: fakeVerifier("u"),
    });
    const req = { headers: {}, method: "GET" } as Parameters<typeof mw>[0];
    const r = makeRes();
    await mw(req, r.res, () => {});
    expect(r.status).toBe(401);
  });

  test("middleware — verifier failure returns 401", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeLogto({
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
    expect((r.body as { error: string }).error).toBe("logto-verify-failed");
  });

  test("middleware — deny returns 403", async () => {
    daemon = startMockDaemon({
      adminToken: "admin",
      decide: () => ({
        decision: "deny",
        reason: "no",
        approval_id: null,
        proof_id: "sha256:logto-deny",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const mw = trustforgeLogto({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyToken: fakeVerifier("u"),
    });
    const req = {
      headers: { authorization: "Bearer ok" },
      method: "GET",
    } as Parameters<typeof mw>[0];
    const r = makeRes();
    await mw(req, r.res, () => {});
    expect(r.status).toBe(403);
  });
});
