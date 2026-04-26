import { afterEach, describe, expect, test } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge/test-utils";
import {
  decideForStackAuthToken,
  trustforgeStackAuth,
  type StackAuthUser,
} from "../src/index.ts";

let daemon: MockDaemonHandle;

afterEach(async () => {
  await daemon.stop();
});

const fakeVerifier =
  (id: string) =>
  async (token: string): Promise<StackAuthUser> => {
    if (token === "bad") throw new Error("invalid-stack-auth-session");
    return { id, primaryEmail: `${id}@example.com`, displayName: id };
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

describe("@trustforge/stack-auth", () => {
  test("decideForStackAuthToken — verifies and forwards user.id", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const out = await decideForStackAuthToken("good-token", {
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifySession: fakeVerifier("user-1"),
    });
    expect(out.user.id).toBe("user-1");
    const captured = daemon.calls()[0]!;
    expect(captured.host_token).toBe("good-token");
    expect(captured.host_token_kind).toBe("stack-auth");
    expect((captured.context as { user_id: string }).user_id).toBe("user-1");
  });

  test("decideForStackAuthToken — propagates verifier error", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    await expect(
      decideForStackAuthToken("bad", {
        daemonUrl: daemon.url,
        adminToken: "admin",
        verifySession: fakeVerifier("u"),
      }),
    ).rejects.toThrow(/invalid-stack-auth-session/);
  });

  test("middleware — reads cookie", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeStackAuth({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifySession: fakeVerifier("user-2"),
    });
    const req = {
      headers: { cookie: "stack-access=cookie-blob" },
      url: "/x",
      method: "GET",
    } as Parameters<typeof mw>[0];
    let nexted = false;
    const r = makeRes();
    await mw(req, r.res, () => {
      nexted = true;
    });
    expect(nexted).toBe(true);
    expect(req.tfStackAuthUserId).toBe("user-2");
  });

  test("middleware — falls back to Bearer", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeStackAuth({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifySession: fakeVerifier("user-3"),
    });
    const req = {
      headers: { authorization: "Bearer raw-token" },
      url: "/x",
      method: "GET",
    } as Parameters<typeof mw>[0];
    const r = makeRes();
    await mw(req, r.res, () => {});
    expect(req.tfStackAuthUserId).toBe("user-3");
  });

  test("middleware — missing token returns 401", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeStackAuth({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifySession: fakeVerifier("u"),
    });
    const req = { headers: {}, method: "GET" } as Parameters<typeof mw>[0];
    const r = makeRes();
    await mw(req, r.res, () => {});
    expect(r.status).toBe(401);
  });

  test("middleware — verifier failure returns 401", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeStackAuth({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifySession: fakeVerifier("u"),
    });
    const req = {
      headers: { authorization: "Bearer bad" },
      method: "GET",
    } as Parameters<typeof mw>[0];
    const r = makeRes();
    await mw(req, r.res, () => {});
    expect(r.status).toBe(401);
    expect((r.body as { error: string }).error).toBe("stack-auth-verify-failed");
  });

  test("middleware — deny returns 403", async () => {
    daemon = startMockDaemon({
      adminToken: "admin",
      decide: () => ({
        decision: "deny",
        reason: "no",
        approval_id: null,
        proof_id: "sha256:stack-deny",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const mw = trustforgeStackAuth({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifySession: fakeVerifier("u"),
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
