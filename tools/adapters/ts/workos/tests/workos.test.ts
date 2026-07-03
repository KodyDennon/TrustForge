import { afterEach, describe, expect, test } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge-protocol/test-utils";
import {
  decideForWorkOSToken,
  trustforgeWorkOS,
  type WorkOSVerifierResult,
} from "../src/index.ts";

let daemon: MockDaemonHandle;

afterEach(async () => {
  await daemon.stop();
});

const fakeVerifier =
  (id: string, accessToken = "wos-jwt-abc") =>
  async (token: string): Promise<WorkOSVerifierResult> => {
    if (token === "bad") throw new Error("invalid-workos-session");
    return {
      accessToken,
      user: { id, email: `${id}@example.com` },
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

describe("@trustforge-protocol/workos", () => {
  test("decideForWorkOSToken — verifies session and forwards access token", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const out = await decideForWorkOSToken("good-cookie", {
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifySession: fakeVerifier("user-1", "wos-tok-1"),
    });
    expect(out.user.id).toBe("user-1");
    expect(out.accessToken).toBe("wos-tok-1");
    const captured = daemon.calls()[0]!;
    expect(captured.host_token).toBe("wos-tok-1");
    expect(captured.host_token_kind).toBe("workos-jwt");
    expect((captured.context as { user_id: string }).user_id).toBe("user-1");
  });

  test("middleware — reads session from cookie header", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeWorkOS({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifySession: fakeVerifier("user-2"),
    });
    const req = {
      headers: { cookie: "wos-session=cookie-blob" },
      url: "/x",
      method: "GET",
    } as Parameters<typeof mw>[0];
    let nexted = false;
    const r = makeRes();
    await mw(req, r.res, () => {
      nexted = true;
    });
    expect(nexted).toBe(true);
    expect(req.tfWorkOSUserId).toBe("user-2");
  });

  test("middleware — falls back to Authorization Bearer", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeWorkOS({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifySession: fakeVerifier("user-3"),
    });
    const req = {
      headers: { authorization: "Bearer raw-access" },
      url: "/x",
      method: "GET",
    } as Parameters<typeof mw>[0];
    const r = makeRes();
    await mw(req, r.res, () => {});
    expect(req.tfWorkOSUserId).toBe("user-3");
  });

  test("middleware — missing token returns 401", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeWorkOS({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifySession: fakeVerifier("u"),
    });
    const req = { headers: {}, method: "GET" } as Parameters<typeof mw>[0];
    const r = makeRes();
    await mw(req, r.res, () => {
      throw new Error("nope");
    });
    expect(r.status).toBe(401);
  });

  test("middleware — verifier failure returns 401 with detail", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeWorkOS({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifySession: fakeVerifier("u"),
    });
    const req = {
      headers: { authorization: "Bearer bad" },
      method: "GET",
    } as Parameters<typeof mw>[0];
    const r = makeRes();
    await mw(req, r.res, () => {
      throw new Error("nope");
    });
    expect(r.status).toBe(401);
    expect((r.body as { error: string }).error).toBe("workos-verify-failed");
  });

  test("middleware — deny returns 403", async () => {
    daemon = startMockDaemon({
      adminToken: "admin",
      decide: () => ({
        decision: "deny",
        reason: "no",
        approval_id: null,
        proof_id: "sha256:wos-deny",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const mw = trustforgeWorkOS({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifySession: fakeVerifier("u"),
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
