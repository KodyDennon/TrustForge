import { afterEach, describe, expect, test } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge-protocol/test-utils";
import {
  decideForSupabaseToken,
  trustforgeSupabase,
  type SupabaseUser,
} from "../src/index.ts";

let daemon: MockDaemonHandle;

afterEach(async () => {
  await daemon.stop();
});

const fakeVerifier =
  (id: string) =>
  async (token: string): Promise<SupabaseUser> => {
    if (token === "bad") throw new Error("invalid-supabase-jwt");
    return { id, email: `${id}@example.com` };
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

describe("@trustforge-protocol/supabase-auth", () => {
  test("decideForSupabaseToken — verifies JWT and forwards user.id", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const out = await decideForSupabaseToken("good-jwt", {
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyAccessToken: fakeVerifier("uuid-1"),
    });
    expect(out.user.id).toBe("uuid-1");
    expect(out.decision.decision).toBe("allow");
    const captured = daemon.calls()[0]!;
    expect(captured.host_token).toBe("good-jwt");
    expect(captured.host_token_kind).toBe("supabase-jwt");
    expect((captured.context as { user_id: string }).user_id).toBe("uuid-1");
  });

  test("decideForSupabaseToken — propagates verifier error", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    await expect(
      decideForSupabaseToken("bad", {
        daemonUrl: daemon.url,
        adminToken: "admin",
        verifyAccessToken: fakeVerifier("ignored"),
      }),
    ).rejects.toThrow(/invalid-supabase-jwt/);
  });

  test("middleware — allow path attaches tfSupabaseUserId", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeSupabase({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyAccessToken: fakeVerifier("uuid-2"),
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
    expect(req.tfSupabaseUserId).toBe("uuid-2");
    expect(r.headers["x-tf-proof-id"]).toMatch(/^sha256:/);
  });

  test("middleware — missing bearer token returns 401", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeSupabase({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyAccessToken: fakeVerifier("u1"),
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
    const mw = trustforgeSupabase({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyAccessToken: fakeVerifier("u1"),
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
    expect((r.body as { error: string }).error).toBe("supabase-verify-failed");
  });

  test("middleware — deny returns 403", async () => {
    daemon = startMockDaemon({
      adminToken: "admin",
      decide: () => ({
        decision: "deny",
        reason: "no",
        approval_id: null,
        proof_id: "sha256:sb-deny",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: ["x"],
      }),
    });
    const mw = trustforgeSupabase({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyAccessToken: fakeVerifier("u"),
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
