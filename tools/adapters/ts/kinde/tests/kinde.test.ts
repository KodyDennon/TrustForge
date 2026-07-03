import { afterEach, describe, expect, test } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge-protocol/test-utils";
import {
  decideForKindeToken,
  trustforgeKinde,
  type KindeClaims,
} from "../src/index.ts";

let daemon: MockDaemonHandle;

afterEach(async () => {
  await daemon.stop();
});

const fakeVerifier =
  (sub: string, orgCode = "org-1") =>
  async (token: string): Promise<KindeClaims> => {
    if (token === "bad") throw new Error("invalid-kinde-jwt");
    return {
      sub,
      iss: "https://my-org.kinde.com",
      aud: "my-api",
      org_code: orgCode,
      permissions: ["read:foo"],
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

describe("@trustforge-protocol/kinde", () => {
  test("decideForKindeToken — verifies and forwards sub + org_code", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const out = await decideForKindeToken("good-jwt", {
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyToken: fakeVerifier("kp_user1", "org-7"),
    });
    expect(out.claims.sub).toBe("kp_user1");
    const captured = daemon.calls()[0]!;
    expect(captured.host_token).toBe("good-jwt");
    expect(captured.host_token_kind).toBe("kinde-jwt");
    expect((captured.context as { sub: string }).sub).toBe("kp_user1");
    expect((captured.context as { org_code: string }).org_code).toBe("org-7");
  });

  test("decideForKindeToken — propagates verifier error", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    await expect(
      decideForKindeToken("bad", {
        daemonUrl: daemon.url,
        adminToken: "admin",
        verifyToken: fakeVerifier("u"),
      }),
    ).rejects.toThrow(/invalid-kinde-jwt/);
  });

  test("middleware — allow path attaches tfKindeSub", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeKinde({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyToken: fakeVerifier("kp_u2"),
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
    expect(req.tfKindeSub).toBe("kp_u2");
  });

  test("middleware — missing Bearer returns 401", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeKinde({
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
    const mw = trustforgeKinde({
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
    expect((r.body as { error: string }).error).toBe("kinde-verify-failed");
  });

  test("middleware — deny returns 403", async () => {
    daemon = startMockDaemon({
      adminToken: "admin",
      decide: () => ({
        decision: "deny",
        reason: "no",
        approval_id: null,
        proof_id: "sha256:kinde-deny",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const mw = trustforgeKinde({
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
