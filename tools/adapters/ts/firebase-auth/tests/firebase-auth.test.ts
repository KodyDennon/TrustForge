import { afterEach, describe, expect, test } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge/test-utils";
import {
  decideForFirebaseToken,
  trustforgeFirebase,
  type FirebaseDecodedToken,
} from "../src/index.ts";

let daemon: MockDaemonHandle;

afterEach(async () => {
  await daemon.stop();
});

const fakeVerifier = (uid: string) => async (token: string): Promise<FirebaseDecodedToken> => {
  if (token === "bad") throw new Error("invalid-firebase-id-token");
  return { uid, email: `${uid}@example.com`, email_verified: true };
};

describe("@trustforge/firebase-auth", () => {
  test("decideForFirebaseToken — verifies token and forwards uid", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const out = await decideForFirebaseToken("good-id-token", {
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyIdToken: fakeVerifier("user-42"),
    });
    expect(out.uid).toBe("user-42");
    expect(out.decision.decision).toBe("allow");
    const captured = daemon.calls()[0]!;
    expect(captured.host_token).toBe("good-id-token");
    expect(captured.host_token_kind).toBe("firebase-id-token");
    expect((captured.context as { uid: string }).uid).toBe("user-42");
  });

  test("decideForFirebaseToken — propagates verifier error", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    await expect(
      decideForFirebaseToken("bad", {
        daemonUrl: daemon.url,
        adminToken: "admin",
        verifyIdToken: fakeVerifier("ignored"),
      }),
    ).rejects.toThrow(/invalid-firebase-id-token/);
    expect(daemon.callCount()).toBe(0);
  });

  test("middleware — allow path attaches req.tfFirebaseUid + req.tfDecision", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeFirebase({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyIdToken: fakeVerifier("user-99"),
    });
    const req = {
      headers: { authorization: "Bearer ok" },
      url: "/foo",
      method: "GET",
    } as Parameters<typeof mw>[0];
    let nexted = false;
    const res = makeRes();
    await mw(req, res.res, () => {
      nexted = true;
    });
    expect(nexted).toBe(true);
    expect(req.tfFirebaseUid).toBe("user-99");
    expect(req.tfDecision?.decision).toBe("allow");
    expect(res.headers["x-tf-proof-id"]).toMatch(/^sha256:/);
  });

  test("middleware — missing bearer token returns 401", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeFirebase({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyIdToken: fakeVerifier("u1"),
    });
    const req = { headers: {}, method: "GET" } as Parameters<typeof mw>[0];
    const res = makeRes();
    await mw(req, res.res, () => {
      throw new Error("should not call next");
    });
    expect(res.status).toBe(401);
  });

  test("middleware — verifier failure returns 401 with detail", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforgeFirebase({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyIdToken: fakeVerifier("u1"),
    });
    const req = {
      headers: { authorization: "Bearer bad" },
      method: "GET",
    } as Parameters<typeof mw>[0];
    const res = makeRes();
    await mw(req, res.res, () => {
      throw new Error("should not call next");
    });
    expect(res.status).toBe(401);
    expect((res.body as { error: string }).error).toBe("firebase-verify-failed");
  });

  test("middleware — deny returns 403 with reason", async () => {
    daemon = startMockDaemon({
      adminToken: "admin",
      decide: () => ({
        decision: "deny",
        reason: "no",
        approval_id: null,
        proof_id: "sha256:fb-deny",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: ["x"],
      }),
    });
    const mw = trustforgeFirebase({
      daemonUrl: daemon.url,
      adminToken: "admin",
      verifyIdToken: fakeVerifier("u"),
    });
    const req = {
      headers: { authorization: "Bearer ok" },
      method: "GET",
    } as Parameters<typeof mw>[0];
    const res = makeRes();
    await mw(req, res.res, () => {
      throw new Error("should not call next");
    });
    expect(res.status).toBe(403);
    expect((res.body as { decision: string }).decision).toBe("deny");
  });
});

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
