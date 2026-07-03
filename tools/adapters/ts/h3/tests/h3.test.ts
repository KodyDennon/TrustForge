import { afterEach, describe, expect, test } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge-protocol/test-utils";
import {
  trustforgeHandler,
  tfRequire,
  evaluateEvent,
  type H3EventLike,
} from "../src/index.ts";

let daemon: MockDaemonHandle;

afterEach(async () => {
  await daemon.stop();
});

interface CapturedRes {
  statusCode: number;
  headers: Record<string, string>;
}

function makeEvent(init: {
  path?: string;
  method?: string;
  headers?: Record<string, string>;
}): { event: H3EventLike; res: CapturedRes } {
  const headers = init.headers ?? {};
  const res: CapturedRes = { statusCode: 200, headers: {} };
  const event: H3EventLike = {
    node: {
      req: {
        url: init.path ?? "/",
        method: init.method ?? "GET",
        headers,
      },
      res: {
        get statusCode() {
          return res.statusCode;
        },
        set statusCode(v: number) {
          res.statusCode = v;
        },
        setHeader(name: string, value: string) {
          res.headers[name.toLowerCase()] = value;
        },
      } as H3EventLike["node"] extends infer T
        ? T extends { res?: infer R }
          ? R
          : never
        : never,
    },
    context: {},
    path: init.path ?? "/",
    method: init.method ?? "GET",
  };
  return { event, res };
}

describe("@trustforge-protocol/h3", () => {
  test("allow path returns undefined and stamps proof header", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const handler = trustforgeHandler({
      daemonUrl: daemon.url,
      adminToken: "admin",
      profile: "home",
    });
    const { event, res } = makeEvent({
      path: "/api/x",
      headers: { authorization: "Bearer host-token-h3" },
    });
    const result = await handler(event);
    expect(result).toBeUndefined();
    expect(res.headers["x-tf-proof-id"]).toMatch(/^sha256:/);
    expect(event.context.tfDecision?.decision).toBe("allow");
    expect(daemon.calls()[0]!.host_token).toBe("host-token-h3");
  });

  test("deny path returns a 403 body and sets statusCode", async () => {
    daemon = startMockDaemon({
      adminToken: "admin",
      decide: () => ({
        decision: "deny",
        reason: "blocked",
        approval_id: null,
        proof_id: "sha256:deny-h3",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: ["fs"],
      }),
    });
    const handler = trustforgeHandler({
      daemonUrl: daemon.url,
      adminToken: "admin",
    });
    const { event, res } = makeEvent({ path: "/api/y" });
    const body = (await handler(event)) as {
      error: string;
      decision: string;
      danger_tags: string[];
    };
    expect(res.statusCode).toBe(403);
    expect(body.decision).toBe("deny");
    expect(body.danger_tags).toEqual(["fs"]);
  });

  test("approval-required returns 202 with location header", async () => {
    daemon = startMockDaemon({
      adminToken: "admin",
      decide: () => ({
        decision: "approval-required",
        reason: "needs human",
        approval_id: "appr-h3-7",
        proof_id: "sha256:appr-h3",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T2",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const handler = trustforgeHandler({
      daemonUrl: daemon.url,
      adminToken: "admin",
    });
    const { event, res } = makeEvent({ path: "/api/z" });
    await handler(event);
    expect(res.statusCode).toBe(202);
    expect(res.headers["location"]).toBe("/approvals/appr-h3-7");
  });

  test("observe-only forwards on deny", async () => {
    daemon = startMockDaemon({
      adminToken: "admin",
      decide: () => ({
        decision: "deny",
        reason: "would-be-blocked",
        approval_id: null,
        proof_id: "sha256:obs-h3",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const { event } = makeEvent({ path: "/api/x" });
    const outcome = await evaluateEvent(event, {
      daemonUrl: daemon.url,
      adminToken: "admin",
      mode: "observe-only",
    });
    expect(outcome.allowed).toBe(true);
    expect(event.context.tfProofId).toBe("sha256:obs-h3");
  });

  test("tfRequire pins a custom action", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const handler = tfRequire("billing.charge", {
      daemonUrl: daemon.url,
      adminToken: "admin",
    });
    const { event } = makeEvent({ path: "/billing/charge", method: "POST" });
    await handler(event);
    expect(daemon.calls()[0]!.action).toBe("billing.charge");
  });

  test("daemon failure in enforce mode returns 502", async () => {
    daemon = startMockDaemon({ adminToken: "real-token" });
    const handler = trustforgeHandler({
      daemonUrl: daemon.url,
      adminToken: "wrong",
    });
    const { event, res } = makeEvent({ path: "/x" });
    await handler(event);
    expect(res.statusCode).toBe(502);
  });
});
