import { afterEach, describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge/test-utils";
import { trustforgeMiddleware, tfRequire, type DecideResponse } from "../src/index.ts";

let daemon: MockDaemonHandle;

afterEach(async () => {
  await daemon.stop();
});

function makeApp(daemonUrl: string, mode: "enforce" | "observe-only" = "enforce") {
  const app = new Hono<{
    Variables: {
      tfActor?: string;
      tfDecision?: DecideResponse;
      tfProofId?: string;
    };
  }>();
  app.use(
    "*",
    trustforgeMiddleware({
      daemonUrl,
      adminToken: "test-admin-token",
      mode,
      profile: "home",
    }),
  );
  app.get("/public", (c) =>
    c.json({
      ok: true,
      actor: c.get("tfActor"),
      proof: c.get("tfProofId"),
    }),
  );
  return app;
}

describe("@trustforge/hono", () => {
  test("happy path — allow attaches actor + proof", async () => {
    daemon = startMockDaemon({ adminToken: "test-admin-token" });
    const app = makeApp(daemon.url);
    const res = await app.request("/public", {
      headers: { authorization: "Bearer host-token-abc" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { actor: string; proof: string };
    expect(body.actor).toMatch(/^tf:actor:/);
    expect(body.proof).toMatch(/^sha256:/);
    expect(res.headers.get("x-tf-proof-id")).toMatch(/^sha256:/);
  });

  test("deny — 403 with danger_tags", async () => {
    daemon = startMockDaemon({
      adminToken: "test-admin-token",
      decide: () => ({
        decision: "deny",
        reason: "blocked",
        approval_id: null,
        proof_id: "sha256:deny-1",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: ["blocked"],
      }),
    });
    const app = makeApp(daemon.url);
    const res = await app.request("/public");
    expect(res.status).toBe(403);
    const body = (await res.json()) as { decision: string; danger_tags: string[] };
    expect(body.decision).toBe("deny");
    expect(body.danger_tags).toEqual(["blocked"]);
  });

  test("observe-only — forwards on deny", async () => {
    daemon = startMockDaemon({
      adminToken: "test-admin-token",
      decide: () => ({
        decision: "deny",
        reason: "would-block",
        approval_id: null,
        proof_id: "sha256:obs-1",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const app = makeApp(daemon.url, "observe-only");
    const res = await app.request("/public");
    expect(res.status).toBe(200);
    expect(res.headers.get("x-tf-proof-id")).toBe("sha256:obs-1");
  });

  test("approval-required — 202 + Location header", async () => {
    daemon = startMockDaemon({
      adminToken: "test-admin-token",
      decide: () => ({
        decision: "approval-required",
        reason: "need-human",
        approval_id: "approval-h1",
        proof_id: "sha256:appr-h1",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T2",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const app = makeApp(daemon.url);
    const res = await app.request("/public");
    expect(res.status).toBe(202);
    expect(res.headers.get("location")).toBe("/approvals/approval-h1");
  });

  test("tfRequire(action, opts) pins action sent to daemon (route-only)", async () => {
    daemon = startMockDaemon({ adminToken: "test-admin-token" });
    const app = new Hono();
    app.post(
      "/charge",
      tfRequire("billing.charge", {
        daemonUrl: daemon.url,
        adminToken: "test-admin-token",
      }),
      (c) => c.json({ ok: true }),
    );
    const res = await app.request("/charge", { method: "POST" });
    expect(res.status).toBe(200);
    expect(daemon.callCount()).toBe(1);
    expect(daemon.calls()[0]!.action).toBe("billing.charge");
  });

  test("daemon unreachable — enforce returns 502", async () => {
    daemon = startMockDaemon({ adminToken: "real-token" });
    const app = new Hono();
    app.use(
      "*",
      trustforgeMiddleware({
        daemonUrl: daemon.url,
        adminToken: "wrong-token",
        mode: "enforce",
      }),
    );
    app.get("/x", (c) => c.json({ ok: true }));
    const res = await app.request("/x");
    expect(res.status).toBe(502);
  });
});
