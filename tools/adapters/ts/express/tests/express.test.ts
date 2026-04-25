import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import express from "express";
import request from "supertest";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge/test-utils";
import { tfExpress, tfRequire } from "../src/index.ts";

let daemon: MockDaemonHandle;

afterEach(async () => {
  await daemon.stop();
});

function makeApp(daemonUrl: string, mode: "enforce" | "observe-only" = "enforce") {
  const app = express();
  app.use(express.json());
  app.use(
    tfExpress({
      daemonUrl,
      adminToken: "test-admin-token",
      mode,
      profile: "home",
    }),
  );
  app.get("/public", (req, res) => {
    res.json({ ok: true, actor: req.tfActor, proof: req.tfProofId });
  });
  app.post("/billing/charge", tfRequire("billing.charge"), (req, res) => {
    res.json({ charged: true, decision: req.tfDecision?.decision });
  });
  return app;
}

describe("@trustforge/express", () => {
  test("happy path — allow forwards request and attaches req.tfActor + proof_id", async () => {
    daemon = startMockDaemon({ adminToken: "test-admin-token" });
    const app = makeApp(daemon.url);
    const res = await request(app)
      .get("/public")
      .set("Authorization", "Bearer host-token-abc");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.actor).toMatch(/^tf:actor:/);
    expect(res.body.proof).toMatch(/^sha256:/);
    expect(res.headers["x-tf-proof-id"]).toMatch(/^sha256:/);
    expect(daemon.callCount()).toBe(1);
    expect(daemon.calls()[0]!.host_token).toBe("host-token-abc");
  });

  test("deny path — 403 with reason + danger_tags", async () => {
    daemon = startMockDaemon({
      adminToken: "test-admin-token",
      decide: () => ({
        decision: "deny",
        reason: "policy: blocked",
        approval_id: null,
        proof_id: "sha256:deny-1",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: ["filesystem-secret-read"],
      }),
    });
    const app = makeApp(daemon.url);
    const res = await request(app).get("/public");
    expect(res.status).toBe(403);
    expect(res.body.decision).toBe("deny");
    expect(res.body.danger_tags).toEqual(["filesystem-secret-read"]);
  });

  test("observe-only mode — forwards even on deny", async () => {
    daemon = startMockDaemon({
      adminToken: "test-admin-token",
      decide: () => ({
        decision: "deny",
        reason: "would-be-blocked",
        approval_id: null,
        proof_id: "sha256:obs-1",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const app = makeApp(daemon.url, "observe-only");
    const res = await request(app).get("/public");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    // proof id still attached
    expect(res.headers["x-tf-proof-id"]).toBe("sha256:obs-1");
  });

  test("approval-required — 202 + Location header", async () => {
    daemon = startMockDaemon({
      adminToken: "test-admin-token",
      decide: () => ({
        decision: "approval-required",
        reason: "human approval needed",
        approval_id: "approval-9912-abc",
        proof_id: "sha256:appr-1",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T2",
        authority_mode: "layered",
        danger_tags: ["irreversible"],
      }),
    });
    const app = makeApp(daemon.url);
    const res = await request(app).get("/public");
    expect(res.status).toBe(202);
    expect(res.headers["location"]).toBe("/approvals/approval-9912-abc");
    expect(res.body.approval_id).toBe("approval-9912-abc");
  });

  test("tfRequire(action) — route-only gating, action propagates to daemon", async () => {
    daemon = startMockDaemon({ adminToken: "test-admin-token" });
    // Initialise lastConfig via tfExpress() but do NOT mount it globally.
    tfExpress({
      daemonUrl: daemon.url,
      adminToken: "test-admin-token",
      mode: "enforce",
    });
    const app = express();
    app.use(express.json());
    app.post("/billing/charge", tfRequire("billing.charge"), (_req, res) => {
      res.json({ charged: true });
    });
    const res = await request(app).post("/billing/charge").send({ amount: 5 });
    expect(res.status).toBe(200);
    const calls = daemon.calls();
    expect(calls.length).toBe(1);
    expect(calls[0]!.action).toBe("billing.charge");
  });

  test("missing Authorization header — still calls daemon (auto kind), gets default allow", async () => {
    daemon = startMockDaemon({ adminToken: "test-admin-token" });
    const app = makeApp(daemon.url);
    const res = await request(app).get("/public");
    expect(res.status).toBe(200);
    const captured = daemon.calls()[0]!;
    expect(captured.host_token).toBeUndefined();
  });

  test("unauthorized daemon (wrong admin token) — enforce mode returns 502", async () => {
    daemon = startMockDaemon({ adminToken: "real-token" });
    const app = express();
    app.use(express.json());
    app.use(
      tfExpress({
        daemonUrl: daemon.url,
        adminToken: "wrong-token",
        mode: "enforce",
      }),
    );
    app.get("/x", (_req, res) => res.json({ ok: true }));
    const res = await request(app).get("/x");
    expect(res.status).toBe(502);
  });

  test("proof_id always exposed via x-tf-proof-id header on allow", async () => {
    daemon = startMockDaemon({
      adminToken: "test-admin-token",
      decide: (req) => ({
        decision: "allow",
        reason: "ok",
        approval_id: null,
        proof_id: `sha256:proof-${req.trace_id}`,
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T2",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const app = makeApp(daemon.url);
    const res = await request(app).get("/public");
    expect(res.status).toBe(200);
    expect(res.headers["x-tf-proof-id"]).toMatch(/^sha256:proof-/);
  });
});
