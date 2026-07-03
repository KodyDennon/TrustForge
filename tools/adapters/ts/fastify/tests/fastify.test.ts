import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import Fastify, { type FastifyInstance } from "fastify";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge-protocol/test-utils";
import { fastifyTrustForge } from "../src/index.ts";

let daemon: MockDaemonHandle;
let app: FastifyInstance;

afterEach(async () => {
  await app?.close();
  await daemon.stop();
});

async function buildApp(
  daemonUrl: string,
  mode: "enforce" | "observe-only" = "enforce",
  gateGlobally = true,
) {
  app = Fastify({ logger: false });
  await app.register(fastifyTrustForge, {
    daemonUrl,
    adminToken: "test-admin-token",
    mode,
    profile: "home",
    gateGlobally,
  });
  app.get("/public", async (req) => ({
    ok: true,
    actor: req.tfActor,
    proof: req.tfProofId,
  }));
  app.post(
    "/billing/charge",
    { preHandler: app.tfRequire("billing.charge") },
    async (req) => ({ charged: true, decision: req.tfDecision?.decision }),
  );
  await app.ready();
  return app;
}

describe("@trustforge-protocol/fastify", () => {
  test("happy path — allow attaches actor + proof_id, x-tf-proof-id header", async () => {
    daemon = startMockDaemon({ adminToken: "test-admin-token" });
    await buildApp(daemon.url);
    const res = await app.inject({
      method: "GET",
      url: "/public",
      headers: { authorization: "Bearer host-token-abc" },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { ok: boolean; actor: string; proof: string };
    expect(body.ok).toBe(true);
    expect(body.actor).toMatch(/^tf:actor:/);
    expect(body.proof).toMatch(/^sha256:/);
    expect(res.headers["x-tf-proof-id"]).toMatch(/^sha256:/);
  });

  test("deny path — 403 + danger_tags", async () => {
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
        danger_tags: ["blocked"],
      }),
    });
    await buildApp(daemon.url);
    const res = await app.inject({ method: "GET", url: "/public" });
    expect(res.statusCode).toBe(403);
    const body = res.json() as { decision: string; danger_tags: string[] };
    expect(body.decision).toBe("deny");
    expect(body.danger_tags).toEqual(["blocked"]);
  });

  test("deny path is terminal and does not run the route handler", async () => {
    daemon = startMockDaemon({
      adminToken: "test-admin-token",
      decide: () => ({
        decision: "deny",
        reason: "policy: blocked",
        approval_id: null,
        proof_id: "sha256:terminal-deny",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    let handlerRan = false;
    app = Fastify({ logger: false });
    await app.register(fastifyTrustForge, {
      daemonUrl: daemon.url,
      adminToken: "test-admin-token",
      mode: "enforce",
    });
    app.get("/terminal", async () => {
      handlerRan = true;
      return { ok: true };
    });
    await app.ready();

    const res = await app.inject({ method: "GET", url: "/terminal" });

    expect(res.statusCode).toBe(403);
    expect(handlerRan).toBe(false);
  });

  test("observe-only forwards even on deny", async () => {
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
    await buildApp(daemon.url, "observe-only");
    const res = await app.inject({ method: "GET", url: "/public" });
    expect(res.statusCode).toBe(200);
    expect(res.headers["x-tf-proof-id"]).toBe("sha256:obs-1");
  });

  test("approval-required — 202 + Location header", async () => {
    daemon = startMockDaemon({
      adminToken: "test-admin-token",
      decide: () => ({
        decision: "approval-required",
        reason: "needs human",
        approval_id: "approval-1",
        proof_id: "sha256:appr-1",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T2",
        authority_mode: "layered",
        danger_tags: ["irreversible"],
      }),
    });
    await buildApp(daemon.url);
    const res = await app.inject({ method: "GET", url: "/public" });
    expect(res.statusCode).toBe(202);
    expect(res.headers["location"]).toBe("/approvals/approval-1");
  });

  test("approval-required is terminal and does not run the route handler", async () => {
    daemon = startMockDaemon({
      adminToken: "test-admin-token",
      decide: () => ({
        decision: "approval-required",
        reason: "needs human",
        approval_id: "approval-terminal",
        proof_id: "sha256:terminal-approval",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T2",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    let handlerRan = false;
    app = Fastify({ logger: false });
    await app.register(fastifyTrustForge, {
      daemonUrl: daemon.url,
      adminToken: "test-admin-token",
      mode: "enforce",
    });
    app.get("/needs-approval", async () => {
      handlerRan = true;
      return { ok: true };
    });
    await app.ready();

    const res = await app.inject({ method: "GET", url: "/needs-approval" });

    expect(res.statusCode).toBe(202);
    expect(handlerRan).toBe(false);
  });

  test("tfRequire(action) pins the action sent to daemon (route-only mode)", async () => {
    daemon = startMockDaemon({ adminToken: "test-admin-token" });
    await buildApp(daemon.url, "enforce", false); // gateGlobally = false
    const res = await app.inject({
      method: "POST",
      url: "/billing/charge",
      payload: { amount: 5 },
    });
    expect(res.statusCode).toBe(200);
    const calls = daemon.calls();
    expect(calls.length).toBe(1);
    expect(calls[0]!.action).toBe("billing.charge");
  });

  test("missing Authorization header still calls daemon (no token, default allow)", async () => {
    daemon = startMockDaemon({ adminToken: "test-admin-token" });
    await buildApp(daemon.url);
    const res = await app.inject({ method: "GET", url: "/public" });
    expect(res.statusCode).toBe(200);
    expect(daemon.calls()[0]!.host_token).toBeUndefined();
  });

  test("unauthorized daemon — enforce mode returns 502", async () => {
    daemon = startMockDaemon({ adminToken: "real-token" });
    app = Fastify({ logger: false });
    await app.register(fastifyTrustForge, {
      daemonUrl: daemon.url,
      adminToken: "wrong-token",
      mode: "enforce",
    });
    app.get("/x", async () => ({ ok: true }));
    await app.ready();
    const res = await app.inject({ method: "GET", url: "/x" });
    expect(res.statusCode).toBe(502);
  });

  test("batch — multiple sequential requests all gated", async () => {
    daemon = startMockDaemon({ adminToken: "test-admin-token" });
    await buildApp(daemon.url);
    for (let i = 0; i < 4; i++) {
      const res = await app.inject({
        method: "GET",
        url: "/public",
        headers: { authorization: `Bearer t-${i}` },
      });
      expect(res.statusCode).toBe(200);
    }
    expect(daemon.callCount()).toBe(4);
  });
});
