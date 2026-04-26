import { afterEach, describe, expect, test } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge/test-utils";
import { tfRequestContext, withTrustforge } from "../src/index.ts";

let daemon: MockDaemonHandle;

afterEach(async () => {
  await daemon.stop();
});

describe("@trustforge/bun-serve", () => {
  test("allow path runs the user handler and stamps x-tf-proof-id", async () => {
    daemon = startMockDaemon({ adminToken: "test-admin" });
    const handler = withTrustforge(
      (req) => {
        const ctx = tfRequestContext(req);
        return new Response(
          JSON.stringify({ actor: ctx?.actor, proof: ctx?.proofId }),
          { headers: { "content-type": "application/json" } },
        );
      },
      { daemonUrl: daemon.url, adminToken: "test-admin", mode: "enforce" },
    );
    const res = await handler(
      new Request("http://localhost/ok", {
        headers: { authorization: "Bearer host-token-bun" },
      }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("x-tf-proof-id")).toMatch(/^sha256:/);
    const body = (await res.json()) as { actor: string; proof: string };
    expect(body.actor).toMatch(/^tf:actor:/);
    expect(body.proof).toMatch(/^sha256:/);
    expect(daemon.callCount()).toBe(1);
    expect(daemon.calls()[0]!.host_token).toBe("host-token-bun");
  });

  test("deny path short-circuits with 403", async () => {
    daemon = startMockDaemon({
      adminToken: "test-admin",
      decide: () => ({
        decision: "deny",
        reason: "policy: blocked",
        approval_id: null,
        proof_id: "sha256:deny-bun",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: ["fs-secret"],
      }),
    });
    let userCalled = false;
    const handler = withTrustforge(
      () => {
        userCalled = true;
        return new Response("should-not-be-reached");
      },
      { daemonUrl: daemon.url, adminToken: "test-admin" },
    );
    const res = await handler(new Request("http://localhost/foo"));
    expect(userCalled).toBe(false);
    expect(res.status).toBe(403);
    const body = (await res.json()) as {
      decision: string;
      danger_tags: string[];
    };
    expect(body.decision).toBe("deny");
    expect(body.danger_tags).toEqual(["fs-secret"]);
  });

  test("approval-required returns 202 + Location", async () => {
    daemon = startMockDaemon({
      adminToken: "test-admin",
      decide: () => ({
        decision: "approval-required",
        reason: "needs human",
        approval_id: "appr-001",
        proof_id: "sha256:appr-bun",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T2",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const handler = withTrustforge(
      () => new Response("nope"),
      { daemonUrl: daemon.url, adminToken: "test-admin" },
    );
    const res = await handler(new Request("http://localhost/x"));
    expect(res.status).toBe(202);
    expect(res.headers.get("location")).toBe("/approvals/appr-001");
  });

  test("observe-only forwards on deny", async () => {
    daemon = startMockDaemon({
      adminToken: "test-admin",
      decide: () => ({
        decision: "deny",
        reason: "would-be-blocked",
        approval_id: null,
        proof_id: "sha256:obs-bun",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const handler = withTrustforge(
      () => new Response("through"),
      {
        daemonUrl: daemon.url,
        adminToken: "test-admin",
        mode: "observe-only",
      },
    );
    const res = await handler(new Request("http://localhost/y"));
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("through");
    expect(res.headers.get("x-tf-proof-id")).toBe("sha256:obs-bun");
  });

  test("skip predicate bypasses the daemon entirely", async () => {
    daemon = startMockDaemon({ adminToken: "test-admin" });
    const handler = withTrustforge(
      () => new Response("public"),
      {
        daemonUrl: daemon.url,
        adminToken: "test-admin",
        skip: (url) => url.pathname === "/health",
      },
    );
    const res = await handler(new Request("http://localhost/health"));
    expect(res.status).toBe(200);
    expect(daemon.callCount()).toBe(0);
  });

  test("daemon failure in enforce mode returns 502", async () => {
    daemon = startMockDaemon({ adminToken: "real-token" });
    const handler = withTrustforge(
      () => new Response("ok"),
      { daemonUrl: daemon.url, adminToken: "wrong" },
    );
    const res = await handler(new Request("http://localhost/x"));
    expect(res.status).toBe(502);
  });
});
